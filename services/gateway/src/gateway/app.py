"""MCP gateway: the OAuth-protected MCP server that clients connect to (SPEC §6.2).

- Streamable HTTP at /mcp. The MCP SDK provides the resource-server plumbing:
  BearerAuth → RequireAuth (401/403 + WWW-Authenticate) and PRM (RFC 9728).
- Our TokenVerifier is the AgentCore-style multi-issuer JWT authorizer, and it
  writes a ledger event for every accept/reject.
- `gateway___whoami` echoes the verified inbound identity.
- `jira___*` tools reach Jira DC as the user via identity's token vault (downstream.py).
  When consent is needed: URL elicitation (-32042) if the client declared `elicitation.url`,
  otherwise an isError tool result carrying the link.
"""

import asyncio
import os
import time
from pathlib import Path
from typing import Any

import yaml
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import UrlElicitationRequiredError
from mcp_types import ElicitRequest, ElicitRequestURLParams, InputRequiredResult
from playground_common import fingerprint, ledger
from playground_common.http import async_client
from playground_common.jwt_authz import AuthorizerConfig, AuthzError, MultiIssuerAuthorizer
from starlette.requests import Request
from starlette.responses import JSONResponse

from gateway.downstream import ConsentRequired, DownstreamError, Identity, Target

SERVICE = "gateway"
CONFIG = yaml.safe_load(Path(os.environ.get("GATEWAY_CONFIG", "/app/config/gateway.yaml")).read_text())
RESOURCE: str = CONFIG["resource"]
REQUIRED_SCOPES: list[str] = CONFIG.get("required_scopes", [])
PUBLIC_HOST = RESOURCE.split("/")[2]
# Optional per-request introspection (S17). AgentCore's JWT authorizer validates locally, so it's off by default.
INTROSPECT = {"enabled": False, "cacheSeconds": 30} | CONFIG.get("introspection", {})
if os.environ.get("GATEWAY_INTROSPECT"):
    INTROSPECT["enabled"] = os.environ["GATEWAY_INTROSPECT"].lower() == "true"


class GatewayTokenVerifier:
    """Adapts MultiIssuerAuthorizer to the MCP SDK's TokenVerifier protocol."""

    def __init__(self) -> None:
        self.authz = MultiIssuerAuthorizer(
            [
                AuthorizerConfig(
                    name=a["name"],
                    discovery_url=a["discoveryUrl"],
                    allowed_audience=a["allowedAudience"],
                    allowed_clients=a.get("allowedClients", ["*"]),
                )
                for a in CONFIG["authorizers"]
            ],
            async_client(),
        )
        self._http = async_client()
        self._introspected: dict[str, tuple[bool, float]] = {}

    async def _active(self, token: str, claims: dict) -> bool:
        """S17: a JWT stays valid until `exp` even after the user is disabled. Optional RFC 7662
        introspection asks the IdP whether it's still active, cached per token for cacheSeconds. Keycloak
        only answers for a client in the token's audience, which is why T1 also names gateway-svc (§6.1)."""
        key = fingerprint(token)
        hit = self._introspected.get(key)
        if hit and time.monotonic() - hit[1] < INTROSPECT["cacheSeconds"]:
            return hit[0]
        r = await self._http.post(f"{claims['iss']}/protocol/openid-connect/token/introspect", data={
            "token": token, "client_id": CONFIG["identity"]["serviceClientId"],
            "client_secret": os.environ["GATEWAY_SVC_CLIENT_SECRET"]})
        active = r.status_code == 200 and r.json().get("active") is True
        self._introspected[key] = (active, time.monotonic())
        ledger.emit(SERVICE, "inbound.introspected", token=token, label="T1", active=active)
        return active

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            authorizer, claims = await self.authz.validate(token)
        except AuthzError as e:
            ledger.emit(SERVICE, "inbound.rejected", token=token, label="T1?", reason=e.reason)
            return None
        if INTROSPECT["enabled"] and not await self._active(token, claims):
            ledger.emit(SERVICE, "inbound.rejected", token=token, label="T1", claims=claims,
                        reason="introspection: inactive (user disabled, session revoked or logged out)")
            return None
        ledger.emit(SERVICE, "inbound.validated", token=token, label="T1", claims=claims, authorizer=authorizer,
                    introspected=INTROSPECT["enabled"] or None)
        return AccessToken(
            token=token,
            client_id=claims.get("azp") or claims.get("client_id") or "",
            scopes=claims.get("scope", "").split(),
            expires_at=claims["exp"],
            resource=RESOURCE,  # the authorizer already enforced aud ∋ RESOURCE
            subject=claims["sub"],
            claims={**claims, "_authorizer": authorizer},
        )


verifier = GatewayTokenVerifier()

mcp = MCPServer(
    name="atlassian-gateway",
    instructions="Playground MCP gateway in front of Jira Data Center. Jira tools act as the signed-in user. "
    "If a tool says Jira access isn't connected yet, show the user the link it returns, and retry after they've "
    "approved access.",
    token_verifier=verifier,
    auth=AuthSettings(
        # PRM advertises one AS. A second IdP (SPEC §12) will need a custom PRM route.
        issuer_url=verifier.authz.issuers[0],
        resource_server_url=RESOURCE,
        required_scopes=REQUIRED_SCOPES,
        validate_token_resource=False,  # our verifier checks `aud` itself
    ),
)


@mcp.tool(
    name="gateway___whoami",
    description="Show the identity the gateway sees for you: the verified claims of your inbound "
    "access token (no raw token). Useful for checking who you are logged in as.",
)
async def whoami() -> dict[str, Any]:
    at = get_access_token()
    assert at is not None  # RequireAuth guarantees this
    claims = dict(at.claims or {})
    authorizer = claims.pop("_authorizer", None)
    ledger.emit(SERVICE, "tool.call", token=at.token, label="T1", tool="gateway___whoami", sub=at.subject)
    return {
        "authorizer": authorizer,
        "token_fingerprint": fingerprint(at.token),
        "user_id": f"{claims.get('iss')}|{at.subject}",  # the future vault key component (SPEC §3 inv. 3)
        "client_id": at.client_id,
        "scopes": at.scopes,
        "claims": claims,
    }


# ------------------------------------------------------------------ Jira target (phase 4)

_issuer = verifier.authz.issuers[0]
identity = Identity(CONFIG["identity"], f"{_issuer}/protocol/openid-connect/token")
targets = {t["name"]: Target(t, identity) for t in CONFIG.get("targets", [])}
JIRA, CONFLUENCE = targets["jira"], targets["confluence"]


# How "consent needed" reaches the user (SPEC §6.2):
#   auto            URL elicitation (-32042) for clients that declare elicitation.url, else isError text with the link
#   tool_error      always the isError text, so the link lands in the chat (Claude Code drops it on a declined prompt)
#   url_elicitation always -32042, even for clients that didn't declare support
CONSENT_SIGNAL = os.environ.get("GATEWAY_CONSENT_SIGNAL") or CONFIG.get("consentSignal", "auto")
assert CONSENT_SIGNAL in ("auto", "tool_error", "url_elicitation"), CONSENT_SIGNAL
WATCH_INTERVAL_S, WATCH_MAX_S = 2.0, 600.0
_watchers: set[asyncio.Task] = set()




def _supports_url_elicitation(ctx: Context) -> bool:
    caps = ctx.client_capabilities
    return bool(caps and caps.elicitation and caps.elicitation.url is not None)


def _use_url_elicitation(ctx: Context) -> bool:
    return CONSENT_SIGNAL == "url_elicitation" or (CONSENT_SIGNAL == "auto" and _supports_url_elicitation(ctx))


async def _watch_consent(session, c: ConsentRequired, elicitation_id: str) -> None:
    """MCP 2025-11-25: once an out-of-band URL elicitation completes, the server SHOULD send
    notifications/elicitation/complete so the client can retry (without it, Claude Code keeps
    offering "Reopen URL"). We poll identity's session status. A production design would push instead."""
    waited = 0.0
    while waited < WATCH_MAX_S:
        await asyncio.sleep(WATCH_INTERVAL_S)
        waited += WATCH_INTERVAL_S
        try:
            status = await identity.session_status(c.t3, c.session_uri)
        except Exception:  # noqa: BLE001 - T3 expiry (5 min) or identity hiccup: stop watching quietly
            return
        if status == "COMPLETED":
            try:
                await session.send_elicit_complete(elicitation_id)
                ledger.emit(SERVICE, "consent.complete_notified", token=c.session_uri, label="T6",
                            elicitation_id=elicitation_id)
            except Exception as e:  # noqa: BLE001 - client may have no open GET stream / session gone
                ledger.emit(SERVICE, "consent.complete_notify_failed", token=c.session_uri, label="T6",
                            error=e.__class__.__name__)
            return
        if status in ("FAILED", "EXPIRED"):
            return


async def _downstream(ctx: Context, target: Target, tool: str, scopes: list[str], method: str, path: str,
                      **kw) -> Any:
    """Run one Jira call as the user. Translates "consent needed" into the MCP signal the client understands."""
    at = get_access_token()
    assert at is not None
    ledger.emit(SERVICE, "tool.call", token=at.token, label="T1", tool=tool, sub=at.subject)
    try:
        r = await target.call(at.token, scopes, method, path, **kw)
    except ConsentRequired as c:
        product = target.display_name
        input_key = f"{target.name}_consent"  # our key in InputRequiredResult.input_requests (2026-07-28)
        message = (f"{product} access for this assistant isn't connected yet (needs {' '.join(c.scopes)}). "
                   f"Open this link, sign in to {product} and approve access, then ask again: {c.url}")
        proto = ctx.protocol_version or ""
        eid = fingerprint(c.session_uri)
        prior = (ctx.input_responses or {}).get(input_key)
        if prior is not None and getattr(prior, "action", None) in ("decline", "cancel"):
            # 2026-07-28 retry after the user declined/cancelled the prompt: the server DOES learn this,
            # so fall back to the link as text. The model can show it, and the user can still open it later.
            ledger.emit(SERVICE, "consent.signalled", token=c.session_uri, label="T6", mode="tool_error",
                        setting=CONSENT_SIGNAL, protocol=proto, after=prior.action)
            raise ToolError(message) from None
        if _use_url_elicitation(ctx) and proto >= "2026-07-28":
            # 2026-07-28: no -32042 and no notifications/elicitation/complete. Return InputRequiredResult;
            # the client shows the URL, then RETRIES this tools/call ("Retry now"), and the retry finds the
            # token in the vault. No request_state: the vault is the source of truth on every retry.
            ledger.emit(SERVICE, "consent.signalled", token=c.session_uri, label="T6", mode="input_required",
                        setting=CONSENT_SIGNAL, protocol=proto, elicitation_id=eid,
                        retry=prior.action if prior is not None else None)
            return InputRequiredResult(input_requests={input_key: ElicitRequest(params=ElicitRequestURLParams(
                message=f"Connect your {product} account so the assistant can act as you. Retry when you've approved.",
                url=c.url, elicitation_id=eid))})
        if _use_url_elicitation(ctx):
            # 2025-11-25: -32042 is one-way: the gateway never learns if the user declined or dismissed the prompt.
            # So the link also goes in the error message the model sees (not every client shows it).
            ledger.emit(SERVICE, "consent.signalled", token=c.session_uri, label="T6", mode="url_elicitation",
                        setting=CONSENT_SIGNAL, protocol=proto, elicitation_id=eid)
            task = asyncio.create_task(_watch_consent(ctx.session, c, eid))
            _watchers.add(task)
            task.add_done_callback(_watchers.discard)
            raise UrlElicitationRequiredError(
                [ElicitRequestURLParams(message=f"Connect your {product} account so the assistant can act as you.",
                                        url=c.url, elicitation_id=eid)],
                message=message) from None
        ledger.emit(SERVICE, "consent.signalled", token=c.session_uri, label="T6", mode="tool_error",
                    setting=CONSENT_SIGNAL, protocol=proto)
        raise ToolError(message) from None
    except DownstreamError as e:
        raise ToolError(f"Gateway error talking to identity ({e.status}).") from None
    if r.status_code >= 400:
        # Atlassian's own messages are already non-revealing ("does not exist", "no content found"): pass them on.
        try:
            body = r.json()
            msgs = body.get("errorMessages") or ([body["message"]] if body.get("message") else [str(body.get("errors"))])
        except ValueError:
            msgs = [r.text[:200]]
        raise ToolError(f"{target.display_name} returned {r.status_code}: {'; '.join(msgs)}")
    return r.json()


def _issue_summary(i: dict) -> dict[str, Any]:
    f = i["fields"]
    return {"key": i["key"], "summary": f["summary"], "status": f["status"]["name"], "type": f["issuetype"]["name"],
            "project": f["project"]["key"], "assignee": (f.get("assignee") or {}).get("name")}


@mcp.tool(name="jira___get_myself", description="Who am I in Jira? Returns your Jira username and display name.")
async def jira_get_myself(ctx: Context) -> dict[str, Any] | InputRequiredResult:
    me = await _downstream(ctx, JIRA, "jira___get_myself", ["READ"], "GET", "/rest/api/2/myself")
    if isinstance(me, InputRequiredResult):
        return me
    return {k: me.get(k) for k in ("name", "key", "displayName", "emailAddress")}


@mcp.tool(
    name="jira___search_issues",
    description="Search Jira issues you can see, with JQL (e.g. 'project = ALPHA', 'assignee = currentUser() AND "
    "status = \"To Do\"'). An empty JQL lists everything you can see.",
)
async def jira_search_issues(ctx: Context, jql: str = "", max_results: int = 20) -> dict[str, Any] | InputRequiredResult:
    res = await _downstream(ctx, JIRA, "jira___search_issues", ["READ"], "POST", "/rest/api/2/search",
                      json={"jql": jql, "maxResults": max(1, min(max_results, 50))})
    if isinstance(res, InputRequiredResult):
        return res
    return {"total": res["total"], "issues": [_issue_summary(i) for i in res["issues"]]}


@mcp.tool(name="jira___get_issue", description="Get one Jira issue (e.g. ALPHA-1) with its description and comments.")
async def jira_get_issue(ctx: Context, key: str) -> dict[str, Any] | InputRequiredResult:
    i = await _downstream(ctx, JIRA, "jira___get_issue", ["READ"], "GET", f"/rest/api/2/issue/{key}")
    if isinstance(i, InputRequiredResult):
        return i
    f = i["fields"]
    return _issue_summary(i) | {
        "description": f.get("description"), "reporter": (f.get("reporter") or {}).get("name"),
        "comments": [{"author": c["author"]["name"], "body": c["body"], "created": c["created"]}
                     for c in f.get("comment", {}).get("comments", [])]}


@mcp.tool(
    name="jira___add_comment",
    description="Add a comment to a Jira issue as you. Needs WRITE access; you may be asked to approve it.",
)
async def jira_add_comment(ctx: Context, key: str, body: str) -> dict[str, Any] | InputRequiredResult:
    c = await _downstream(ctx, JIRA, "jira___add_comment", ["WRITE"], "POST", f"/rest/api/2/issue/{key}/comment",
                    json={"body": body})
    if isinstance(c, InputRequiredResult):
        return c
    return {"id": c["id"], "author": c["author"]["name"], "created": c["created"]}


# ------------------------------------------------------------------ Confluence target (phase 6)

def _page_summary(p: dict) -> dict[str, Any]:
    return {"id": p["id"], "title": p["title"], "space": p["space"]["key"], "version": p["version"]["number"]}


@mcp.tool(
    name="confluence___search",
    description="Search Confluence pages you can see, with CQL (e.g. 'space = ENG', 'text ~ \"runbook\"'). "
    "An empty CQL lists everything you can see.",
)
async def confluence_search(ctx: Context, cql: str = "", limit: int = 20) -> dict[str, Any] | InputRequiredResult:
    res = await _downstream(ctx, CONFLUENCE, "confluence___search", ["READ"], "GET", "/rest/api/content/search",
                            params={"cql": cql, "limit": max(1, min(limit, 50))})
    if isinstance(res, InputRequiredResult):
        return res
    return {"total": res["totalSize"], "pages": [_page_summary(p) for p in res["results"]]}


@mcp.tool(name="confluence___get_page", description="Get one Confluence page (by id) with its body.")
async def confluence_get_page(ctx: Context, page_id: str) -> dict[str, Any] | InputRequiredResult:
    p = await _downstream(ctx, CONFLUENCE, "confluence___get_page", ["READ"], "GET", f"/rest/api/content/{page_id}")
    if isinstance(p, InputRequiredResult):
        return p
    return _page_summary(p) | {"body": p["body"]["storage"]["value"]}


def _prm_document() -> dict[str, Any]:
    return {
        "resource": RESOURCE,
        "authorization_servers": verifier.authz.issuers,
        "scopes_supported": REQUIRED_SCOPES,
        "bearer_methods_supported": ["header"],
        "resource_name": "Atlassian MCP gateway (playground)",
    }


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def prm_root(_: Request) -> JSONResponse:
    """Root-form PRM, for clients that don't use the path-suffixed form the SDK serves."""
    return JSONResponse(_prm_document())


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(_: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


class WwwAuthenticateScope:
    """Adds `scope="…"` to WWW-Authenticate on 401/403. MCP 2025-11-25 says servers
    SHOULD include it so clients know which scopes to request. SDK 2.3 omits it."""

    def __init__(self, app, scopes: list[str]):
        self.app = app
        self.hint = f', scope="{" ".join(scopes)}"'.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.hint:
            return await self.app(scope, receive, send)

        async def _send(msg):
            if msg["type"] == "http.response.start" and msg["status"] in (401, 403):
                msg = {
                    **msg,
                    "headers": [
                        (k, v + self.hint if k.lower() == b"www-authenticate" and b"scope=" not in v else v)
                        for k, v in msg["headers"]
                    ],
                }
            await send(msg)

        await self.app(scope, receive, _send)


app = WwwAuthenticateScope(
    mcp.streamable_http_app(
        streamable_http_path="/mcp",
        host="0.0.0.0",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[PUBLIC_HOST],
            allowed_origins=[f"https://{PUBLIC_HOST}"],
        ),
    ),
    REQUIRED_SCOPES,
)
