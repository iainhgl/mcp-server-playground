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

import os
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
from mcp_types import ElicitRequestURLParams
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

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            authorizer, claims = await self.authz.validate(token)
        except AuthzError as e:
            ledger.emit(SERVICE, "inbound.rejected", token=token, label="T1?", reason=e.reason)
            return None
        ledger.emit(SERVICE, "inbound.validated", token=token, label="T1", claims=claims, authorizer=authorizer)
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
JIRA = targets["jira"]


def _supports_url_elicitation(ctx: Context) -> bool:
    caps = ctx.client_capabilities
    return bool(caps and caps.elicitation and caps.elicitation.url is not None)


async def _jira(ctx: Context, tool: str, scopes: list[str], method: str, path: str, **kw) -> Any:
    """Run one Jira call as the user. Translates "consent needed" into the MCP signal the client understands."""
    at = get_access_token()
    assert at is not None
    ledger.emit(SERVICE, "tool.call", token=at.token, label="T1", tool=tool, sub=at.subject)
    try:
        r = await JIRA.call(at.token, scopes, method, path, **kw)
    except ConsentRequired as c:
        message = (f"Jira access for this assistant isn't connected yet (needs {' '.join(c.scopes)}). "
                   f"Open this link, sign in to Jira and approve access, then ask again: {c.url}")
        if _supports_url_elicitation(ctx):
            ledger.emit(SERVICE, "consent.signalled", token=c.session_uri, label="T6", mode="url_elicitation")
            raise UrlElicitationRequiredError([ElicitRequestURLParams(
                message="Connect your Jira account so the assistant can act as you.",
                url=c.url, elicitation_id=fingerprint(c.session_uri))]) from None
        ledger.emit(SERVICE, "consent.signalled", token=c.session_uri, label="T6", mode="tool_error")
        raise ToolError(message) from None
    except DownstreamError as e:
        raise ToolError(f"Gateway error talking to identity ({e.status}).") from None
    if r.status_code >= 400:
        # Jira's own messages are already non-revealing ("does not exist", "no permission"): pass them on.
        try:
            msgs = r.json().get("errorMessages") or [str(r.json().get("errors"))]
        except ValueError:
            msgs = [r.text[:200]]
        raise ToolError(f"Jira returned {r.status_code}: {'; '.join(msgs)}")
    return r.json()


def _issue_summary(i: dict) -> dict[str, Any]:
    f = i["fields"]
    return {"key": i["key"], "summary": f["summary"], "status": f["status"]["name"], "type": f["issuetype"]["name"],
            "project": f["project"]["key"], "assignee": (f.get("assignee") or {}).get("name")}


@mcp.tool(name="jira___get_myself", description="Who am I in Jira? Returns your Jira username and display name.")
async def jira_get_myself(ctx: Context) -> dict[str, Any]:
    me = await _jira(ctx, "jira___get_myself", ["READ"], "GET", "/rest/api/2/myself")
    return {k: me.get(k) for k in ("name", "key", "displayName", "emailAddress")}


@mcp.tool(
    name="jira___search_issues",
    description="Search Jira issues you can see, with JQL (e.g. 'project = ALPHA', 'assignee = currentUser() AND "
    "status = \"To Do\"'). An empty JQL lists everything you can see.",
)
async def jira_search_issues(ctx: Context, jql: str = "", max_results: int = 20) -> dict[str, Any]:
    res = await _jira(ctx, "jira___search_issues", ["READ"], "POST", "/rest/api/2/search",
                      json={"jql": jql, "maxResults": max(1, min(max_results, 50))})
    return {"total": res["total"], "issues": [_issue_summary(i) for i in res["issues"]]}


@mcp.tool(name="jira___get_issue", description="Get one Jira issue (e.g. ALPHA-1) with its description and comments.")
async def jira_get_issue(ctx: Context, key: str) -> dict[str, Any]:
    i = await _jira(ctx, "jira___get_issue", ["READ"], "GET", f"/rest/api/2/issue/{key}")
    f = i["fields"]
    return _issue_summary(i) | {
        "description": f.get("description"), "reporter": (f.get("reporter") or {}).get("name"),
        "comments": [{"author": c["author"]["name"], "body": c["body"], "created": c["created"]}
                     for c in f.get("comment", {}).get("comments", [])]}


@mcp.tool(
    name="jira___add_comment",
    description="Add a comment to a Jira issue as you. Needs WRITE access; you may be asked to approve it.",
)
async def jira_add_comment(ctx: Context, key: str, body: str) -> dict[str, Any]:
    c = await _jira(ctx, "jira___add_comment", ["WRITE"], "POST", f"/rest/api/2/issue/{key}/comment",
                    json={"body": body})
    return {"id": c["id"], "author": c["author"]["name"], "created": c["created"]}


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
