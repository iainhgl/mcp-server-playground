"""MCP gateway: the OAuth-protected MCP server that clients connect to (SPEC §6.2).

Phase 1 scope:
- Streamable HTTP at /mcp. The MCP SDK provides the resource-server plumbing:
  BearerAuth → RequireAuth (401/403 + WWW-Authenticate) and PRM (RFC 9728).
- Our TokenVerifier is the AgentCore-style multi-issuer JWT authorizer, and it
  writes a ledger event for every accept/reject.
- Tool `gateway___whoami` echoes the verified inbound identity (no downstream yet).
"""

import os
from pathlib import Path
from typing import Any

import yaml
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from playground_common import fingerprint, ledger
from playground_common.http import async_client
from playground_common.jwt_authz import AuthorizerConfig, AuthzError, MultiIssuerAuthorizer
from starlette.requests import Request
from starlette.responses import JSONResponse

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
    instructions="Playground MCP gateway. Phase 1: identity only (gateway___whoami).",
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
