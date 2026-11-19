# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Reconcile the `playground` realm (Keycloak acting as Red Hat SSO) to the
desired state in SPEC §6.1. Idempotent: it runs on every `up`, and changing a
value here and re-running updates Keycloak in place without wiping volumes.

Desired state:
- realm `playground`, 5 min access tokens
- user-profile attribute `jira_username` (KC 24+ drops unmanaged attributes)
- client scope `mcp:tools` + audience mapper -> https://gateway.localtest.me/mcp
  It is a realm *optional* scope, so the gateway audience only appears when a
  client asks for `mcp:tools`. Other clients (portal, …) never mint gateway tokens.
- clients: mcp-public (pre-registered fallback), portal, gateway-svc, identity
- anonymous DCR policy: trusted redirect hosts = loopback + vscode.dev
- seed users alice, bob, carol, dave
"""

import os
import sys
import time

import httpx

KC = os.environ.get("KC_URL", "http://keycloak:8080")
REALM = "playground"
GATEWAY_RESOURCE = "https://gateway.localtest.me/mcp"
MCP_SCOPE = "mcp:tools"
DCR_POLICY_TYPE = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
TRUSTED_DCR_HOSTS = ["localhost", "127.0.0.1", "vscode.dev"]

REALM_SETTINGS = {
    "realm": REALM,
    "id": REALM,
    "enabled": True,
    "displayName": "Playground SSO (Red Hat SSO stand-in)",
    "sslRequired": "external",
    "registrationAllowed": False,
    "accessTokenLifespan": 300,
    "ssoSessionIdleTimeout": 1800,
    "ssoSessionMaxLifespan": 36000,
}

USERS = [
    {"username": "alice", "firstName": "Alice", "lastName": "Anders", "jira_username": "alice"},
    {"username": "bob", "firstName": "Bob", "lastName": "Brown", "jira_username": "bob"},
    {"username": "carol", "firstName": "Carol", "lastName": "White", "jira_username": "carol.w"},
    {"username": "dave", "firstName": "Dave", "lastName": "Davis", "jira_username": None},
]


def env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"missing env {name}: run `make env`")
    return v


def audience_mapper(name: str, audience: str) -> dict:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.custom.audience": audience,
            "access.token.claim": "true",
            "id.token.claim": "false",
            "introspection.token.claim": "true",
        },
    }


CLIENTS = [
    {
        # Fallback for MCP clients / IdPs that can't use DCR (this is what Entra will need).
        "clientId": "mcp-public",
        "name": "MCP clients (pre-registered)",
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": ["http://127.0.0.1/*", "http://localhost/*", "https://vscode.dev/redirect"],
        "attributes": {"pkce.code.challenge.method": "S256"},
        "_mcp_scope": True,
    },
    {
        "clientId": "portal",
        "name": "Consent portal",
        "publicClient": False,
        "secret": env("PORTAL_CLIENT_SECRET"),
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": ["https://portal.localtest.me/callback"],
        "webOrigins": ["https://portal.localtest.me"],
        "attributes": {"pkce.code.challenge.method": "S256",
                       "post.logout.redirect.uris": "https://portal.localtest.me/*"},
        # User tokens (T2) say they're for the portal, so identity can accept them as `userToken`
        # while the gateway still rejects them.
        "_mappers": [audience_mapper("audience: portal", "portal")],
    },
    {
        # The portal's *service* credential for calling identity. It's a separate client on purpose:
        # a user's portal token (T2) must never double as the portal's service identity.
        "clientId": "portal-svc",
        "name": "Portal service account",
        "publicClient": False,
        "secret": env("PORTAL_SVC_CLIENT_SECRET"),
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "_mappers": [audience_mapper("audience: identity", "identity")],
    },
    {
        # The gateway's own service credential (T7), standing in for IAM.
        "clientId": "gateway-svc",
        "name": "Gateway service account",
        "publicClient": False,
        "secret": env("GATEWAY_SVC_CLIENT_SECRET"),
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "_mappers": [audience_mapper("audience: identity", "identity")],
    },
    {
        # Resource-only: the audience the identity service checks for.
        "clientId": "identity",
        "name": "Identity service (resource)",
        "publicClient": False,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
    },
]


class AdminAuth(httpx.Auth):
    """Master-realm admin token, refreshed before its 60 s lifetime runs out."""

    def __init__(self) -> None:
        self._token, self._at = "", 0.0

    def auth_flow(self, request):
        if time.monotonic() - self._at > 45:
            r = httpx.post(
                f"{KC}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": env("KC_ADMIN_USER"),
                    "password": env("KC_ADMIN_PASSWORD"),
                },
            )
            r.raise_for_status()
            self._token, self._at = r.json()["access_token"], time.monotonic()
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


api = httpx.Client(base_url=f"{KC}/admin/realms", auth=AdminAuth(), timeout=30)


def log(msg: str) -> None:
    print(f"[keycloak-init] {msg}", flush=True)


def ok(r: httpx.Response) -> httpx.Response:
    if r.is_error:
        sys.exit(f"{r.request.method} {r.request.url} -> {r.status_code}: {r.text}")
    return r


def created_id(r: httpx.Response) -> str:
    return ok(r).headers["Location"].rstrip("/").rsplit("/", 1)[-1]


def ensure_realm() -> None:
    if api.get(f"/{REALM}").status_code == 404:
        ok(api.post("", json=REALM_SETTINGS))
        log(f"created realm {REALM}")
    else:
        ok(api.put(f"/{REALM}", json=REALM_SETTINGS))


def ensure_user_profile() -> None:
    profile = ok(api.get(f"/{REALM}/users/profile")).json()
    if not any(a["name"] == "jira_username" for a in profile["attributes"]):
        profile["attributes"].append(
            {
                "name": "jira_username",
                "displayName": "Jira username",
                "permissions": {"view": ["admin"], "edit": ["admin"]},
                "multivalued": False,
            }
        )
        ok(api.put(f"/{REALM}/users/profile", json=profile))
        log("added user-profile attribute jira_username")


def ensure_mapper(base: str, mapper: dict) -> None:
    existing = {m["name"]: m for m in ok(api.get(f"{base}/protocol-mappers/models")).json()}
    if mapper["name"] in existing:
        ok(api.put(f"{base}/protocol-mappers/models/{existing[mapper['name']]['id']}",
                   json={**mapper, "id": existing[mapper["name"]]["id"]}))
    else:
        ok(api.post(f"{base}/protocol-mappers/models", json=mapper))


def ensure_mcp_scope() -> str:
    rep = {
        "name": MCP_SCOPE,
        "protocol": "openid-connect",
        "description": "Call tools on the Atlassian MCP gateway",
        "attributes": {
            "include.in.token.scope": "true",
            "display.on.consent.screen": "true",
            "consent.screen.text": "Use Atlassian tools through the MCP gateway",
        },
    }
    scopes = {s["name"]: s for s in ok(api.get(f"/{REALM}/client-scopes")).json()}
    if MCP_SCOPE in scopes:
        sid = scopes[MCP_SCOPE]["id"]
        ok(api.put(f"/{REALM}/client-scopes/{sid}", json={**rep, "id": sid}))
    else:
        sid = created_id(api.post(f"/{REALM}/client-scopes", json=rep))
        log(f"created client scope {MCP_SCOPE}")
    ensure_mapper(f"/{REALM}/client-scopes/{sid}", audience_mapper("audience: gateway", GATEWAY_RESOURCE))
    # Realm *optional* scope: DCR clients get it, and it only applies when requested.
    realm_optional = ok(api.get(f"/{REALM}/default-optional-client-scopes")).json()
    if not any(s["id"] == sid for s in realm_optional):
        ok(api.put(f"/{REALM}/default-optional-client-scopes/{sid}"))
    return sid


def ensure_client(spec: dict, mcp_scope_id: str) -> None:
    rep = {k: v for k, v in spec.items() if not k.startswith("_")}
    found = ok(api.get(f"/{REALM}/clients", params={"clientId": rep["clientId"]})).json()
    if found:
        cid = found[0]["id"]
        ok(api.put(f"/{REALM}/clients/{cid}", json={**found[0], **rep}))
    else:
        cid = created_id(api.post(f"/{REALM}/clients", json=rep))
        log(f"created client {rep['clientId']}")
    for m in spec.get("_mappers", []):
        ensure_mapper(f"/{REALM}/clients/{cid}", m)
    # Only clients that are meant to call the gateway may request the gateway audience.
    scopes_path = f"/{REALM}/clients/{cid}/optional-client-scopes"
    has_scope = any(s["id"] == mcp_scope_id for s in ok(api.get(scopes_path)).json())
    if spec.get("_mcp_scope") and not has_scope:
        ok(api.put(f"{scopes_path}/{mcp_scope_id}"))
    elif not spec.get("_mcp_scope") and has_scope:
        ok(api.delete(f"{scopes_path}/{mcp_scope_id}"))


def ensure_dcr_policies() -> None:
    comps = ok(api.get(f"/{REALM}/components", params={"type": DCR_POLICY_TYPE})).json()
    for c in comps:
        if c.get("subType") != "anonymous":
            continue
        if c["providerId"] == "trusted-hosts":
            c["config"] = {
                "trusted-hosts": TRUSTED_DCR_HOSTS,
                # Registration requests arrive via the proxy from the host machine, so
                # don't check the *sender's* address. Instead require every redirect URI
                # to be on a trusted host (loopback / vscode.dev).
                "host-sending-registration-request-must-match": ["false"],
                "client-uris-must-match": ["true"],
            }
            ok(api.put(f"/{REALM}/components/{c['id']}", json=c))
        elif c["providerId"] == "allowed-client-templates":
            c["config"] = {**c.get("config", {}), "allow-default-scopes": ["true"]}
            ok(api.put(f"/{REALM}/components/{c['id']}", json=c))


def ensure_users() -> None:
    password = env("SEED_USER_PASSWORD")
    for u in USERS:
        rep = {
            "username": u["username"],
            "firstName": u["firstName"],
            "lastName": u["lastName"],
            "email": f"{u['username']}@example.test",
            "emailVerified": True,
            "enabled": True,
            "attributes": {"jira_username": [u["jira_username"]]} if u["jira_username"] else {},
        }
        found = ok(api.get(f"/{REALM}/users", params={"username": u["username"], "exact": "true"})).json()
        if found:
            uid = found[0]["id"]
            ok(api.put(f"/{REALM}/users/{uid}", json=rep))
        else:
            uid = created_id(api.post(f"/{REALM}/users", json=rep))
            log(f"created user {u['username']}")
        ok(api.put(f"/{REALM}/users/{uid}/reset-password",
                   json={"type": "password", "value": password, "temporary": False}))


def main() -> None:
    ensure_realm()
    ensure_user_profile()
    sid = ensure_mcp_scope()
    for spec in CLIENTS:
        ensure_client(spec, sid)
    ensure_dcr_policies()
    ensure_users()
    log("realm reconciled")


if __name__ == "__main__":
    main()
