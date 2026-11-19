# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 0 exit criteria (SPEC §10), checked from the host over trusted TLS.

Imitates what an MCP client does in SPEC §4.1 Flow A, without the gateway:
discovery → DCR → auth code + PKCE (as alice, through the real login and
consent pages) → check the access token's claims.
"""

import sys

import httpx
from _oauth import (
    GATEWAY,
    IDP,
    ISSUER,
    Results,
    aud_list,
    browser_authorize,
    claims,
    dcr_delete,
    dcr_register,
    fp,
    new_browser,
)

R = Results()


def main() -> None:
    http = new_browser()

    meta = http.get(f"{ISSUER}/.well-known/openid-configuration").json()
    R.check(meta.get("issuer") == ISSUER, "OIDC discovery over trusted TLS", meta.get("issuer", ""))
    # MCP clients try RFC 8414 path-insertion first; Keycloak must serve it natively.
    r = http.get(f"{IDP}/.well-known/oauth-authorization-server/realms/playground")
    R.check(r.status_code == 200 and r.json().get("issuer") == ISSUER,
            "RFC 8414 path-inserted AS metadata", str(r.status_code))
    R.check("S256" in meta.get("code_challenge_methods_supported", []), "PKCE S256 advertised")
    reg_ep = meta.get("registration_endpoint", "")
    R.check(bool(reg_ep), "registration_endpoint advertised", reg_ep)

    try:
        reg = dcr_register(http, reg_ep, "phase0-check")
        R.check(True, "DCR: loopback redirect accepted")
    except httpx.HTTPStatusError as e:
        R.check(False, "DCR: loopback redirect accepted", f"{e.response.status_code} {e.response.text[:120]}")
        return
    client_id = reg["client_id"]

    bad = http.post(reg_ep, json={"client_name": "evil", "redirect_uris": ["https://evil.example/cb"],
                                  "token_endpoint_auth_method": "none"})
    R.check(bad.status_code in (400, 403), "DCR: untrusted redirect host rejected", str(bad.status_code))

    try:
        tok = browser_authorize(http, client_id, "openid mcp:tools")
        c = claims(tok["access_token"])
        print(f"\n  T1 fp={fp(tok['access_token'])} claims (with mcp:tools):")
        for k in ("iss", "aud", "azp", "sub", "preferred_username", "scope", "exp"):
            print(f"    {k:20} {c.get(k)}")
        R.check(c["iss"] == ISSUER, "token iss = realm issuer")
        R.check(GATEWAY in aud_list(c), "aud contains gateway resource when mcp:tools requested", str(c.get("aud")))
        R.check(c.get("azp") == client_id, "azp = DCR client_id")
        R.check("mcp:tools" in c.get("scope", "").split(), "scope contains mcp:tools")
        R.check(tok.get("refresh_token") is not None, "refresh token issued (T1r)")

        tok2 = browser_authorize(http, client_id, "openid")
        aud2 = aud_list(claims(tok2["access_token"]))
        R.check(GATEWAY not in aud2, "aud omits gateway when mcp:tools not requested", str(aud2))
    except Exception as e:  # noqa: BLE001
        R.check(False, "browser auth code + PKCE flow", repr(e))
    finally:
        R.check(dcr_delete(http, reg) == 204, "DCR client deleted via registration_access_token")

    bao = httpx.get("http://localhost:8200/v1/sys/health", timeout=5)
    R.check(bao.status_code == 200, "OpenBao initialised + unsealed", str(bao.status_code))
    mitm = httpx.get("http://localhost:8081/", timeout=5)
    R.check(mitm.status_code in (200, 401, 403), "mitmweb reachable", str(mitm.status_code))


if __name__ == "__main__":
    try:
        main()
    finally:
        sys.exit(R.report())
