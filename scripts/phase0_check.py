# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 0 exit criteria (SPEC §10), checked from the host over trusted TLS.

Imitates what an MCP client does in SPEC §4.1 Flow A, without the gateway:
discovery → DCR → auth code + PKCE (as alice, through the real login and
consent pages) → check the access token's claims. Prints claims and
fingerprints only, never raw tokens (SPEC §3 invariant 6).
"""

import base64
import hashlib
import html
import json
import os
import secrets
import sys
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

IDP = "https://idp.localtest.me"
ISSUER = f"{IDP}/realms/playground"
GATEWAY = "https://gateway.localtest.me/mcp"
REDIRECT = "http://127.0.0.1:33418/callback"
CA = "certs/caddy-root.crt"

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    results.append((ok, name, detail))
    return ok


def fp(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def claims(jwt: str) -> dict:
    body = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


class Forms(HTMLParser):
    """Collect <form action> and its <input> fields from Keycloak's login pages."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append({"action": html.unescape(a.get("action") or ""), "fields": {}})
        elif tag in ("input", "button") and self.forms and a.get("name"):
            self.forms[-1]["fields"].setdefault(a["name"], a.get("value") or "")


def browser_authorize(http: httpx.Client, client_id: str, scope: str) -> dict:
    """Run auth code + PKCE the way a browser would. Returns the token response."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    r = http.get(f"{ISSUER}/protocol/openid-connect/auth", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "scope": scope, "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": GATEWAY,
    })
    for _ in range(6):  # login page → (consent page) → redirect to the loopback callback
        while r.is_redirect:
            loc = r.headers["location"]
            if loc.startswith(REDIRECT):
                q = parse_qs(urlparse(loc).query)
                if "error" in q:
                    raise RuntimeError(f"authorize error: {q}")
                assert q["state"][0] == state, "state mismatch"
                tok = httpx.post(f"{ISSUER}/protocol/openid-connect/token", verify=CA, data={
                    "grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
                    "client_id": client_id, "code_verifier": verifier, "resource": GATEWAY,
                })
                tok.raise_for_status()
                return tok.json()
            r = http.get(urljoin(str(r.url), loc))
        p = Forms()
        p.feed(r.text)
        form = next((f for f in p.forms if "login-actions" in f["action"]), None)
        if not form:
            raise RuntimeError(f"no Keycloak form on page {r.url} (status {r.status_code})")
        data = {k: v for k, v in form["fields"].items() if k not in ("accept", "cancel")}
        if "username" in form["fields"]:
            data |= {"username": "alice", "password": os.environ["SEED_USER_PASSWORD"]}
        if "accept" in form["fields"]:
            data["accept"] = form["fields"]["accept"] or "Yes"
        r = http.post(urljoin(str(r.url), form["action"]), data=data)
    raise RuntimeError("authorize flow did not complete")


def main() -> None:
    http = httpx.Client(verify=CA, timeout=15, follow_redirects=False)

    # 1. Discovery: appended (Keycloak native) and inserted (RFC 8414 / MCP client) forms.
    meta = http.get(f"{ISSUER}/.well-known/openid-configuration").json()
    check(meta.get("issuer") == ISSUER, "OIDC discovery over trusted TLS", meta.get("issuer", ""))
    # MCP clients try RFC 8414 path-insertion first; Keycloak must serve it natively.
    r = http.get(f"{IDP}/.well-known/oauth-authorization-server/realms/playground")
    check(r.status_code == 200 and r.json().get("issuer") == ISSUER,
          "RFC 8414 path-inserted AS metadata", str(r.status_code))
    check("S256" in meta.get("code_challenge_methods_supported", []), "PKCE S256 advertised")
    reg_ep = meta.get("registration_endpoint", "")
    check(bool(reg_ep), "registration_endpoint advertised", reg_ep)

    # 2. DCR, as Claude Code would register itself.
    dcr = {
        "client_name": "phase0-check", "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none", "scope": "mcp:tools",
    }
    r = http.post(reg_ep, json=dcr)
    if not check(r.status_code == 201, "DCR: loopback redirect accepted", f"{r.status_code} {r.text[:120]}"):
        return
    reg = r.json()
    client_id = reg["client_id"]

    bad = http.post(reg_ep, json={**dcr, "client_name": "evil", "redirect_uris": ["https://evil.example/cb"]})
    check(bad.status_code in (400, 403), "DCR: untrusted redirect host rejected", str(bad.status_code))

    try:
        # 3. Auth code + PKCE as alice, asking for mcp:tools.
        tok = browser_authorize(http, client_id, "openid mcp:tools")
        c = claims(tok["access_token"])
        aud = c["aud"] if isinstance(c["aud"], list) else [c["aud"]]
        print(f"\n  T1 fp={fp(tok['access_token'])} claims (with mcp:tools):")
        for k in ("iss", "aud", "azp", "sub", "preferred_username", "scope", "exp"):
            print(f"    {k:20} {c.get(k)}")
        check(c["iss"] == ISSUER, "token iss = realm issuer")
        check(GATEWAY in aud, "aud contains gateway resource when mcp:tools requested", str(aud))
        check(c.get("azp") == client_id, "azp = DCR client_id")
        check("mcp:tools" in c.get("scope", "").split(), "scope contains mcp:tools")
        check(tok.get("refresh_token") is not None, "refresh token issued (T1r)")

        # 4. Same client, no mcp:tools: the gateway audience must be absent.
        tok2 = browser_authorize(http, client_id, "openid")
        aud2 = claims(tok2["access_token"]).get("aud", [])
        aud2 = aud2 if isinstance(aud2, list) else [aud2]
        check(GATEWAY not in aud2, "aud omits gateway when mcp:tools not requested", str(aud2))
    except Exception as e:  # noqa: BLE001
        check(False, "browser auth code + PKCE flow", repr(e))
    finally:
        d = http.delete(reg["registration_client_uri"],
                        headers={"Authorization": f"Bearer {reg['registration_access_token']}"})
        check(d.status_code == 204, "DCR client deleted via registration_access_token", str(d.status_code))

    # 5. Supporting services.
    bao = httpx.get("http://localhost:8200/v1/sys/health", timeout=5)
    check(bao.status_code == 200, "OpenBao initialised + unsealed", str(bao.status_code))
    mitm = httpx.get("http://localhost:8081/", timeout=5)
    check(mitm.status_code in (200, 401, 403), "mitmweb reachable", str(mitm.status_code))


if __name__ == "__main__":
    try:
        main()
    finally:
        print()
        for ok, name, detail in results:
            print(f"  {'✓' if ok else '✗'} {name}" + (f"  [{detail}]" if detail and not ok else ""))
        failed = sum(not ok for ok, *_ in results)
        print(f"\n  {len(results) - failed}/{len(results)} passed")
        sys.exit(1 if failed else 0)
