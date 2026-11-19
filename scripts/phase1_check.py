# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 1 exit criteria (SPEC §10): S1 and S14 automated; S2 (Claude Code) is manual.

S1 does exactly what a spec-compliant MCP client does (SPEC §4.1 Flow A):
  unauthenticated request → 401 → PRM from `resource_metadata` → AS metadata →
  DCR → auth code + PKCE with the scope from the challenge → initialize → tools.
S14 sends tokens the gateway must refuse, and shows the reason the gateway logged
for each one in its ledger.
"""

import json
import os
import re
import subprocess
import sys

import httpx
from _oauth import GATEWAY, IDP, ISSUER, Results, browser_authorize, claims, dcr_delete, dcr_register, fp, new_browser

R = Results()
PROTOCOL = "2025-11-25"
ACCEPT = "application/json, text/event-stream"


def rpc(token: str | None, method: str, params: dict | None = None, *, session: str | None = None,
        rid: int | None = 1) -> httpx.Response:
    headers = {"Accept": ACCEPT, "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session:
        headers["Mcp-Session-Id"] = session
        headers["Mcp-Protocol-Version"] = PROTOCOL
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if rid is not None:
        body["id"] = rid
    return httpx.post(GATEWAY, json=body, headers=headers, verify="certs/caddy-root.crt", timeout=15)


def rpc_result(r: httpx.Response) -> dict:
    """Responses may be plain JSON or an SSE stream. Take the last JSON-RPC message."""
    if r.headers.get("content-type", "").startswith("text/event-stream"):
        msgs = [json.loads(line[5:]) for line in r.text.splitlines() if line.startswith("data:")]
        return msgs[-1]
    return r.json()


def initialize(token: str) -> tuple[httpx.Response, str | None]:
    r = rpc(token, "initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                  "clientInfo": {"name": "phase1-check", "version": "0"}})
    sid = r.headers.get("mcp-session-id")
    if r.status_code == 200 and sid:
        rpc(token, "notifications/initialized", session=sid, rid=None)
    return r, sid


def parse_www_authenticate(h: str) -> dict:
    return dict(re.findall(r'(\w+)="([^"]*)"', h))


def s1_and_happy_path() -> tuple[str, dict, httpx.Client]:
    http = new_browser()
    r = rpc(None, "initialize")
    R.check(r.status_code == 401, "S1 unauthenticated → 401", str(r.status_code))
    www = parse_www_authenticate(r.headers.get("www-authenticate", ""))
    R.check("resource_metadata" in www, "S1 WWW-Authenticate has resource_metadata", str(www))
    R.check(www.get("scope") == "mcp:tools", "S1 WWW-Authenticate has scope hint", str(www))

    prm = http.get(www["resource_metadata"]).json()
    R.check(prm.get("resource") == GATEWAY, "S1 PRM resource = gateway URL", str(prm.get("resource")))
    R.check(prm.get("authorization_servers") == [ISSUER], "S1 PRM names the realm as AS")

    issuer = prm["authorization_servers"][0]
    path = issuer.removeprefix(IDP)
    asm = http.get(f"{IDP}/.well-known/oauth-authorization-server{path}").json()  # RFC 8414 path insertion
    R.check(asm.get("issuer") == issuer, "S1 AS metadata via RFC 8414 discovery")

    reg = dcr_register(http, asm["registration_endpoint"], "phase1-check", scope=www["scope"])
    tok = browser_authorize(http, reg["client_id"], www["scope"])
    t1 = tok["access_token"]
    R.check(GATEWAY in (claims(t1)["aud"] if isinstance(claims(t1)["aud"], list) else [claims(t1)["aud"]]),
            "S1 T1 audience = gateway")

    r, sid = initialize(t1)
    R.check(r.status_code == 200 and bool(sid), "S1 initialize with T1 → 200 + session", str(r.status_code))
    tools = rpc_result(rpc(t1, "tools/list", session=sid, rid=2))["result"]["tools"]
    R.check("gateway___whoami" in [t["name"] for t in tools], "S1 tools/list includes gateway___whoami")
    res = rpc_result(rpc(t1, "tools/call", {"name": "gateway___whoami", "arguments": {}}, session=sid, rid=3))
    who = res["result"].get("structuredContent") or json.loads(res["result"]["content"][0]["text"])
    R.check(who["claims"].get("preferred_username") == "alice", "S1 whoami → alice")
    R.check(who["token_fingerprint"] == fp(t1), "S1 whoami fingerprint matches T1")
    R.check("access_token" not in json.dumps(who) and t1 not in json.dumps(who), "whoami never echoes the raw token")
    print(f"\n  whoami: user_id={who['user_id']} client={who['client_id']} scopes={who['scopes']}")
    return sid, {"t1": t1, "tok": tok, "reg": reg}, http


def s14_rejections(ctx: dict, alice_sid: str) -> list[tuple[str, str]]:
    """Each case must get 401 at initialize. Returns (case, fingerprint) for the ledger lookup."""
    cases: list[tuple[str, str]] = []
    http_alice = new_browser()

    # a) Same DCR client, scope without mcp:tools → no gateway audience.
    no_mcp = browser_authorize(http_alice, ctx["reg"]["client_id"], "openid")
    cases.append(("DCR client token without mcp:tools", no_mcp["access_token"]))

    # b) The portal's token (T2). Keycloak refuses to even issue mcp:tools to the portal
    #    client (invalid_scope), and its normal token must be rejected by the gateway.
    portal = {"redirect_uri": "https://portal.localtest.me/callback",
              "client_secret": os.environ["PORTAL_CLIENT_SECRET"], "resource": None}
    try:
        browser_authorize(new_browser(), "portal", "openid mcp:tools", **portal)
        R.check(False, "Keycloak refuses mcp:tools to the portal client", "token was issued")
    except RuntimeError as e:
        R.check("invalid_scope" in str(e), "Keycloak refuses mcp:tools to the portal client", str(e)[:80])
    t = browser_authorize(new_browser(), "portal", "openid", **portal)["access_token"]
    cases.append(("portal token T2 (aud≠gateway)", t))

    # c) An ID token instead of an access token.
    cases.append(("ID token instead of access token", no_mcp["id_token"]))

    # d) Tampered signature on a valid T1.
    h, p, s = ctx["t1"].split(".")
    cases.append(("T1 with tampered signature", f"{h}.{p}.{s[:-4]}{'AAAA' if s[-4:] != 'AAAA' else 'BBBB'}"))

    # e) A token from an untrusted issuer (Keycloak master realm).
    m = httpx.post(f"{IDP}/realms/master/protocol/openid-connect/token", verify="certs/caddy-root.crt", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": os.environ["KC_ADMIN_USER"], "password": os.environ["KC_ADMIN_PASSWORD"]})
    cases.append(("master-realm token (untrusted issuer)", m.json()["access_token"]))

    for name, tok in cases:
        r, _ = initialize(tok)
        www = parse_www_authenticate(r.headers.get("www-authenticate", ""))
        R.check(r.status_code == 401 and "resource_metadata" in www, f"S14 {name} → 401", str(r.status_code))

    # f) Session binding: bob's valid token may not drive alice's MCP session.
    bob_http = new_browser()
    bob_reg = dcr_register(bob_http, f"{ISSUER}/clients-registrations/openid-connect", "phase1-bob")
    bob_t1 = browser_authorize(bob_http, bob_reg["client_id"], "mcp:tools", user="bob")["access_token"]
    r = rpc(bob_t1, "tools/call", {"name": "gateway___whoami", "arguments": {}}, session=alice_sid, rid=9)
    R.check(r.status_code in (403, 404), "bob's token cannot use alice's MCP session", f"{r.status_code} {r.text[:80]}")
    dcr_delete(bob_http, bob_reg)

    return [(n, fp(t)) for n, t in cases]


def ledger_reasons(fps: list[tuple[str, str]], raw_t1: str) -> None:
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "gateway"],
                          check=False, capture_output=True, text=True).stdout
    events = [json.loads(line[7:]) for line in logs.splitlines() if line.startswith("LEDGER ")]
    print("\n  Gateway ledger, rejection reasons:")
    for name, f in fps:
        ev = next((e for e in reversed(events) if e.get("fp") == f and e["event"] == "inbound.rejected"), None)
        R.check(ev is not None, f"ledger recorded rejection: {name}")
        print(f"    {name:42} → {ev['reason'] if ev else '??'}")
    R.check(raw_t1 not in logs, "raw T1 never appears in gateway logs (invariant 6)")


def main() -> None:
    sid, ctx, http = s1_and_happy_path()
    try:
        fps = s14_rejections(ctx, sid)
        ledger_reasons(fps, ctx["t1"])
    finally:
        dcr_delete(http, ctx["reg"])


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        R.check(False, "unexpected error", repr(e))
    finally:
        sys.exit(R.report())
