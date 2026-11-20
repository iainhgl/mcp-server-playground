# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 5 exit criteria (SPEC §10): lifecycle and attacks through the real gateway.

  S6   a stale T4 is refreshed transparently through the gateway, and the old T5 is rotated (dead)
  S7   10 concurrent tool calls on a stale T4 → exactly ONE refresh at Jira
  S10  verify mode: alice approves while her browser is logged in to Jira as bob → rejected, nothing stored
  S16  step-up to WRITE denied at Jira → the existing READ grant keeps working
  S17  alice disabled in Keycloak: her T1 still works until exp (the gap); her offline refresh token dies;
       with gateway introspection on, the same T1 is refused
  PKCE an auth-code request without PKCE is refused for every client (incl. DCR)
"""

import concurrent.futures
import html
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import httpx
from _mcp import McpSession
from _oauth import (
    CA,
    IDP,
    ISSUER,
    LOOPBACK,
    Results,
    browse,
    browser_authorize,
    claims,
    dcr_delete,
    dcr_register,
    new_browser,
)

PORTAL, JIRA = "https://portal.localtest.me", "https://jira.localtest.me"
STUB_ADMIN = {"X-Stub-Admin": os.environ["STUB_ADMIN_TOKEN"]}
LINK = re.compile(r"https://jira\.localtest\.me/rest/oauth2/latest/authorize\?\S+")
R = Results()


def psql(db: str, sql: str) -> str:
    return subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", db, "-At",
                           "-c", sql], check=True, capture_output=True, text=True).stdout.strip()


def ledger(since: str) -> list[dict]:
    rows = psql("ledger", f"select data from events where ts >= '{since}' order by ts, id")
    return [json.loads(x) for x in rows.splitlines() if x]


def gateway_env(**env: str) -> None:
    subprocess.run(["docker", "compose", "up", "-d", "--wait", "gateway"], check=True, capture_output=True,
                   env=os.environ | env)


def kc_admin() -> httpx.Client:
    tok = httpx.post(f"{IDP}/realms/master/protocol/openid-connect/token", verify=CA, data={
        "grant_type": "password", "client_id": "admin-cli", "username": os.environ["KC_ADMIN_USER"],
        "password": os.environ["KC_ADMIN_PASSWORD"]}).json()["access_token"]
    return httpx.Client(base_url=f"{IDP}/admin/realms/playground", verify=CA,
                        headers={"Authorization": f"Bearer {tok}"})


class Person:
    def __init__(self, name: str, scope: str = "mcp:tools"):
        self.name, self.b = name, new_browser()
        self.reg = dcr_register(self.b, f"{ISSUER}/clients-registrations/openid-connect", f"phase5-{name}",
                                scope=scope)
        self.tok = browser_authorize(self.b, self.reg["client_id"], scope, user=name)
        self.t1 = self.tok["access_token"]

    def mcp(self) -> McpSession:
        return McpSession(self.t1, {}, f"phase5-{self.name}")

    def user_id_like(self) -> str:
        return f"%|{claims(self.t1)['sub']}"


def keys(res: dict) -> list[str]:
    return sorted(i["key"] for i in (res.get("data") or {}).get("issues", []))


def connect(p: Person, m: McpSession, tool: str = "jira___search_issues", args: dict | None = None,
            jira_user: str | None = None, decision: str = "allow") -> dict:
    """Trigger consent via a tool call and walk the link like the user's browser. Returns browse() output."""
    first = m.call(tool, args or {})
    link = LINK.search(first.get("text", ""))
    assert link, f"expected a consent link, got {first}"
    return browse(p.b, link.group(0), p.name, jira_user, jira_decision=decision)


def main() -> None:
    httpx.delete(f"{JIRA}/_stub/faults", headers=STUB_ADMIN, verify=CA)
    psql("identity", "delete from token_vault")
    alice = Person("alice")
    m = alice.mcp()

    # ---- S6 + S7: stale T4, then 10 concurrent tool calls through the gateway
    httpx.post(f"{JIRA}/_stub/faults", headers=STUB_ADMIN, json={"access_ttl": 1}, verify=CA)
    res = connect(alice, m)
    httpx.delete(f"{JIRA}/_stub/faults", headers=STUB_ADMIN, verify=CA)
    R.check("Jira connected" in res["text"], "alice connected (T4 issued with a 1 s lifetime)")
    since = datetime.now(UTC).isoformat()
    with concurrent.futures.ThreadPoolExecutor(10) as ex:
        outs = list(ex.map(lambda _: McpSession(alice.t1, {}, "phase5-par").call("jira___search_issues"), range(10)))
    ev = ledger(since)
    refreshes = [e for e in ev if e["service"] == "jira-stub" and e["event"] == "oauth.token_refreshed"]
    R.check(all(keys(o) == ["ALPHA-1", "ALPHA-2", "ALPHA-3"] for o in outs),
            "S7 10 concurrent tool calls through the gateway all return alice's issues")
    R.check(len(refreshes) == 1, "S7 exactly ONE refresh at Jira (identity row lock)", f"{len(refreshes)}")
    hits = sum(e["event"] == "vault.hit" for e in ev)
    R.check(hits == 9, "S7 9 vault hits waited for the lock, then used the new T4", str(hits))
    old_t5 = next((e["fp"] for e in ev if e["event"] == "vault.refresh_start"), "")
    state = httpx.get(f"{JIRA}/_stub/state", headers=STUB_ADMIN, verify=CA).json()
    row = next((t for t in state["tokens"] if t["hash"] == old_t5), {})
    R.check(row.get("kind") == "refresh" and row.get("rotated") == 1,
            "S6 refresh was transparent, and the old T5 is now rotated (dead) at Jira", str(row))

    # ---- S10: verify mode, alice approves while logged in to Jira as bob
    psql("identity", f"delete from token_vault where user_id like '{alice.user_id_like()}'")
    alice.b.get(f"{JIRA}/logout")
    res = connect(alice, m, jira_user="bob")
    page = html.unescape(res["text"])
    R.check("wasn't connected" in page and "not the one expected for you" in page,
            "S10 portal says the approving Jira account isn't the expected one", page[-200:])
    mm = [e for e in ledger(since) if e["event"] == "binding.downstream_mismatch"]
    R.check(mm and mm[-1].get("expected") == "alice" and mm[-1].get("actual") == "bob",
            "S10 ledger binding.downstream_mismatch expected=alice actual=bob")
    R.check(psql("identity", f"select count(*) from token_vault where user_id like '{alice.user_id_like()}'") == "0",
            "S10 nothing stored for alice")
    alice.b.get(f"{JIRA}/logout")
    res = connect(alice, m)
    R.check("Jira connected" in res["text"], "S10 then approving as Jira-alice works")
    R.check(psql("identity", f"select downstream_user from token_vault where user_id like '{alice.user_id_like()}'")
            == "alice", "vault row records downstream_user=alice (verified)")

    # ---- S16: step-up to WRITE denied at Jira → READ grant untouched
    res = connect(alice, m, "jira___add_comment", {"key": "ALPHA-2", "body": "denied?"}, decision="deny")
    R.check("wasn't connected" in html.unescape(res["text"]) and "access_denied" in res["text"],
            "S16 WRITE consent denied → portal 'not connected (access_denied)'")
    R.check(psql("identity", f"select scopes from token_vault where user_id like '{alice.user_id_like()}'") == "{READ}",
            "S16 vault still holds the READ grant")
    R.check(keys(m.call("jira___search_issues")) == ["ALPHA-1", "ALPHA-2", "ALPHA-3"], "S16 READ tools still work")

    # ---- S17: disable alice in Keycloak
    off = Person("alice", scope="mcp:tools offline_access")  # Claude Code asks for offline_access
    R.check(off.tok.get("refresh_token") and claims(off.tok["refresh_token"]).get("typ") == "Offline",
            "S17 setup: an offline refresh token, as Claude Code gets")
    mo = off.mcp()
    R.check(mo.call("gateway___whoami").get("data", {}).get("claims", {}).get("preferred_username") == "alice",
            "S17 before: whoami works")
    kc = kc_admin()
    uid = kc.get("/users", params={"username": "alice", "exact": "true"}).json()[0]["id"]
    kc.put(f"/users/{uid}", json={"enabled": False}).raise_for_status()
    try:
        r = mo.call("gateway___whoami")
        R.check("error" not in r and not r.get("isError"),
                "S17 GAP: disabled user's T1 still accepted until exp (local JWT validation, introspection off)")
        rr = httpx.post(f"{ISSUER}/protocol/openid-connect/token", verify=CA, data={
            "grant_type": "refresh_token", "client_id": off.reg["client_id"], "refresh_token": off.tok["refresh_token"]})
        R.check(rr.status_code == 400, "S17 the offline refresh token no longer works for a disabled user",
                f"{rr.status_code} {rr.text[:80]}")
        gateway_env(GATEWAY_INTROSPECT="true")
        r2 = McpSession(off.t1, {}, "phase5-introspect")
        R.check(r2.init_status == 401, "S17 introspection on → the same T1 is refused (401)", str(r2.init_status))
        ev = ledger(since)
        R.check(any(e["event"] == "inbound.introspected" and e.get("active") is False for e in ev),
                "S17 ledger inbound.introspected active=false")
        R.check(psql("identity", f"select count(*) from token_vault where user_id like '{alice.user_id_like()}'") == "1",
                "S17 note: the vault still holds the disabled user's Jira tokens (identity has no IdP lifecycle hook)")
    finally:
        kc.put(f"/users/{uid}", json={"enabled": True}).raise_for_status()
        gateway_env(GATEWAY_INTROSPECT="")
    fresh = Person("alice")
    R.check(fresh.mcp().init_status == 200, "S17 after re-enabling: alice can sign in and connect again")

    # ---- PKCE enforced for every client (incl. DCR-registered ones)
    b = new_browser()
    reg = dcr_register(b, f"{ISSUER}/clients-registrations/openid-connect", "phase5-nopkce")
    r = b.get(f"{ISSUER}/protocol/openid-connect/auth", params={"response_type": "code", "client_id": reg["client_id"],
                                                                "redirect_uri": LOOPBACK, "scope": "mcp:tools",
                                                                "state": secrets.token_hex(8)})
    q = parse_qs(urlparse(r.headers.get("location", "")).query)
    R.check(r.is_redirect and q.get("error") == ["invalid_request"],
            "PKCE: auth request without code_challenge → invalid_request", f"{r.status_code} {q}")
    dcr_delete(b, reg)

    for p in (alice, off, fresh):
        dcr_delete(p.b, p.reg)
    psql("identity", "delete from token_vault")



if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        R.check(False, "unexpected error", repr(e))
    finally:
        sys.exit(R.report())
