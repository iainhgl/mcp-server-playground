# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 4 exit criteria (SPEC §10): S3, S5, S8, S15, S18 end to end through the real gateway + portal.
(S4 is the manual Claude Code run.) Also checks: URL elicitation vs isError signalling, S12 (dave),
step-up to WRITE (S16 preview), revocation in Jira through the gateway (C6), the ledger viewer,
mitmweb labels, and invariant 6 across every service.

Each user has ONE scripted browser (a cookie jar shared across Keycloak, Jira and the portal),
as a real person would. The MCP client is raw JSON-RPC over Streamable HTTP.
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime

import httpx
from _mcp import McpSession
from _oauth import CA, ISSUER, Results, browse, browser_authorize, claims, dcr_delete, dcr_register, fp, new_browser

PORTAL = "https://portal.localtest.me"
JIRA = "https://jira.localtest.me"
STUB_ADMIN = {"X-Stub-Admin": os.environ["STUB_ADMIN_TOKEN"]}
R = Results()
raw: list[str] = []
LINK = re.compile(r"https://jira\.localtest\.me/rest/oauth2/latest/authorize\?\S+")


def set_signal(mode: str) -> None:
    """Recreate the gateway with GATEWAY_CONSENT_SIGNAL=mode ('' = gateway.yaml) and wait until healthy."""
    subprocess.run(["docker", "compose", "up", "-d", "--wait", "gateway"], check=True, capture_output=True,
                   env=os.environ | {"GATEWAY_CONSENT_SIGNAL": mode})


def psql(db: str, sql: str) -> str:
    return subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", db, "-At",
                           "-c", sql], check=True, capture_output=True, text=True).stdout.strip()


def ledger(since: str) -> list[dict]:
    rows = psql("ledger", f"select data from events where ts >= '{since}' order by ts, id")
    return [json.loads(x) for x in rows.splitlines() if x]


class Person:
    def __init__(self, name: str, jira_user: str | None = None):
        self.name, self.jira_user, self.b = name, jira_user or name, new_browser()
        self.reg = dcr_register(self.b, f"{ISSUER}/clients-registrations/openid-connect", f"phase4-{name}")
        tok = browser_authorize(self.b, self.reg["client_id"], "mcp:tools", user=name)
        self.t1 = tok["access_token"]
        raw.append(self.t1)

    def mcp(self, url_elicitation: bool = False) -> McpSession:
        caps = {"elicitation": {"url": {}}} if url_elicitation else {}
        return McpSession(self.t1, caps, f"phase4-{self.name}")

    def consent(self, link: str) -> dict:
        return browse(self.b, link, self.name, self.jira_user)


def keys(res: dict) -> list[str]:
    return sorted(i["key"] for i in (res.get("data") or {}).get("issues", []))


def main() -> None:
    httpx.delete(f"{JIRA}/_stub/faults", headers=STUB_ADMIN, verify=CA)
    psql("identity", "delete from token_vault")
    since = datetime.now(UTC).isoformat()
    alice, bob, carol, dave = Person("alice"), Person("bob"), Person("carol", "carol.w"), Person("dave")

    # ---- S3: first Jira call → consent link (isError, client without URL elicitation)
    m = alice.mcp()
    first = m.call("jira___search_issues", {"jql": ""})
    link = LINK.search(first.get("text", ""))
    R.check(first.get("isError") and link is not None, "S3 first call → isError tool result with consent link")
    print(f"\n  consent message: {first.get('text', '')[:110]}…")
    res = alice.consent(link.group(0))
    R.check("Jira connected" in res["text"], "S3 browser: Jira login + consent → identity → portal → 'Jira connected'",
            res.get("error") or res["url"])
    print(f"  pages the user actually saw: {res['prompts']}")
    R.check(res["prompts"] == ["login@jira.localtest.me", "consent@jira.localtest.me"],
            "H3 silent: no second IdP login at the portal (SSO cookie from H1)", str(res["prompts"]))
    again = m.call("jira___search_issues", {"jql": ""})
    R.check(not again.get("isError") and keys(again) == ["ALPHA-1", "ALPHA-2", "ALPHA-3"], "S3 retry → alice's ALPHA issues")
    me = m.call("jira___get_myself")
    R.check((me.get("data") or {}).get("name") == "alice", "jira___get_myself → alice")

    # ---- S5: subsequent calls, no consent
    one = m.call("jira___get_issue", {"key": "ALPHA-1"})
    R.check(not one.get("isError") and one["data"]["comments"], "S5 get_issue ALPHA-1 (vault hit, no consent)")
    hidden = m.call("jira___get_issue", {"key": "BETA-1"})
    R.check(hidden.get("isError") and "404" in hidden["text"] and "do not have permission" in hidden["text"],
            "alice get_issue BETA-1 → 404 tool error (doesn't say whether it exists)")
    jql = m.call("jira___search_issues", {"jql": "project = BETA"})
    R.check(jql.get("isError") and "does not exist" in jql["text"], "alice JQL on BETA → 'does not exist'")

    # ---- step-up: WRITE (S16 preview)
    up = m.call("jira___add_comment", {"key": "ALPHA-2", "body": "via MCP gateway"})
    R.check(up.get("isError") and "WRITE" in up["text"] and LINK.search(up["text"]),
            "add_comment with READ grant → consent link for WRITE")
    alice.consent(LINK.search(up["text"]).group(0))
    done = m.call("jira___add_comment", {"key": "ALPHA-2", "body": "via MCP gateway"})
    R.check(not done.get("isError") and done["data"]["author"] == "alice", "after WRITE consent → comment as alice")
    R.check(not m.call("jira___search_issues", {"jql": ""}).get("isError"), "READ still works with WRITE grant (no re-consent)")

    # ---- URL elicitation (-32042) + S8: bob, separate consent, BETA only
    mb = bob.mcp(url_elicitation=True)
    inbox = mb.listen()  # standalone GET stream: where notifications/elicitation/complete arrives
    time.sleep(1)
    e = mb.call("jira___search_issues")
    err = e.get("error") or {}
    elic = (err.get("data") or {}).get("elicitations", [{}])[0]
    R.check(err.get("code") == -32042 and elic.get("mode") == "url" and LINK.match(elic.get("url", "")),
            "client with elicitation.url → JSON-RPC -32042 URLElicitationRequired", str(err)[:120])
    R.check(LINK.search(err.get("message", "")) is not None,
            "-32042 error message also carries the link (survives a declined/dismissed prompt)")
    bob.consent(elic["url"])
    deadline = time.time() + 15
    done = []
    while time.time() < deadline and not done:
        done = [x for x in inbox if x.get("method") == "notifications/elicitation/complete"]
        time.sleep(0.5)
    R.check(bool(done) and done[0]["params"].get("elicitationId") == elic.get("elicitationId"),
            "after consent: server sent notifications/elicitation/complete with the same elicitationId",
            str(inbox)[:120])
    rb = mb.call("jira___search_issues")
    R.check(keys(rb) == ["BETA-1", "BETA-2", "BETA-3"], "S8 bob → BETA only")
    R.check(keys(m.call("jira___search_issues")) == ["ALPHA-1", "ALPHA-2", "ALPHA-3"], "S8 alice unaffected")
    R.check(psql("identity", "select count(*) from token_vault") == "2", "S8 two separate vault rows")

    # ---- S18: carol pre-connects in the portal, then her first tool call needs no consent
    pre = browse(carol.b, f"{PORTAL}/login?next=/connections", "carol")
    R.check("Connected apps" in pre["text"] and "Not connected" in pre["text"], "S18 portal Connected apps: not connected")
    con = browse(carol.b, f"{PORTAL}/connections/connect", "carol", "carol.w", method="POST",
                 data={"provider": "jira-dc"})
    R.check("Jira connected" in con["text"], "S18 Connect → Jira (as carol.w) → portal → connected", con.get("error", ""))
    page = carol.b.get(f"{PORTAL}/connections")
    R.check("Connected</td>" in page.text, "S18 Connected apps shows jira-dc connected")
    rc = carol.mcp().call("jira___search_issues")
    R.check(not rc.get("isError") and len(keys(rc)) == 6, "S18 carol's first MCP call: no consent, ALPHA+BETA")

    # ---- S12: dave has no Jira account
    md = dave.mcp()
    d1 = md.call("jira___search_issues")
    dres = dave.consent(LINK.search(d1["text"]).group(0))
    R.check(dres.get("error") == "jira login failed", "S12 dave: Jira login fails")
    d2 = md.call("jira___search_issues")
    R.check(d2.get("isError") and LINK.search(d2["text"]), "S12 dave: still a clean consent link, no crash")

    # ---- S15: Jira only ever saw T4s, never a T1
    ev = ledger(since)
    t1_fps = {fp(p.t1) for p in (alice, bob, carol, dave)}
    jira_fps = {e.get("fp") for e in ev if e["service"] == "jira-stub" and e["event"].startswith("api.")}
    gw_fps = {e.get("fp") for e in ev if e["service"] == "gateway" and e["event"] == "downstream.call"}
    R.check(jira_fps and not (jira_fps & t1_fps), "S15 no T1 fingerprint ever reached Jira")
    R.check(gw_fps <= jira_fps, "S15 every gateway downstream.call T4 matches a Jira api.call")
    services = {e["service"] for e in ev}
    R.check({"gateway", "identity", "jira-stub", "portal"} <= services, "ledger DB has events from all 4 services",
            str(services))

    # ---- mitmweb labels: gateway→Jira requests carry T4, never T1
    flows = httpx.get("http://localhost:8081/flows", headers={"Authorization": f"Bearer {os.environ['MITM_WEB_PASSWORD']}"},
                      timeout=10).json()
    to_jira_api = [f for f in flows if f["request"]["host"] == "jira.localtest.me" and "/rest/api/" in f["request"]["path"]]
    labels = {f.get("comment", "").split(":")[0] for f in to_jira_api}
    R.check(to_jira_api and labels == {"→ T4"}, "mitmweb: every proxied Jira API call is labelled → T4",
            str(labels))
    gw_to_id = [f for f in flows if f["request"]["path"].endswith("GetWorkloadAccessTokenForJWT")]
    R.check(gw_to_id and "userToken T1" in gw_to_id[-1].get("comment", "") and "T7" in gw_to_id[-1].get("comment", ""),
            "mitmweb: gateway→identity shows T7 (caller) + T1 (userToken)")

    # ---- ledger viewer (alice's portal session)
    lv = alice.b.get(f"{PORTAL}/ledger?minutes=30")
    R.check(lv.status_code == 200 and "binding.ok" in lv.text and "vault.store" in lv.text and "sequenceDiagram" in lv.text,
            "portal /ledger renders the cross-service timeline")

    # ---- C6: alice revokes the app in Jira → gateway gets 401 → fresh consent link
    httpx.post(f"{JIRA}/_stub/revoke-all", headers=STUB_ADMIN, verify=CA)
    rv = m.call("jira___search_issues")
    R.check(rv.get("isError") and LINK.search(rv["text"]), "C6 revoked in Jira → 401 → new consent link")
    ev = ledger(since)
    R.check(any(e["event"] == "downstream.unauthorized" and e.get("vault") == "PURGED" for e in ev),
            "C6 gateway reported the 401 → identity tried one refresh → invalid_grant → PURGED")
    alice_sub = claims(alice.t1)["sub"]
    R.check(psql("identity", f"select count(*) from token_vault where user_id like '%|{alice_sub}'") == "0",
            "C6 dead token no longer in the vault")
    R.check("Not connected" in alice.b.get(f"{PORTAL}/connections").text,
            "C6 portal Connected apps now shows Not connected (not a broken 'Connected')")
    t0 = datetime.now(UTC).isoformat()
    rv2 = m.call("jira___search_issues")
    after = [e for e in ledger(t0) if e["service"] in ("gateway", "identity")]
    R.check(rv2.get("isError") and LINK.search(rv2["text"]) and any(e["event"] == "vault.miss" for e in after)
            and not any(e["event"] == "downstream.call" for e in after),
            "C6 next call: vault.miss → straight to consent, no Jira call (no more 401 loop)")

    # ---- protocol 2026-07-28 (what Claude Code negotiates): InputRequiredResult + client retry.
    # alice's row was purged by C6 above, so she needs consent again.
    m26 = McpSession(alice.t1, {"elicitation": {"url": {}}}, "phase4-alice-2026", protocol="2026-07-28")
    R.check(m26.init_status == 200, "2026-07-28 client initializes")
    ir = m26.call("jira___search_issues").get("input_required") or {}
    req = (ir.get("inputRequests") or {}).get("jira_consent", {})
    url26 = (req.get("params") or {}).get("url", "")
    R.check(req.get("method") == "elicitation/create" and req["params"].get("mode") == "url" and LINK.match(url26),
            "2026-07-28: tool returns InputRequiredResult with a URL elicitation (no -32042)", str(ir)[:120])
    dec = m26.call("jira___search_issues", input_responses={"jira_consent": {"action": "decline"}})
    R.check(dec.get("isError") and LINK.search(dec.get("text", "")),
            "2026-07-28: retry after DECLINE → isError text with the link (server learns of the decline)")
    ir2 = m26.call("jira___search_issues").get("input_required") or {}
    url2 = ir2["inputRequests"]["jira_consent"]["params"]["url"]
    alice.consent(url2)
    ok26 = m26.call("jira___search_issues", input_responses={"jira_consent": {"action": "accept"}})
    R.check(not ok26.get("isError") and keys(ok26) == ["ALPHA-1", "ALPHA-2", "ALPHA-3"],
            "2026-07-28: consent, then client retry (accept) → ALPHA results", str(ok26)[:120])
    R.check(any(x["event"] == "consent.signalled" and x.get("mode") == "input_required"
                and x.get("protocol") == "2026-07-28" for x in ledger(since)),
            "ledger: consent.signalled mode=input_required protocol=2026-07-28")

    # ---- consentSignal=tool_error: even an elicitation-capable client gets the link as tool-result text
    set_signal("tool_error")
    try:
        md2 = dave.mcp(url_elicitation=True)
        te = md2.call("jira___search_issues")
        R.check("error" not in te and te.get("isError") and LINK.search(te.get("text", "")),
                "consentSignal=tool_error → isError text with the link, even with elicitation.url declared")
        R.check(any(x["event"] == "consent.signalled" and x.get("setting") == "tool_error" and x.get("mode") == "tool_error"
                    for x in ledger(since)), "ledger: consent.signalled setting=tool_error mode=tool_error")
    finally:
        set_signal("")

    # ---- invariant 6 across all services (stdout logs + ledger DB)
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "gateway", "identity", "jira", "portal"],
                          check=False, capture_output=True, text=True).stdout
    dbdump = psql("ledger", "select string_agg(data::text, ' ') from events")
    leaked = [fp(t) for t in raw if t in logs or t in dbdump]
    R.check(not leaked, f"no raw T1 in any service log or the ledger DB ({len(raw)} checked)", str(leaked))
    for p in (alice, bob, carol, dave):
        dcr_delete(p.b, p.reg)
    # Leave no dead tokens behind for manual runs (revoke-all above invalidated every Jira grant).
    psql("identity", "delete from token_vault")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        R.check(False, "unexpected error", repr(e))
    finally:
        sys.exit(R.report())
