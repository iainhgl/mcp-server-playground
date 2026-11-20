# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 6 exit criteria (SPEC §10, D4): Confluence through the same gateway / identity / vault path.

  - confluence___* tools are listed next to jira___*
  - a Jira grant does NOT cover Confluence: a separate app link means a separate consent and vault row
  - per-user spaces: alice → ENG, bob → OPS, carol.w → none (an account with no spaces)
  - a page you can't see → 404 tool error (Confluence doesn't reveal existence)
  - verify mode (§5.2) also guards Confluence (approve as the wrong Confluence user → rejected)
  - disconnecting Confluence in the portal leaves Jira connected
  - Confluence only ever sees Confluence tokens (no T1, no Jira T4)
  - MCP 2026-07-28 clients get the Confluence consent as InputRequiredResult key `confluence_consent`
"""

import html
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime

import httpx
from _mcp import McpSession
from _oauth import CA, ISSUER, Results, browse, browser_authorize, claims, dcr_delete, dcr_register, fp, new_browser

PORTAL, JIRA, CONF = "https://portal.localtest.me", "https://jira.localtest.me", "https://confluence.localtest.me"
STUB_ADMIN = {"X-Stub-Admin": os.environ["STUB_ADMIN_TOKEN"]}
JIRA_LINK = re.compile(r"https://jira\.localtest\.me/rest/oauth2/latest/authorize\?\S+")
CONF_LINK = re.compile(r"https://confluence\.localtest\.me/rest/oauth2/latest/authorize\?\S+")
R = Results()


def psql(db: str, sql: str) -> str:
    return subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", db, "-At",
                           "-c", sql], check=True, capture_output=True, text=True).stdout.strip()


def ledger(since: str) -> list[dict]:
    rows = psql("ledger", f"select data from events where ts >= '{since}' order by ts, id")
    return [json.loads(x) for x in rows.splitlines() if x]


class Person:
    def __init__(self, name: str, atlassian_user: str | None = None):
        self.name, self.au, self.b = name, atlassian_user or name, new_browser()
        self.reg = dcr_register(self.b, f"{ISSUER}/clients-registrations/openid-connect", f"phase6-{name}")
        self.t1 = browser_authorize(self.b, self.reg["client_id"], "mcp:tools", user=name)["access_token"]
        self.m = McpSession(self.t1, {}, f"phase6-{name}")

    def like(self) -> str:
        return f"%|{claims(self.t1)['sub']}"

    def providers(self) -> list[str]:
        return psql("identity", f"select provider_name from token_vault where user_id like '{self.like()}' "
                                "order by 1").split()

    def consent(self, text: str, pattern: re.Pattern, as_user: str | None = None) -> str:
        link = pattern.search(text or "")
        assert link, f"no consent link in: {text[:120]}"
        return html.unescape(browse(self.b, link.group(0), self.name, as_user or self.au)["text"])


def titles(res: dict) -> list[str]:
    return sorted(p["title"] for p in (res.get("data") or {}).get("pages", []))


def main() -> None:
    for host in (JIRA, CONF):
        httpx.delete(f"{host}/_stub/faults", headers=STUB_ADMIN, verify=CA)
    psql("identity", "delete from token_vault")
    since = datetime.now(UTC).isoformat()
    alice, bob, carol = Person("alice"), Person("bob"), Person("carol", "carol.w")

    tools = {t["name"] for t in alice.m._msg(alice.m._post("tools/list"))["result"]["tools"]}
    R.check({"confluence___search", "confluence___get_page", "jira___search_issues"} <= tools,
            "tools/list has confluence___search, confluence___get_page next to jira___*")

    # ---- Jira first, then Confluence needs its OWN consent
    page = alice.consent(alice.m.call("jira___search_issues")["text"], JIRA_LINK)
    R.check("Jira connected" in page, "alice connects Jira")
    first = alice.m.call("confluence___search")
    R.check(first.get("isError") and CONF_LINK.search(first["text"]) and "Confluence access" in first["text"],
            "Jira grant does NOT cover Confluence → separate Confluence consent link")

    # ---- verify mode on Confluence: approve as the wrong Confluence account
    page = alice.consent(first["text"], CONF_LINK, as_user="bob")
    R.check("not the one expected for you" in page, "verify mode: alice approving as Confluence-bob → rejected")
    R.check(alice.providers() == ["jira-dc"], "…and nothing stored for Confluence")
    alice.b.get(f"{CONF}/logout")

    page = alice.consent(alice.m.call("confluence___search")["text"], CONF_LINK)
    R.check("Confluence connected" in page, "alice connects Confluence (portal names the product)")
    R.check(alice.providers() == ["confluence-dc", "jira-dc"], "alice has two vault rows: confluence-dc + jira-dc")
    res = alice.m.call("confluence___search")
    R.check(titles(res) == ["Architecture overview", "Onboarding checklist", "Token handling standards"],
            "alice → ENG pages only", str(titles(res)))
    one = alice.m.call("confluence___get_page", {"page_id": "65601"})
    R.check(not one.get("isError") and "MCP gateway" in one["data"]["body"], "alice get_page ENG → body")
    hid = alice.m.call("confluence___get_page", {"page_id": "65701"})
    R.check(hid.get("isError") and "404" in hid["text"] and "No content found" in hid["text"],
            "alice get_page OPS → 404 'No content found' (existence not revealed)")
    R.check(not alice.m.call("confluence___search", {"cql": "space = OPS"}).get("data", {}).get("pages"),
            "alice CQL 'space = OPS' → no results")

    # ---- bob and carol
    bob.consent(bob.m.call("confluence___search")["text"], CONF_LINK)
    R.check(titles(bob.m.call("confluence___search")) == ["On-call runbook", "OpenBao unseal procedure"],
            "bob → OPS pages only")
    carol.consent(carol.m.call("confluence___search")["text"], CONF_LINK)
    rc = carol.m.call("confluence___search")
    R.check(not rc.get("isError") and rc["data"]["total"] == 0, "carol.w (account, no spaces) → clean empty result")

    # ---- portal: both listed, disconnect Confluence only
    conns = html.unescape(alice.b.get(f"{PORTAL}/connections").text)
    R.check(conns.count("Connected</td>") == 2, "portal Connected apps lists jira-dc and confluence-dc as Connected")
    alice.b.post(f"{PORTAL}/connections/disconnect", data={"provider": "confluence-dc"})
    R.check(alice.providers() == ["jira-dc"], "Disconnect Confluence → only the Confluence row is forgotten")
    R.check(CONF_LINK.search(alice.m.call("confluence___search").get("text", "")) is not None,
            "next Confluence call → consent link again")
    R.check(not alice.m.call("jira___search_issues").get("isError"), "Jira still works")

    # ---- 2026-07-28 client: Confluence consent key
    m26 = McpSession(alice.t1, {"elicitation": {"url": {}}}, "phase6-2026", protocol="2026-07-28")
    ir = m26.call("confluence___search").get("input_required") or {}
    R.check("confluence_consent" in (ir.get("inputRequests") or {}),
            "2026-07-28: Confluence consent arrives as InputRequiredResult key confluence_consent")

    # ---- Confluence only sees Confluence tokens
    ev = ledger(since)
    conf_fps = {e.get("fp") for e in ev if e["service"] == "confluence-stub" and e["event"].startswith("api.")}
    jira_fps = {e.get("fp") for e in ev if e["service"] == "jira-stub" and e["event"].startswith("api.")}
    t1_fps = {fp(p.t1) for p in (alice, bob, carol)}
    R.check(conf_fps and not (conf_fps & (t1_fps | jira_fps)), "Confluence never saw a T1 or a Jira token")
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "confluence"], check=False,
                          capture_output=True, text=True).stdout
    R.check(not any(p.t1 in logs for p in (alice, bob, carol)), "no raw T1 in Confluence logs")

    for p in (alice, bob, carol):
        dcr_delete(p.b, p.reg)
    psql("identity", "delete from token_vault")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        R.check(False, "unexpected error", repr(e))
    finally:
        sys.exit(R.report())
