# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 2 exit criteria (SPEC §10): the Jira DC stub behaves like the real thing,
as far as auth is concerned.

  Manual-style auth code + PKCE through Jira's own login and consent pages → T4/T5
  → REST v2 filtered per user. Plus rotation, failure modes, revocation and PATs,
  and the stub rejecting an IdP token (stub side of S15). Raw tokens are never printed.
"""

import base64
import hashlib
import os
import secrets
import subprocess
import sys
import time
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from _oauth import CA, Results, _Forms, browser_authorize, dcr_delete, dcr_register, fp, new_browser

JIRA = "https://jira.localtest.me"
CLIENT_ID = os.environ["JIRA_OAUTH_CLIENT_ID"]
CLIENT_SECRET = os.environ["JIRA_OAUTH_CLIENT_SECRET"]
REDIRECT = "https://identity.localtest.me/identities/oauth2/callback"
ADMIN = {"X-Stub-Admin": os.environ["STUB_ADMIN_TOKEN"]}
R = Results()
seen_tokens: list[str] = []


def jira_authorize(http: httpx.Client, user: str, scope: str = "READ", *, decision: str = "allow",
                   pkce: bool = True) -> dict:
    """Drive Jira's login + consent like a browser. Returns {'code', 'verifier'} or {'error'}."""
    verifier = secrets.token_urlsafe(48)
    params = {"client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code", "scope": scope,
              "state": secrets.token_urlsafe(12)}
    if pkce:
        params |= {"code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                   .rstrip(b"=").decode(), "code_challenge_method": "S256"}
    r = http.get(f"{JIRA}/rest/oauth2/latest/authorize", params=params)
    for _ in range(8):
        while r.is_redirect:
            loc = r.headers["location"]
            if loc.startswith(REDIRECT):
                q = {k: v[0] for k, v in parse_qs(urlparse(loc).query).items()}
                assert q.get("state") == params["state"], "state mismatch"
                return q | {"verifier": verifier}
            r = http.get(urljoin(str(r.url), loc))
        f = _Forms()
        f.feed(r.text)
        if r.status_code == 401 and "login-form" in r.text:
            return {"error": "login_failed"}
        if not f.forms:
            return {"error": f"no form (HTTP {r.status_code})"}
        form = f.forms[0]
        data = {k: v for k, v in form["fields"].items() if k not in ("decision", "login")}
        if "os_username" in form["fields"]:
            data |= {"os_username": user, "os_password": os.environ["SEED_USER_PASSWORD"]}
        if "decision" in form["fields"]:
            data["decision"] = decision
        r = http.post(urljoin(str(r.url), form["action"]), data=data)
    return {"error": "flow did not complete"}


def token(data: dict, auth: tuple[str, str] | None = None) -> httpx.Response:
    if auth is None:
        data = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET} | data
    return httpx.post(f"{JIRA}/rest/oauth2/latest/token", data=data, auth=auth, verify=CA)


def exchange(grant: dict) -> dict:
    r = token({"grant_type": "authorization_code", "code": grant["code"], "redirect_uri": REDIRECT,
               "code_verifier": grant["verifier"]})
    r.raise_for_status()
    t = r.json()
    seen_tokens.extend([t["access_token"], t["refresh_token"]])
    return t


def api(tok: str, path: str, method: str = "GET", **kw) -> httpx.Response:
    return httpx.request(method, f"{JIRA}{path}", headers={"Authorization": f"Bearer {tok}"}, verify=CA, **kw)


def keys(r: httpx.Response) -> list[str]:
    return sorted(i["key"] for i in r.json().get("issues", []))


def main() -> None:
    httpx.delete(f"{JIRA}/_stub/faults", headers=ADMIN, verify=CA)

    # --- what Jira DC does not offer
    r = httpx.get(f"{JIRA}/.well-known/oauth-authorization-server", verify=CA)
    R.check(r.status_code == 404, "no OAuth discovery document (as in DC)", str(r.status_code))
    b = new_browser()
    r = b.get(f"{JIRA}/rest/oauth2/latest/authorize", params={"client_id": "nope", "redirect_uri": REDIRECT,
                                                               "response_type": "code", "scope": "READ"})
    R.check(r.status_code == 400 and not r.is_redirect, "unknown client → error page, no redirect")
    r = b.get(f"{JIRA}/rest/oauth2/latest/authorize", params={"client_id": CLIENT_ID, "response_type": "code",
                                                               "redirect_uri": "https://evil.example/cb", "scope": "READ"})
    R.check(r.status_code == 400 and not r.is_redirect, "unregistered redirect_uri → error page, no redirect")

    # --- alice: login + consent + PKCE → T4/T5
    alice = new_browser()
    g = jira_authorize(alice, "alice")
    R.check("code" in g, "alice: Jira login + consent → authorization code", str(g.get("error")))
    r = token({"grant_type": "authorization_code", "code": g["code"], "redirect_uri": REDIRECT,
               "code_verifier": g["verifier"]})
    t = r.json()
    seen_tokens.extend([t.get("access_token", ""), t.get("refresh_token", "")])
    R.check(r.status_code == 200 and t.get("token_type") == "bearer" and t.get("refresh_token"),
            "code + PKCE verifier + client secret → T4 + T5", r.text[:100])
    R.check(t.get("expires_in") == 7200, "access token lifetime = DC default 7200 s", str(t.get("expires_in")))
    R.check(r.headers.get("cache-control") == "no-store", "token response is Cache-Control: no-store")
    print(f"\n  alice T4 fp={fp(t['access_token'])}  T5 fp={fp(t['refresh_token'])}  scope={t.get('scope')}")
    r = token({"grant_type": "authorization_code", "code": g["code"], "redirect_uri": REDIRECT,
               "code_verifier": g["verifier"]})
    R.check(r.status_code == 400 and r.json()["error"] == "invalid_grant", "authorization code is single-use")

    a4 = t["access_token"]
    me = api(a4, "/rest/api/2/myself").json()
    R.check(me.get("name") == "alice" and me.get("key") == "JIRAUSER10100", "/myself → alice")
    R.check(keys(api(a4, "/rest/api/2/search")) == ["ALPHA-1", "ALPHA-2", "ALPHA-3"],
            "alice /search → ALPHA issues only", str(keys(api(a4, "/rest/api/2/search"))))
    r = api(a4, "/rest/api/2/search", params={"jql": "project = BETA"})
    R.check(r.status_code == 400 and "does not exist" in r.text, "alice JQL on BETA → 'does not exist' (DC hides it)")
    R.check(api(a4, "/rest/api/2/issue/BETA-1").status_code == 404, "alice GET BETA-1 → 404")
    iss = api(a4, "/rest/api/2/issue/ALPHA-1").json()
    R.check(iss["fields"]["comment"]["total"] >= 1, "alice GET ALPHA-1 → issue with comments")
    r = api(a4, "/rest/api/2/search", method="POST", json={"jql": "assignee = currentUser() AND status = Done"})
    R.check(keys(r) == ["ALPHA-3"], "POST /search with JQL (assignee = currentUser() AND status)")
    r = api(a4, "/rest/api/2/issue/ALPHA-1/comment", method="POST", json={"body": "hi"})
    R.check(r.status_code == 403, "READ token cannot comment → 403", str(r.status_code))

    # --- token endpoint failure modes
    g2 = jira_authorize(alice, "alice")  # SSO: no login page this time, just consent
    r = token({"grant_type": "authorization_code", "code": g2["code"], "redirect_uri": REDIRECT,
               "code_verifier": "wrong-verifier"})
    R.check(r.status_code == 400 and r.json()["error"] == "invalid_grant", "wrong PKCE verifier → invalid_grant")
    g3 = jira_authorize(alice, "alice")
    r = token({"grant_type": "authorization_code", "code": g3["code"], "redirect_uri": REDIRECT,
               "code_verifier": g3["verifier"], "client_secret": "wrong", "client_id": CLIENT_ID})
    R.check(r.status_code == 401 and r.json()["error"] == "invalid_client", "wrong client secret → 401 invalid_client")
    r = token({"grant_type": "authorization_code", "code": g3["code"], "redirect_uri": REDIRECT,
               "code_verifier": g3["verifier"]}, auth=(CLIENT_ID, CLIENT_SECRET))
    R.check(r.status_code == 200, "client_secret_basic also accepted")
    seen_tokens.extend([r.json()["access_token"], r.json()["refresh_token"]])
    gd = jira_authorize(alice, "alice", decision="deny")
    R.check(gd.get("error") == "access_denied", "user denies consent → access_denied redirect")

    # --- WRITE scope (step-up) → comment
    gw = jira_authorize(alice, "alice", "WRITE")
    tw = exchange(gw)
    r = api(tw["access_token"], "/rest/api/2/issue/ALPHA-2/comment", method="POST", json={"body": "From the playground"})
    R.check(r.status_code == 201 and r.json()["author"]["name"] == "alice", "WRITE token comments as alice → 201")

    # --- refresh rotation
    r = token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"]})
    t2 = r.json()
    seen_tokens.extend([t2.get("access_token", ""), t2.get("refresh_token", "")])
    R.check(r.status_code == 200 and t2["refresh_token"] != t["refresh_token"], "refresh → new T4 + new T5 (rotation)")
    r = token({"grant_type": "refresh_token", "refresh_token": t["refresh_token"]})
    R.check(r.status_code == 400 and r.json()["error"] == "invalid_grant", "old T5 reused → invalid_grant")
    R.check(api(t2["access_token"], "/rest/api/2/myself").status_code == 200, "new T4 works")
    R.check(api(a4, "/rest/api/2/myself").status_code == 200, "old T4 still valid until it expires")

    # --- other users
    tb = exchange(jira_authorize(new_browser(), "bob"))
    R.check(keys(api(tb["access_token"], "/rest/api/2/search")) == ["BETA-1", "BETA-2", "BETA-3"], "bob → BETA only")
    tc = exchange(jira_authorize(new_browser(), "carol.w"))
    R.check(len(keys(api(tc["access_token"], "/rest/api/2/search"))) == 6, "carol.w → ALPHA + BETA")
    R.check(jira_authorize(new_browser(), "dave").get("error") == "login_failed", "dave has no Jira account → login fails")

    # --- fault injection
    httpx.post(f"{JIRA}/_stub/faults", headers=ADMIN, json={"access_ttl": 2}, verify=CA)
    ts = exchange(jira_authorize(alice, "alice"))
    R.check(ts["expires_in"] == 2, "fault access_ttl=2 applied to new tokens")
    time.sleep(3)
    r = api(ts["access_token"], "/rest/api/2/myself")
    R.check(r.status_code == 401 and "expired" in r.text, "expired T4 → 401", r.text[:80])
    httpx.post(f"{JIRA}/_stub/faults", headers=ADMIN, json={"force_invalid_grant": True}, verify=CA)
    r = token({"grant_type": "refresh_token", "refresh_token": ts["refresh_token"]})
    R.check(r.status_code == 400 and r.json()["error"] == "invalid_grant", "fault force_invalid_grant → refresh fails")
    httpx.delete(f"{JIRA}/_stub/faults", headers=ADMIN, verify=CA)

    # --- user revokes the app in Jira (S13 stub side)
    page = alice.get(f"{JIRA}/secure/ViewProfile.jspa")
    f = _Forms()
    f.feed(page.text)
    revokes = [x for x in f.forms if "revoke_grant" in x["fields"]]
    for x in revokes:
        alice.post(urljoin(str(page.url), x["action"]), data=x["fields"])
    R.check(len(revokes) >= 1, f"alice revokes {len(revokes)} grant(s) on her profile page")
    r = api(t2["access_token"], "/rest/api/2/myself")
    R.check(r.status_code == 401 and "revoked" in r.text, "revoked grant → T4 401")
    r = token({"grant_type": "refresh_token", "refresh_token": t2["refresh_token"]})
    R.check(r.status_code == 400 and r.json()["error"] == "invalid_grant", "revoked grant → refresh invalid_grant")

    # --- personal access token (contrast: no OAuth, the user's full rights)
    f = _Forms()
    f.feed(alice.get(f"{JIRA}/secure/ViewProfile.jspa").text)
    form = next(x for x in f.forms if "pat_name" in x["fields"])
    page = alice.post(f"{JIRA}{form['action']}", data=form["fields"] | {"pat_name": "phase2"})
    pat = page.text.split('id="new-pat">')[1].split("<")[0]
    seen_tokens.append(pat)
    R.check(api(pat, "/rest/api/2/myself").json().get("name") == "alice", "PAT works as Bearer (DC style)")

    # --- S15, stub side: an IdP token is not a Jira token
    kc = new_browser()
    reg = dcr_register(kc, "https://idp.localtest.me/realms/playground/clients-registrations/openid-connect", "phase2")
    t1 = browser_authorize(kc, reg["client_id"], "mcp:tools")["access_token"]
    seen_tokens.append(t1)
    r = api(t1, "/rest/api/2/myself")
    R.check(r.status_code == 401, "Keycloak T1 sent to Jira → 401 (no passthrough path)", str(r.status_code))
    dcr_delete(kc, reg)

    # --- invariant 6 for the stub
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "jira"], check=False,
                          capture_output=True, text=True).stdout
    leaked = [fp(x) for x in seen_tokens if x and x in logs]
    R.check(not leaked, f"no raw token in stub logs ({len(seen_tokens)} tokens checked)", str(leaked))
    events = {line.split('"event": "')[1].split('"')[0] for line in logs.splitlines() if line.startswith("LEDGER ")}
    print(f"  stub ledger event types: {', '.join(sorted(events))}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        R.check(False, "unexpected error", repr(e))
    finally:
        sys.exit(R.report())
