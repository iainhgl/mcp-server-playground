# /// script
# requires-python = ">=3.12"
# dependencies = ["httpx>=0.28"]
# ///
"""Phase 3 exit criteria (SPEC §10): scripted Flow B without the gateway, plus S9.

This script plays three parts:
  "gateway": calls identity with gateway-svc's service token (T7) + the user's T1
  "portal":  calls identity with portal-svc's service token + the user's portal token T2
  "browser": follows the consent link through Jira login/consent → identity callback → portal return URL
It checks the token vault at rest in Postgres, the row lock on refresh, AAD row binding,
purge on invalid_grant, and that no raw token reaches identity's logs.
"""

import base64
import concurrent.futures
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import httpx
from _oauth import (
    CA,
    ISSUER,
    Results,
    browser_authorize,
    client_credentials,
    dcr_delete,
    dcr_register,
    follow_consent,
    fp,
    new_browser,
)

ID = "https://identity.localtest.me/identities"
JIRA = "https://jira.localtest.me"
RETURN_URL = "https://portal.localtest.me/oauth/return"
STUB_ADMIN = {"X-Stub-Admin": os.environ["STUB_ADMIN_TOKEN"]}
R = Results()
raw_tokens: list[str] = []


def keep(t: str | None) -> str | None:
    if t:
        raw_tokens.append(t)
    return t


def call(op: str, body: dict, svc_token: str | None) -> httpx.Response:
    h = {"Authorization": f"Bearer {svc_token}"} if svc_token else {}
    return httpx.post(f"{ID}/{op}", json=body, headers=h, verify=CA, timeout=30)


def psql(sql: str) -> str:
    return subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "identity",
                           "-At", "-c", sql], check=True, capture_output=True, text=True).stdout.strip()


def ledger(service: str, since: str) -> list[dict]:
    out = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "--since", since, service], check=False,
                         capture_output=True, text=True).stdout
    return [json.loads(line[7:]) for line in out.splitlines() if line.startswith("LEDGER ")]


def jwt_claims(t: str) -> dict:
    p = t.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


class User:
    """One person: a Keycloak browser (SSO cookie), their T1 (via a DCR client like Claude Code), their T2."""

    def __init__(self, name: str):
        self.name, self.kc = name, new_browser()
        self.reg = dcr_register(self.kc, f"{ISSUER}/clients-registrations/openid-connect", f"phase3-{name}")
        self.t1 = keep(browser_authorize(self.kc, self.reg["client_id"], "mcp:tools", user=name)["access_token"])
        tok = browser_authorize(self.kc, "portal", "openid", user=name,
                                redirect_uri="https://portal.localtest.me/callback",
                                client_secret=os.environ["PORTAL_CLIENT_SECRET"], resource=None)
        self.t2 = keep(tok["access_token"])
        self.portal_login_silent = not tok["_login_prompted"]
        self.jira = new_browser()  # the same person's browser session at Jira

    def t3(self, gw: str) -> str:
        r = call("GetWorkloadAccessTokenForJWT", {"workloadName": "gateway", "userToken": self.t1}, gw)
        r.raise_for_status()
        return keep(r.json()["workloadAccessToken"])


def get_token(gw: str, t3: str, **extra) -> dict:
    r = call("GetResourceOauth2Token", {"workloadIdentityToken": t3, "resourceCredentialProviderName": "jira-dc",
                                        "scopes": ["READ"], "oauth2Flow": "USER_FEDERATION",
                                        "resourceOauth2ReturnUrl": RETURN_URL} | extra, gw)
    r.raise_for_status()
    out = r.json()
    keep(out.get("accessToken"))
    return out


def consent(user: User, auth_url: str, as_jira_user: str | None = None) -> str | None:
    """Browser leg H2: returns the session_id the portal would receive, or None."""
    res = follow_consent(user.jira, auth_url, as_jira_user or user.name, RETURN_URL)
    if not res["location"]:
        return None
    return parse_qs(urlparse(res["location"]).query).get("session_id", [None])[0]


def jira_api(tok: str, path: str) -> httpx.Response:
    return httpx.get(f"{JIRA}{path}", headers={"Authorization": f"Bearer {tok}"}, verify=CA)


def main() -> None:
    gw = keep(client_credentials("gateway-svc", os.environ["GATEWAY_SVC_CLIENT_SECRET"]))
    po = keep(client_credentials("portal-svc", os.environ["PORTAL_SVC_CLIENT_SECRET"]))
    httpx.delete(f"{JIRA}/_stub/faults", headers=STUB_ADMIN, verify=CA)
    psql("delete from token_vault")
    alice, bob = User("alice"), User("bob")
    print(f"\n  T7 gateway-svc aud={jwt_claims(gw)['aud']}  portal-svc aud={jwt_claims(po)['aud']}")
    print(f"  T2 alice aud={jwt_claims(alice.t2)['aud']}  portal login silent after T1 login: "
          f"{alice.portal_login_silent}")

    # ---- caller authentication + authorization (≈ IAM)
    R.check(call("GetWorkloadAccessTokenForJWT", {}, None).status_code == 401, "data plane without service token → 401")
    r = call("GetWorkloadAccessTokenForJWT", {"workloadName": "gateway", "userToken": alice.t1}, po)
    R.check(r.status_code == 403 and r.json()["__type"] == "AccessDeniedException",
            "portal-svc may not mint T3 from a JWT → 403")
    R.check(call("GetWorkloadAccessTokenForJWT", {}, alice.t1).status_code == 401,
            "a user token (T1) is not a service credential → 401")
    R.check(call("GetWorkloadAccessTokenForJWT", {}, alice.t2).status_code == 401,
            "a user portal token (T2) is not portal-svc → 401")
    R.check(httpx.get(f"{ID.rsplit('/', 1)[0]}/admin/vault", verify=CA).status_code == 403,
            "control/admin plane without admin key → 403")

    # ---- T3
    t3a = alice.t3(gw)
    c = jwt_claims(t3a)
    R.check(c["wl"] == "gateway" and c["sub"].endswith(jwt_claims(alice.t1)["sub"]),
            "T3 binds workload=gateway + user=iss|sub(T1)", str(c))
    print(f"  T3 alice fp={fp(t3a)} claims: wl={c['wl']} sub={c['sub']} exp-iat={c['exp'] - c['iat']}s")
    r = call("GetWorkloadAccessTokenForJWT", {"workloadName": "nope", "userToken": alice.t1}, gw)
    R.check(r.status_code == 404, "unknown workload → 404")
    h, p, s = alice.t1.split(".")
    r = call("GetWorkloadAccessTokenForJWT", {"workloadName": "gateway", "userToken": f"{h}.{p}.{s[:-4]}AAAA"}, gw)
    R.check(r.status_code == 400, "tampered userToken → 400")
    r = call("GetResourceOauth2Token", {"workloadIdentityToken": t3a, "resourceCredentialProviderName": "jira-dc",
                                        "scopes": ["READ"], "oauth2Flow": "USER_FEDERATION",
                                        "resourceOauth2ReturnUrl": "https://evil.example/return"}, gw)
    R.check(r.status_code == 400, "return URL not on the workload's allowlist → 400")

    # ---- vault miss → 3LO session (B4–B5)
    first = get_token(gw, t3a)
    R.check("authorizationUrl" in first and first["sessionUri"].startswith("urn:ietf:params:oauth:request_uri:"),
            "vault miss → authorizationUrl + sessionUri (IN_PROGRESS)")
    q = parse_qs(urlparse(first["authorizationUrl"]).query)
    R.check(q["redirect_uri"] == ["https://identity.localtest.me/identities/oauth2/callback"]
            and q["code_challenge_method"] == ["S256"], "authorizationUrl: identity callback + PKCE S256")
    ct = psql(f"select pkce_verifier_ct from oauth_sessions where session_uri = '{first['sessionUri']}'")
    R.check(ct.startswith("vault:v1:"), "T6 PKCE verifier stored encrypted by OpenBao transit")

    # ---- S9: alice's consent, completed by bob
    sid = consent(alice, first["authorizationUrl"])
    R.check(sid == first["sessionUri"], "H2 alice: Jira login + consent → callback → portal ?session_id=sessionUri")
    R.check(psql(f"select status from oauth_sessions where session_uri = '{sid}'") == "PENDING_BINDING",
            "after callback: tokens parked, session PENDING_BINDING")
    R.check("authorizationUrl" in get_token(gw, t3a), "parked tokens are NOT usable before binding")
    r = call("CompleteResourceTokenAuth", {"sessionUri": sid, "userIdentifier": {"userToken": bob.t2}}, po)
    R.check(r.status_code == 403, "S9: bob completes alice's session → 403", f"{r.status_code} {r.text[:80]}")
    r = call("CompleteResourceTokenAuth", {"sessionUri": sid, "userIdentifier": {"userToken": alice.t2}}, po)
    R.check(r.status_code == 400 and "FAILED" in r.text, "S9: hijacked session is dead, even for alice")
    R.check(psql("select count(*) from token_vault") == "0", "S9: nothing stored for anyone")
    R.check(psql(f"select pending_access_ct is null from oauth_sessions where session_uri = '{sid}'") == "t",
            "S9: parked tokens wiped")

    # ---- happy path, with a T4 that is already stale → first use refreshes (S7 under concurrency)
    httpx.post(f"{JIRA}/_stub/faults", headers=STUB_ADMIN, json={"access_ttl": 1}, verify=CA)
    nxt = get_token(gw, t3a)
    res = follow_consent(alice.jira, nxt["authorizationUrl"], "alice", RETURN_URL)
    R.check(not res["login_prompted"], "second consent: Jira session reused, no Jira login")
    sid = parse_qs(urlparse(res["location"]).query)["session_id"][0]
    httpx.delete(f"{JIRA}/_stub/faults", headers=STUB_ADMIN, verify=CA)
    r = call("CompleteResourceTokenAuth", {"sessionUri": sid, "userIdentifier": {"userToken": alice.t2}}, po)
    R.check(r.status_code == 200, "alice completes her own session → vault.store", r.text[:80])
    callback_url = next(h for h in res["hops"] if "/identities/oauth2/callback" in h)
    replay = alice.jira.get(callback_url)
    R.check(replay.status_code == 400 and "Already used" in replay.text,
            "replaying the callback (same code + state) → 400 Already used")

    since = datetime.now(UTC).isoformat()
    with concurrent.futures.ThreadPoolExecutor(10) as ex:
        outs = list(ex.map(lambda _: get_token(gw, t3a), range(10)))
    toks = {o.get("accessToken") for o in outs}
    refreshes = [e for e in ledger("jira", since) if e["event"] == "oauth.token_refreshed"]
    idl = ledger("identity", since)
    R.check(all(o.get("accessToken") for o in outs) and len(toks) == 1, "10 concurrent calls → same T4 for all")
    R.check(len(refreshes) == 1, "exactly ONE refresh at Jira (row lock)", f"{len(refreshes)} refreshes")
    R.check(sum(e["event"] == "vault.hit" for e in idl) == 9 and sum(e["event"] == "vault.refreshed" for e in idl) == 1,
            "identity ledger: 1 vault.refreshed + 9 vault.hit")
    a4 = toks.pop()
    R.check(jira_api(a4, "/rest/api/2/myself").json().get("name") == "alice", "vaulted T4 → Jira /myself = alice")
    keys = sorted(i["key"] for i in jira_api(a4, "/rest/api/2/search").json()["issues"])
    R.check(keys == ["ALPHA-1", "ALPHA-2", "ALPHA-3"], "vaulted T4 → alice's ALPHA issues only")

    # ---- the vault at rest
    row = psql("select left(wrapped_dek, 9), length(access_ct), encode(access_ct, 'hex'), "
               "encode(refresh_ct, 'hex'), scopes from token_vault")
    wrap, n, ahex, rhex, scopes = row.split("|")
    R.check(wrap == "vault:v1:" and int(n) > 12, "vault row: AES-GCM ciphertext + transit-wrapped DEK")
    R.check(a4.encode().hex() not in ahex + rhex, "vault row does not contain T4 in plaintext")
    adm = httpx.get(f"{ID.rsplit('/', 1)[0]}/admin/vault", headers={"X-Identity-Admin": os.environ["IDENTITY_ADMIN_TOKEN"]},
                    verify=CA).json()
    R.check(len(adm["entries"]) == 1 and "access_ct" not in adm["entries"][0], "admin view: metadata only")
    print(f"  vault row: user_id={adm['entries'][0]['user_id']} scopes={scopes} dek={wrap}… ct={n}B")

    # ---- bob: separate consent, separate row, BETA only
    t3b = bob.t3(gw)
    sid = consent(bob, get_token(gw, t3b)["authorizationUrl"])
    call("CompleteResourceTokenAuth", {"sessionUri": sid, "userIdentifier": {"userToken": bob.t2}}, po)
    b4 = get_token(gw, t3b).get("accessToken")
    bkeys = sorted(i["key"] for i in jira_api(b4, "/rest/api/2/search").json()["issues"])
    R.check(b4 and b4 != a4 and bkeys == ["BETA-1", "BETA-2", "BETA-3"], "bob: own row, own T4, BETA only")

    # ---- AAD: alice's ciphertext copied into bob's row must not decrypt as bob's
    psql("update token_vault b set access_ct = a.access_ct, refresh_ct = a.refresh_ct, wrapped_dek = a.wrapped_dek "
         f"from token_vault a where b.user_id like '%|{jwt_claims(bob.t1)['sub']}' "
         f"and a.user_id like '%|{jwt_claims(alice.t1)['sub']}'")
    out = get_token(gw, t3b)
    R.check("authorizationUrl" in out, "swapped ciphertext → AES-GCM tag fails → bob's row purged, re-consent")
    R.check(any(e["event"] == "vault.corrupt_purged" for e in ledger("identity", since)), "ledger: vault.corrupt_purged")

    # ---- revoked in Jira → refresh invalid_grant → purge → re-consent (C4)
    httpx.post(f"{JIRA}/_stub/revoke-all", headers=STUB_ADMIN, verify=CA)
    psql("update token_vault set access_expires_at = now() - interval '1 hour'")
    out = get_token(gw, t3a)
    R.check("authorizationUrl" in out and psql("select count(*) from token_vault") == "0",
            "revoked grant: refresh invalid_grant → row purged → authorizationUrl")

    # ---- forceAuthentication skips the vault
    R.check("authorizationUrl" in get_token(gw, t3a, forceAuthentication=True), "forceAuthentication → new session")

    # ---- invariant 6 for identity
    logs = subprocess.run(["docker", "compose", "logs", "--no-log-prefix", "identity"], check=False,
                          capture_output=True, text=True).stdout
    leaked = [fp(t) for t in raw_tokens if t and t in logs]
    R.check(not leaked, f"no raw token in identity logs ({len(raw_tokens)} checked: T1 T2 T3 T4 T7)", str(leaked))
    events = sorted({e["event"] for e in ledger("identity", "30m")})
    print(f"  identity ledger event types: {', '.join(events)}")

    for u in (alice, bob):
        dcr_delete(u.kc, u.reg)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        R.check(False, "unexpected error", repr(e))
    finally:
        sys.exit(R.report())
