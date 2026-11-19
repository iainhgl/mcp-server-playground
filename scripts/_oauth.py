"""Shared helpers for the phase checks: a scripted 'browser' that runs auth code + PKCE
through Keycloak's real login/consent pages, DCR, and claim decoding.
Never prints raw tokens (SPEC §3 invariant 6)."""

import base64
import hashlib
import html
import json
import os
import secrets
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

IDP = "https://idp.localtest.me"
ISSUER = f"{IDP}/realms/playground"
GATEWAY = "https://gateway.localtest.me/mcp"
LOOPBACK = "http://127.0.0.1:33418/callback"
CA = "certs/caddy-root.crt"


def fp(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def claims(jwt: str) -> dict:
    body = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def aud_list(c: dict) -> list[str]:
    a = c.get("aud", [])
    return a if isinstance(a, list) else [a]


def new_browser() -> httpx.Client:
    """A fresh cookie jar is a fresh browser (no Keycloak SSO session)."""
    return httpx.Client(verify=CA, timeout=15, follow_redirects=False)


class _Forms(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append({"action": html.unescape(a.get("action") or ""), "fields": {}})
        elif tag in ("input", "button") and self.forms and a.get("name"):
            self.forms[-1]["fields"].setdefault(a["name"], a.get("value") or "")


def dcr_register(http: httpx.Client, registration_endpoint: str, name: str, scope: str = "mcp:tools") -> dict:
    r = http.post(registration_endpoint, json={
        "client_name": name, "redirect_uris": [LOOPBACK],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none", "scope": scope,
    })
    r.raise_for_status()
    return r.json()


def dcr_delete(http: httpx.Client, reg: dict) -> int:
    return http.delete(reg["registration_client_uri"],
                       headers={"Authorization": f"Bearer {reg['registration_access_token']}"}).status_code


def browser_authorize(
    http: httpx.Client,
    client_id: str,
    scope: str,
    *,
    user: str = "alice",
    redirect_uri: str = LOOPBACK,
    client_secret: str | None = None,
    resource: str | None = GATEWAY,
) -> dict:
    """Auth code + PKCE the way a user's browser would. Returns the token response."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    params = {
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": scope, "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if resource:
        params["resource"] = resource
    r = http.get(f"{ISSUER}/protocol/openid-connect/auth", params=params)
    prompted = {"_login_prompted": False, "_consent_prompted": False}
    for _ in range(6):  # login → (consent) → redirect to the client's redirect_uri
        while r.is_redirect:
            loc = r.headers["location"]
            if loc.startswith(redirect_uri):
                q = parse_qs(urlparse(loc).query)
                if "error" in q:
                    raise RuntimeError(f"authorize error: {q}")
                assert q["state"][0] == state, "state mismatch"
                data = {"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": redirect_uri,
                        "client_id": client_id, "code_verifier": verifier}
                if resource:
                    data["resource"] = resource
                if client_secret:
                    data["client_secret"] = client_secret
                tok = httpx.post(f"{ISSUER}/protocol/openid-connect/token", verify=CA, data=data)
                tok.raise_for_status()
                return tok.json() | prompted
            r = http.get(urljoin(str(r.url), loc))
        p = _Forms()
        p.feed(r.text)
        form = next((f for f in p.forms if "login-actions" in f["action"]), None)
        if not form:
            raise RuntimeError(f"no Keycloak form on page {r.url} (status {r.status_code})")
        data = {k: v for k, v in form["fields"].items() if k not in ("accept", "cancel")}
        if "username" in form["fields"]:
            data |= {"username": user, "password": os.environ["SEED_USER_PASSWORD"]}
            prompted["_login_prompted"] = True
        if "accept" in form["fields"]:
            data["accept"] = form["fields"]["accept"] or "Yes"
            prompted["_consent_prompted"] = True
        r = http.post(urljoin(str(r.url), form["action"]), data=data)
    raise RuntimeError("authorize flow did not complete")


def follow_consent(http: httpx.Client, url: str, user: str, stop_prefix: str, decision: str = "allow") -> dict:
    """Follow a downstream (Atlassian stub) consent link the way the user's browser would: Jira login if
    needed → consent → redirect to identity's callback (followed) → stop at the first redirect starting
    with stop_prefix (the portal return URL). Returns {'location', 'login_prompted', 'hops'}."""
    out = {"location": None, "login_prompted": False, "hops": []}
    r = http.get(url)
    for _ in range(10):
        while r.is_redirect:
            loc = urljoin(str(r.url), r.headers["location"])
            out["hops"].append(loc)  # full URLs (may contain one-time codes; never print them)
            if loc.startswith(stop_prefix):
                out["location"] = loc
                return out
            r = http.get(loc)
        p = _Forms()
        p.feed(r.text)
        if not p.forms:
            out["error"] = f"stopped at {r.url} HTTP {r.status_code}"
            return out
        form = p.forms[0]
        data = {k: v for k, v in form["fields"].items() if k not in ("decision", "login")}
        if "os_username" in form["fields"]:
            if r.status_code == 401:
                out["error"] = "downstream login failed"
                return out
            data |= {"os_username": user, "os_password": os.environ["SEED_USER_PASSWORD"]}
            out["login_prompted"] = True
        if "decision" in form["fields"]:
            data["decision"] = decision
        r = http.post(urljoin(str(r.url), form["action"]), data=data)
    out["error"] = "consent flow did not complete"
    return out


def browse(http: httpx.Client, url: str, user: str, jira_user: str | None = None, method: str = "GET",
           data: dict | None = None) -> dict:
    """Be the user's browser from `url` until a page with no Keycloak/Jira form: log in at Keycloak
    (`username`) or Jira (`os_username`) when asked, and approve consent screens (`accept` / `decision`).
    Returns {'url', 'status', 'text', 'prompts': [...]}. 'prompts' lists the login pages actually shown."""
    out: dict = {"prompts": []}
    r = http.request(method, url, data=data)
    for _ in range(20):
        while r.is_redirect:
            r = http.get(urljoin(str(r.url), r.headers["location"]))
        p = _Forms()
        p.feed(r.text)
        form = next((f for f in p.forms if {"username", "os_username", "accept", "decision"} & set(f["fields"])), None)
        if form is None:
            return out | {"url": str(r.url), "status": r.status_code, "text": r.text}
        host = urlparse(str(r.url)).netloc
        fields = {k: v for k, v in form["fields"].items() if k not in ("accept", "cancel", "decision", "login")}
        if "username" in form["fields"]:
            fields |= {"username": user, "password": os.environ["SEED_USER_PASSWORD"]}
            out["prompts"].append(f"login@{host}")
        if "os_username" in form["fields"]:
            if r.status_code == 401:
                return out | {"url": str(r.url), "status": 401, "text": r.text, "error": "jira login failed"}
            fields |= {"os_username": jira_user or user, "os_password": os.environ["SEED_USER_PASSWORD"]}
            out["prompts"].append(f"login@{host}")
        if "accept" in form["fields"]:
            fields["accept"] = form["fields"]["accept"] or "Yes"
            out["prompts"].append(f"consent@{host}")
        if "decision" in form["fields"]:
            fields["decision"] = "allow"
            out["prompts"].append(f"consent@{host}")
        r = http.post(urljoin(str(r.url), form["action"]), data=fields)
    return out | {"url": str(r.url), "status": r.status_code, "text": r.text, "error": "too many steps"}


def client_credentials(client_id: str, secret: str) -> str:
    r = httpx.post(f"{ISSUER}/protocol/openid-connect/token", verify=CA,
                   data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret})
    r.raise_for_status()
    return r.json()["access_token"]


class Results:
    def __init__(self) -> None:
        self.rows: list[tuple[bool, str, str]] = []

    def check(self, ok: bool, name: str, detail: str = "") -> bool:
        self.rows.append((ok, name, detail))
        return ok

    def report(self) -> int:
        print()
        for ok, name, detail in self.rows:
            print(f"  {'✓' if ok else '✗'} {name}" + (f"  [{detail}]" if detail and not ok else ""))
        failed = sum(not ok for ok, *_ in self.rows)
        print(f"\n  {len(self.rows) - failed}/{len(self.rows)} passed")
        return 1 if failed else 0
