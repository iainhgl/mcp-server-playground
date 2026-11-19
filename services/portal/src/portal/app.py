"""portal: the app that owns AgentCore's `resourceOauth2ReturnUrl` (SPEC §6.4, architecture H3 / B10–B13).

- /oauth/return?session_id=…  The user arrives here after approving Jira. We ALWAYS run a fresh
  OIDC login (silent when Keycloak already has an SSO session). Then, inside that same request, we
  call CompleteResourceTokenAuth with the fresh user token (T2), so identity can check that the
  person finishing the consent is the person who started it. T2 is never stored.
- /connections  Connected apps: list/disconnect, plus *pre-consent* ("Connect") with
                GetWorkloadAccessTokenForUserId, so users can connect Jira before using an MCP client.
- /ledger       Token-ledger timeline across services (ledger DB, read-only role).

The portal session is a signed cookie holding only {user_id, name, exp}. No tokens are in it.
It calls identity with its *service* credential (portal-svc), never with a user's token as the caller.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlencode

import psycopg
from playground_common import ledger
from playground_common.http import async_client
from playground_common.jwt_authz import AuthorizerConfig, AuthzError, MultiIssuerAuthorizer
from psycopg.rows import dict_row
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from portal import views

SERVICE = "portal"
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://portal.localtest.me")
ISSUER = os.environ["IDP_ISSUER"]
CLIENT_ID, CLIENT_SECRET = "portal", os.environ["PORTAL_CLIENT_SECRET"]
SVC_ID, SVC_SECRET = "portal-svc", os.environ["PORTAL_SVC_CLIENT_SECRET"]
IDENTITY = os.environ.get("IDENTITY_URL", "https://identity.localtest.me/identities")
WORKLOAD = os.environ.get("WORKLOAD_NAME", "gateway")
RETURN_URL = f"{PUBLIC_URL}/oauth/return"
PROVIDERS = os.environ.get("PROVIDERS", "jira-dc").split(",")
COOKIE_KEY = os.environ["PORTAL_COOKIE_KEY"].encode()
LEDGER_READ_URL = os.environ["LEDGER_READ_URL"]
SESSION_TTL = 1800

http = async_client()
users = MultiIssuerAuthorizer([AuthorizerConfig("rhsso", f"{ISSUER}/.well-known/openid-configuration", ["portal"])],
                              http)


# ------------------------------------------------------------------ signed cookies (no tokens inside)

def _sign(data: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    mac = hmac.new(COOKIE_KEY, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def _unsign(raw: str | None) -> dict | None:
    if not raw or "." not in raw:
        return None
    body, mac = raw.rsplit(".", 1)
    if not hmac.compare_digest(mac, hmac.new(COOKIE_KEY, body.encode(), hashlib.sha256).hexdigest()):
        return None
    data = json.loads(base64.urlsafe_b64decode(body))
    return data if data.get("exp", 0) > time.time() else None


def _user(request: Request) -> dict | None:
    return _unsign(request.cookies.get("portal_session"))


def _set(resp: Response, name: str, data: dict, ttl: int) -> None:
    resp.set_cookie(name, _sign(data | {"exp": time.time() + ttl}), max_age=ttl, httponly=True, secure=True,
                    samesite="lax")


# ------------------------------------------------------------------ service token + identity calls

_svc = {"tok": "", "exp": 0.0}


async def _svc_token() -> str:
    if time.time() > _svc["exp"] - 30:
        r = await http.post(f"{ISSUER}/protocol/openid-connect/token", data={
            "grant_type": "client_credentials", "client_id": SVC_ID, "client_secret": SVC_SECRET})
        r.raise_for_status()
        _svc["tok"], _svc["exp"] = r.json()["access_token"], time.time() + r.json().get("expires_in", 300)
        ledger.emit(SERVICE, "service_token.minted", token=_svc["tok"], label="T7", client_id=SVC_ID)
    return _svc["tok"]


async def _identity(op: str, body: dict) -> tuple[int, dict]:
    r = await http.post(f"{IDENTITY}/{op}", json=body, headers={"Authorization": f"Bearer {await _svc_token()}"})
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"message": r.text[:200]}


# ------------------------------------------------------------------ OIDC login (H3)

async def login(request: Request) -> Response:
    """Start auth code + PKCE. `next` is a local path, or `bind:<sessionUri>` for the consent return."""
    nxt = request.query_params.get("next", "/")
    if not nxt.startswith(("/", "bind:")):
        nxt = "/"
    verifier, state, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    resp = RedirectResponse(f"{ISSUER}/protocol/openid-connect/auth?" + urlencode({
        "client_id": CLIENT_ID, "response_type": "code", "scope": "openid", "redirect_uri": f"{PUBLIC_URL}/callback",
        "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}), 302)
    _set(resp, "portal_oidc", {"state": state, "verifier": verifier, "next": nxt}, 600)
    return resp


async def callback(request: Request) -> Response:
    pending = _unsign(request.cookies.get("portal_oidc"))
    q = request.query_params
    if not pending or q.get("state") != pending["state"]:
        return HTMLResponse(views.result(None, False, "Sign-in failed", "State mismatch. Please try again."), 400)
    if q.get("error"):
        return HTMLResponse(views.result(None, False, "Sign-in failed", q["error"]), 400)
    r = await http.post(f"{ISSUER}/protocol/openid-connect/token", data={
        "grant_type": "authorization_code", "code": q.get("code", ""), "redirect_uri": f"{PUBLIC_URL}/callback",
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code_verifier": pending["verifier"]})
    if r.is_error:
        return HTMLResponse(views.result(None, False, "Sign-in failed", "Token exchange failed."), 400)
    t2 = r.json()["access_token"]
    try:
        _, claims = await users.validate(t2)
    except AuthzError as e:
        return HTMLResponse(views.result(None, False, "Sign-in failed", e.reason), 400)
    ledger.emit(SERVICE, "user.login", token=t2, label="T2", claims=claims)
    user = {"user_id": f"{claims['iss']}|{claims['sub']}", "name": claims.get("preferred_username", claims["sub"])}

    nxt = pending["next"]
    if nxt.startswith("bind:"):
        resp = await _bind(nxt[5:], t2, user)
    else:
        resp = RedirectResponse(nxt, 302)
    _set(resp, "portal_session", user, SESSION_TTL)
    resp.delete_cookie("portal_oidc")
    return resp  # t2 goes out of scope here: never stored


# ------------------------------------------------------------------ consent return (B10–B13)

async def oauth_return(request: Request) -> Response:
    sid, err = request.query_params.get("session_id", ""), request.query_params.get("error")
    if err:
        ledger.emit(SERVICE, "consent.return_error", token=sid, label="T6", error=err)
        return HTMLResponse(views.result(_user(request), False, "Jira wasn't connected",
                                         f"The authorization didn't complete ({err}). You can try again from your "
                                         "assistant or from Connected apps."))
    ledger.emit(SERVICE, "consent.returned", token=sid, label="T6")
    # Always re-authenticate (H3) to get a fresh T2 for binding. This is silent if there's a Keycloak SSO session.
    return RedirectResponse(f"/login?{urlencode({'next': 'bind:' + sid})}", 302)


async def _bind(session_uri: str, t2: str, user: dict) -> Response:
    status, out = await _identity("CompleteResourceTokenAuth",
                                  {"sessionUri": session_uri, "userIdentifier": {"userToken": t2}})
    ledger.emit(SERVICE, "binding.requested", token=session_uri, label="T6", user=user["name"], status=status)
    if status == 200:
        return HTMLResponse(views.result(user, True, "Jira connected",
                                         "You can close this tab and ask your assistant again."))
    msg = out.get("message", "")
    if status == 403:
        msg = ("This approval was started by a different user than the one signed in here, so it was discarded. "
               "Nothing was connected.")
    return HTMLResponse(views.result(user, False, "Jira wasn't connected", msg), status)


# ------------------------------------------------------------------ connected apps (+ pre-consent)

def _origin_ok(request: Request) -> bool:
    return request.headers.get("origin") in (None, PUBLIC_URL)  # CSRF guard alongside SameSite=Lax


async def connections(request: Request) -> Response:
    user = _user(request)
    if not user:
        return RedirectResponse("/login?next=/connections", 302)
    _, out = await _identity("x-ListUserConnections", {"userId": user["user_id"]})
    return HTMLResponse(views.connections(user, out.get("connections", []), PROVIDERS))


async def connect(request: Request) -> Response:
    user = _user(request)
    if not user or not _origin_ok(request):
        return RedirectResponse("/login?next=/connections", 302)
    provider = str((await request.form()).get("provider"))
    status, w = await _identity("GetWorkloadAccessTokenForUserId", {"workloadName": WORKLOAD, "userId": user["user_id"]})
    if status != 200:
        return HTMLResponse(views.result(user, False, "Couldn't start", w.get("message", "")), 502)
    status, out = await _identity("GetResourceOauth2Token", {
        "workloadIdentityToken": w["workloadAccessToken"], "resourceCredentialProviderName": provider,
        "scopes": ["READ"], "oauth2Flow": "USER_FEDERATION", "resourceOauth2ReturnUrl": RETURN_URL})
    if status != 200:
        return HTMLResponse(views.result(user, False, "Couldn't start", out.get("message", "")), 502)
    if "accessToken" in out:  # already connected (the token itself is discarded immediately)
        return RedirectResponse("/connections", 303)
    ledger.emit(SERVICE, "preconsent.started", token=out["sessionUri"], label="T6", provider=provider)
    return RedirectResponse(out["authorizationUrl"], 303)


async def disconnect(request: Request) -> Response:
    user = _user(request)
    if not user or not _origin_ok(request):
        return RedirectResponse("/login?next=/connections", 302)
    provider = str((await request.form()).get("provider"))
    await _identity("x-DeleteUserConnection", {"userId": user["user_id"], "workloadName": WORKLOAD,
                                               "providerName": provider})
    return RedirectResponse("/connections", 303)


# ------------------------------------------------------------------ ledger viewer

async def ledger_view(request: Request) -> Response:
    user = _user(request)
    if not user:
        return RedirectResponse("/login?next=/ledger", 302)
    try:
        minutes = max(1, min(int(request.query_params.get("minutes", "15")), 24 * 60))
    except ValueError:
        minutes = 15
    q = request.query_params.get("q", "").strip()
    sql = "select ts, service, event, token_label, fp, data from events where ts > now() - make_interval(mins => %s)"
    args: list = [minutes]
    if q:
        sql += " and (event ilike %s or fp ilike %s or data::text ilike %s)"
        args += [f"%{q}%"] * 3
    sql += " order by ts, id limit 2000"
    async with await psycopg.AsyncConnection.connect(LEDGER_READ_URL, row_factory=dict_row) as conn:
        events = await (await conn.execute(sql, args)).fetchall()
    return HTMLResponse(views.ledger(user, events, minutes, q))


async def home(request: Request) -> Response:
    return HTMLResponse(views.home(_user(request)))


async def logout(_: Request) -> Response:
    resp = RedirectResponse(f"{ISSUER}/protocol/openid-connect/logout?" + urlencode(
        {"client_id": CLIENT_ID, "post_logout_redirect_uri": f"{PUBLIC_URL}/"}), 302)
    resp.delete_cookie("portal_session")
    return resp


async def healthz(_: Request) -> Response:
    return Response('{"ok":true}', media_type="application/json")


app = Starlette(routes=[
    Route("/", home), Route("/healthz", healthz),
    Route("/login", login), Route("/callback", callback), Route("/logout", logout),
    Route("/oauth/return", oauth_return),
    Route("/connections", connections),
    Route("/connections/connect", connect, methods=["POST"]),
    Route("/connections/disconnect", disconnect, methods=["POST"]),
    Route("/ledger", ledger_view),
])
