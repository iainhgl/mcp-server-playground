"""Atlassian Data Center stub (SPEC §6.5): OAuth 2.0 provider + REST subset.

It copies the DC behaviour that matters for auth:
- OAuth 2.0 provider of an *incoming application link*: /rest/oauth2/latest/authorize
  and /token. Auth code (+PKCE S256), refresh_token with rotation, client_secret_post
  or _basic, scopes READ < WRITE < ADMIN < SYSTEM_ADMIN. Opaque tokens.
  NO discovery document, introspection or token exchange.
- Bearer tokens on /rest/api/2/*: OAuth access tokens *or* Personal Access Tokens.
- Permission filtering that hides what you can't see: a project you can't browse
  "does not exist" in JQL, and an issue you can't see is 404.

Persona: PERSONA=jira (phase 2). confluence arrives in phase 6.
"""

import asyncio
import base64
import hashlib
import os
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from playground_common import ledger
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from atlassian_stub import pages, seed
from atlassian_stub.cql import CqlError, compile_cql
from atlassian_stub.jql import JqlError, compile_jql
from atlassian_stub.store import Store

PERSONA = os.environ.get("PERSONA", "jira")
PRODUCT = {"jira": "Jira", "confluence": "Confluence"}[PERSONA]
SERVICE = f"{PERSONA}-stub"
BASE_URL = os.environ.get("BASE_URL", "https://jira.localtest.me")
ADMIN_TOKEN = os.environ.get("STUB_ADMIN_TOKEN", "")
SCOPE_ORDER = ["READ", "WRITE", "ADMIN", "SYSTEM_ADMIN"]

store = Store(os.environ.get("STUB_DB", "/data/stub.db"))


# ---------------------------------------------------------------- helpers

def _now_jira() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _session(request: Request):
    return store.session(request.cookies.get("JSESSIONID"))


def _scopes_ok(requested: list[str], allowed: str) -> bool:
    cap = SCOPE_ORDER.index(allowed) if allowed in SCOPE_ORDER else -1
    return bool(requested) and all(s in SCOPE_ORDER and SCOPE_ORDER.index(s) <= cap for s in requested)


def _implies(granted: str, needed: str) -> bool:
    """DC scopes are hierarchical: WRITE implies READ (to confirm on the real instance, R4)."""
    top = max((SCOPE_ORDER.index(s) for s in granted.split() if s in SCOPE_ORDER), default=-1)
    return top >= SCOPE_ORDER.index(needed)


def _oauth_error(error: str, desc: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": desc}, status_code=status)


def _jira_error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"errorMessages": [message], "errors": {}}, status_code=status)


def _redirect_with(uri: str, params: dict[str, str]) -> RedirectResponse:
    sep = "&" if "?" in uri else "?"
    return RedirectResponse(f"{uri}{sep}{urlencode(params)}", status_code=302)


async def _latency() -> None:
    if ms := store.faults()["latency_ms"]:
        await asyncio.sleep(ms / 1000)


# ---------------------------------------------------------------- login / logout

async def login_get(request: Request) -> Response:
    return HTMLResponse(pages.login(PRODUCT, request.query_params.get("os_destination", "/")))


async def login_post(request: Request) -> Response:
    form = await request.form()
    user, pw = str(form.get("os_username", "")), str(form.get("os_password", ""))
    dest = str(form.get("os_destination", "/"))
    if not dest.startswith("/"):  # no open redirects
        dest = "/"
    if not seed.password_ok(user, pw):
        ledger.emit(SERVICE, "web.login_failed", username=user)
        return HTMLResponse(pages.login(PRODUCT, dest, "Sorry, your username and password are incorrect."),
                            status_code=401)
    sid, _ = store.new_session(user)
    ledger.emit(SERVICE, "web.login", username=user)
    resp = RedirectResponse(dest, status_code=302)
    resp.set_cookie("JSESSIONID", sid, httponly=True, secure=True, samesite="lax")
    return resp


async def logout(request: Request) -> Response:
    if sid := request.cookies.get("JSESSIONID"):
        store.end_session(sid)
    resp = RedirectResponse("/login.jsp", status_code=302)
    resp.delete_cookie("JSESSIONID")
    return resp


# ---------------------------------------------------------------- OAuth 2.0 provider

AUTHZ_PARAMS = ("client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge",
                "code_challenge_method")


async def authorize_get(request: Request) -> Response:
    q = {k: request.query_params.get(k, "") for k in AUTHZ_PARAMS}
    client = store.client(q["client_id"])
    # Invalid client or redirect_uri: show an error, never redirect (RFC 6749 §4.1.2.1).
    if client is None:
        return HTMLResponse(pages.error_page(PRODUCT, "Unknown application (client_id)."), status_code=400)
    if q["redirect_uri"] != client["redirect_uri"]:
        return HTMLResponse(pages.error_page(PRODUCT, "redirect_uri does not match the application link."),
                            status_code=400)
    if q["response_type"] != "code":
        return _redirect_with(q["redirect_uri"], {"error": "unsupported_response_type", "state": q["state"]})
    scopes = q["scope"].split()
    if not _scopes_ok(scopes, client["scope"]):
        return _redirect_with(q["redirect_uri"], {"error": "invalid_scope", "state": q["state"]})
    if q["code_challenge"] and q["code_challenge_method"] != "S256":
        return _redirect_with(q["redirect_uri"], {"error": "invalid_request", "state": q["state"],
                                                  "error_description": "only S256 PKCE is supported"})
    if client["require_pkce"] and not q["code_challenge"]:
        return _redirect_with(q["redirect_uri"], {"error": "invalid_request", "state": q["state"],
                                                  "error_description": "PKCE required"})

    sess = _session(request)
    if sess is None:
        dest = f"{request.url.path}?{request.url.query}"
        return RedirectResponse(f"/login.jsp?{urlencode({'os_destination': dest})}", status_code=302)
    ledger.emit(SERVICE, "oauth.consent_shown", client_id=q["client_id"], username=sess["username"], scope=q["scope"])
    return HTMLResponse(pages.consent(PRODUCT, sess["username"], client["name"], scopes,
                                      {**q, "atl_token": sess["xsrf"]}))


async def authorize_post(request: Request) -> Response:
    form = {k: str(v) for k, v in (await request.form()).items()}
    sess = _session(request)
    if sess is None or form.get("atl_token") != sess["xsrf"]:
        return HTMLResponse(pages.error_page(PRODUCT, "XSRF check failed. Log in and try again."), status_code=403)
    client = store.client(form.get("client_id"))
    if client is None or form.get("redirect_uri") != client["redirect_uri"]:
        return HTMLResponse(pages.error_page(PRODUCT, "Invalid application."), status_code=400)
    state, redirect_uri = form.get("state", ""), client["redirect_uri"]
    if form.get("decision") != "allow":
        ledger.emit(SERVICE, "oauth.consent_denied", client_id=client["client_id"], username=sess["username"])
        return _redirect_with(redirect_uri, {"error": "access_denied", "state": state})
    code = store.new_code(client["client_id"], sess["username"], redirect_uri, form.get("scope", ""),
                          form.get("code_challenge") or None, form.get("code_challenge_method") or None)
    ledger.emit(SERVICE, "oauth.code_issued", client_id=client["client_id"], username=sess["username"],
                scope=form.get("scope"), pkce=bool(form.get("code_challenge")))
    return _redirect_with(redirect_uri, {"code": code, "state": state})


def _client_auth(request: Request, form: dict[str, str]) -> tuple[Any, str]:
    """client_secret_post or client_secret_basic."""
    cid, secret, method = form.get("client_id"), form.get("client_secret"), "client_secret_post"
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            cid, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
            method = "client_secret_basic"
        except ValueError:
            return None, method
    client = store.client(cid)
    if client is None or not secret or hashlib.sha256(secret.encode()).hexdigest() != client["client_secret_hash"]:
        return None, method
    return client, method


async def token(request: Request) -> Response:
    await _latency()
    form = {k: str(v) for k, v in (await request.form()).items()}
    client, auth_method = _client_auth(request, form)
    if client is None:
        ledger.emit(SERVICE, "oauth.token_rejected", reason="invalid_client", client_id=form.get("client_id"))
        return _oauth_error("invalid_client", "Client authentication failed", 401)
    gt = form.get("grant_type")

    if gt == "authorization_code":
        row = store.consume_code(form.get("code", ""))
        reason = None
        if row is None:
            reason = "unknown code"
        elif row["used"]:
            reason = "code already used"
        elif row["expires_at"] < time.time():
            reason = "code expired"
        elif row["client_id"] != client["client_id"]:
            reason = "code issued to another client"
        elif form.get("redirect_uri") != row["redirect_uri"]:
            reason = "redirect_uri mismatch"
        elif row["code_challenge"]:
            verifier = form.get("code_verifier", "")
            calc = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if calc != row["code_challenge"]:
                reason = "PKCE verification failed"
        if reason:
            ledger.emit(SERVICE, "oauth.token_rejected", reason=reason, grant_type=gt, client_id=client["client_id"])
            return _oauth_error("invalid_grant", reason)
        grant_id = store.new_grant(client["client_id"], row["username"], row["scope"])
        pair = store.tx(lambda db: store.issue_pair(db, grant_id, client["client_id"], row["username"], row["scope"]))
        ledger.emit(SERVICE, "oauth.token_issued", token=pair["access_token"], label="T4", grant_type=gt,
                    username=row["username"], scope=row["scope"], expires_in=pair["expires_in"],
                    client_auth=auth_method, grant_id=grant_id)
        ledger.emit(SERVICE, "oauth.token_issued", token=pair["refresh_token"], label="T5", grant_id=grant_id)
        return JSONResponse(pair, headers={"Cache-Control": "no-store"})

    if gt == "refresh_token":
        if store.faults()["force_invalid_grant"]:
            ledger.emit(SERVICE, "oauth.token_rejected", reason="fault: force_invalid_grant", grant_type=gt)
            return _oauth_error("invalid_grant", "Refresh token is invalid")
        raw = form.get("refresh_token", "")
        status, out = store.rotate(raw, client["client_id"])
        if status != "ok":
            ledger.emit(SERVICE, "oauth.token_rejected", token=raw, label="T5", reason=f"refresh {status}",
                        grant_type=gt)
            return _oauth_error("invalid_grant", f"Refresh token is {status}")
        ledger.emit(SERVICE, "oauth.token_refreshed", token=raw, label="T5", note="old refresh token now dead (rotation)")
        ledger.emit(SERVICE, "oauth.token_issued", token=out["access_token"], label="T4", grant_type=gt,
                    expires_in=out["expires_in"])
        ledger.emit(SERVICE, "oauth.token_issued", token=out["refresh_token"], label="T5", grant_type=gt)
        return JSONResponse(out, headers={"Cache-Control": "no-store"})

    return _oauth_error("unsupported_grant_type", f"grant_type {gt!r} is not supported")


async def no_discovery(_: Request) -> Response:
    """DC publishes no OAuth/OIDC discovery document. Clients need explicit endpoints (SPEC §6.3)."""
    return Response(status_code=404)


# ---------------------------------------------------------------- bearer auth for REST

class Caller:
    def __init__(self, username: str, scope: str, kind: str):
        self.username, self.scope, self.kind = username, scope, kind


def _bearer(request: Request) -> tuple[Caller | None, Response | None]:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, _jira_error(401, "You are not authenticated. Authentication required to perform this operation.")
    raw = auth[7:].strip()
    if store.faults()["force_401"]:
        ledger.emit(SERVICE, "api.rejected", token=raw, label="T4?", reason="fault: force_401")
        return None, _jira_error(401, "OAuth 2.0 token is invalid")
    t = store.token(raw)
    if t is not None and t.kind == "access":
        reason = "revoked" if t.revoked else "expired" if t.expires_at < time.time() else None
        if reason:
            ledger.emit(SERVICE, "api.rejected", token=raw, label="T4", reason=reason, username=t.username)
            return None, _jira_error(401, f"OAuth 2.0 token is {reason}")
        return Caller(t.username, t.scope, "oauth"), None
    if (p := store.pat(raw)) is not None:
        return Caller(p["username"], "SYSTEM_ADMIN", "pat"), None  # a PAT carries the user's full permissions
    ledger.emit(SERVICE, "api.rejected", token=raw, label="T4?", reason="unknown token (not issued by this server)")
    return None, _jira_error(401, "You are not authenticated. Authentication required to perform this operation.")


def api(needed_scope: str):
    def deco(fn):
        async def handler(request: Request) -> Response:
            await _latency()
            caller, err = _bearer(request)
            if err:
                return err
            if not _implies(caller.scope, needed_scope):
                ledger.emit(SERVICE, "api.forbidden", username=caller.username, scope=caller.scope,
                            needed=needed_scope, path=request.url.path)
                return _jira_error(403, f"The OAuth 2.0 token does not have the {needed_scope} scope.")
            ledger.emit(SERVICE, "api.call", label="T4" if caller.kind == "oauth" else "PAT",
                        token=request.headers["authorization"][7:].strip(), username=caller.username,
                        method=request.method, path=request.url.path)
            return await fn(request, caller)
        return handler
    return deco


# ---------------------------------------------------------------- Jira REST v2 subset

def _user_json(name: str | None) -> dict[str, Any] | None:
    if name is None:
        return None
    u = seed.USERS[name]
    return {"self": f"{BASE_URL}/rest/api/2/user?username={u.name}", "name": u.name, "key": u.key,
            "emailAddress": u.email, "displayName": u.display_name, "active": True}


def _comments_json(issue: seed.Issue) -> list[dict[str, Any]]:
    out = [{"id": str(10000 + n), "author": _user_json(a), "body": b, "created": c, "updated": c}
           for n, (a, b, c) in enumerate(issue.comments)]
    out += [{"id": str(20000 + r["id"]), "author": _user_json(r["author"]), "body": r["body"],
             "created": r["created"], "updated": r["created"]} for r in store.comments(issue.key)]
    return out


def _issue_json(i: seed.Issue, with_comments: bool = False) -> dict[str, Any]:
    p = seed.PROJECTS[i.project]
    fields: dict[str, Any] = {
        "summary": i.summary, "description": i.description,
        "issuetype": {"name": i.issuetype}, "status": {"name": i.status},
        "project": {"id": p.id, "key": p.key, "name": p.name},
        "assignee": _user_json(i.assignee), "reporter": _user_json(i.reporter),
        "created": i.created, "updated": i.updated,
    }
    if with_comments:
        cs = _comments_json(i)
        fields["comment"] = {"startAt": 0, "maxResults": len(cs), "total": len(cs), "comments": cs}
    return {"expand": "renderedFields,names,schema,transitions,changelog", "id": i.id,
            "self": f"{BASE_URL}/rest/api/2/issue/{i.id}", "key": i.key, "fields": fields}


@api("READ")
async def myself(_: Request, caller: Caller) -> Response:
    u = _user_json(caller.username)
    return JSONResponse({**u, "timeZone": "Europe/London", "locale": "en_GB", "groups": {"size": 1, "items": []}})


@api("READ")
async def search(request: Request, caller: Caller) -> Response:
    if request.method == "POST":
        body = await request.json()
        jql, start, maxr = body.get("jql", ""), int(body.get("startAt", 0)), int(body.get("maxResults", 50))
    else:
        qp = request.query_params
        jql, start, maxr = qp.get("jql", ""), int(qp.get("startAt", 0)), int(qp.get("maxResults", 50))
    visible = seed.visible_projects(caller.username)
    try:
        pred = compile_jql(jql, caller.username, visible)
    except JqlError as e:
        return _jira_error(400, str(e))
    hits = [i for i in seed.ISSUES.values() if i.project in visible and pred(i)]
    page = hits[start:start + min(maxr, 100)]
    return JSONResponse({"expand": "schema,names", "startAt": start, "maxResults": maxr, "total": len(hits),
                         "issues": [_issue_json(i) for i in page]})


def _visible_issue(key: str, username: str) -> seed.Issue | None:
    i = seed.ISSUES.get(key.upper())
    return i if i and i.project in seed.visible_projects(username) else None


NOT_FOUND = "Issue does not exist or you do not have permission to see it."


@api("READ")
async def get_issue(request: Request, caller: Caller) -> Response:
    i = _visible_issue(request.path_params["key"], caller.username)
    return JSONResponse(_issue_json(i, with_comments=True)) if i else _jira_error(404, NOT_FOUND)


@api("READ")
async def list_comments(request: Request, caller: Caller) -> Response:
    i = _visible_issue(request.path_params["key"], caller.username)
    if not i:
        return _jira_error(404, NOT_FOUND)
    cs = _comments_json(i)
    return JSONResponse({"startAt": 0, "maxResults": len(cs), "total": len(cs), "comments": cs})


@api("WRITE")
async def add_comment(request: Request, caller: Caller) -> Response:
    i = _visible_issue(request.path_params["key"], caller.username)
    if not i:
        return _jira_error(404, NOT_FOUND)
    body = (await request.json()).get("body", "")
    if not body:
        return JSONResponse({"errorMessages": [], "errors": {"comment": "Comment body can not be empty!"}}, 400)
    created = _now_jira()
    cid = store.add_comment(i.key, caller.username, body, created)
    return JSONResponse({"id": str(20000 + cid), "author": _user_json(caller.username), "body": body,
                         "created": created, "updated": created}, status_code=201)


# ---------------------------------------------------------------- profile (authorized apps, PATs)

async def profile(request: Request) -> Response:
    sess = _session(request)
    if sess is None:
        return RedirectResponse("/login.jsp?os_destination=/secure/ViewProfile.jspa", status_code=302)
    user, new_pat = sess["username"], None
    if request.method == "POST":
        form = await request.form()
        if form.get("atl_token") != sess["xsrf"]:
            return HTMLResponse(pages.error_page(PRODUCT, "XSRF check failed.", user), status_code=403)
        if gid := form.get("revoke_grant"):
            if store.revoke_grant(int(gid), user):
                ledger.emit(SERVICE, "oauth.grant_revoked", username=user, grant_id=int(gid), by="user")
        elif name := form.get("pat_name"):
            new_pat = store.new_pat(user, str(name))
            ledger.emit(SERVICE, "pat.created", token=new_pat, label="PAT", username=user)
    return HTMLResponse(pages.profile(PRODUCT, user, sess["xsrf"], store.grants_for(user), store.pats_for(user), new_pat))


# ---------------------------------------------------------------- admin + fault injection

def _admin(request: Request) -> bool:
    return bool(ADMIN_TOKEN) and request.headers.get("x-stub-admin") == ADMIN_TOKEN


async def admin_faults(request: Request) -> Response:
    if not _admin(request):
        return Response(status_code=403)
    if request.method == "DELETE":
        store.reset_faults()
    elif request.method == "POST":
        try:
            store.set_faults(await request.json())
        except KeyError as e:
            return JSONResponse({"error": f"unknown fault {e}"}, status_code=400)
    f = store.faults()
    ledger.emit(SERVICE, "stub.faults", **{k: v for k, v in f.items() if v not in (False, 0)})
    return JSONResponse(f)


async def admin_revoke_all(request: Request) -> Response:
    if not _admin(request):
        return Response(status_code=403)
    n = store.revoke_all()
    ledger.emit(SERVICE, "oauth.grant_revoked", by="admin", count=n)
    return JSONResponse({"revoked_grants": n})


async def admin_state(request: Request) -> Response:
    return JSONResponse(store.state()) if _admin(request) else Response(status_code=403)


async def healthz(_: Request) -> Response:
    return JSONResponse({"ok": True, "persona": PERSONA})


def _seed_link() -> None:
    """The incoming application link a Jira admin would create by hand (SPEC §6.5).
    Real Jira generates the client id/secret. Here they come from .env so identity can be configured."""
    cid, secret = os.environ.get("OAUTH_CLIENT_ID"), os.environ.get("OAUTH_CLIENT_SECRET")
    if cid and secret:
        store.upsert_client(cid, secret, os.environ.get("OAUTH_CLIENT_NAME", "MCP Gateway (playground)"),
                            os.environ["OAUTH_REDIRECT_URI"], os.environ.get("OAUTH_SCOPE", "WRITE"),
                            os.environ.get("OAUTH_REQUIRE_PKCE", "false") == "true")


_seed_link()

routes = [
    Route("/healthz", healthz),
    Route("/login.jsp", login_get, methods=["GET"]),
    Route("/login.jsp", login_post, methods=["POST"]),
    Route("/logout", logout),
    Route("/rest/oauth2/latest/authorize", authorize_get, methods=["GET"]),
    Route("/rest/oauth2/latest/authorize", authorize_post, methods=["POST"]),
    Route("/rest/oauth2/latest/token", token, methods=["POST"]),
    Route("/.well-known/oauth-authorization-server", no_discovery),
    Route("/.well-known/openid-configuration", no_discovery),
    Route("/secure/ViewProfile.jspa", profile, methods=["GET", "POST"]),
    Route("/_stub/faults", admin_faults, methods=["GET", "POST", "DELETE"]),
    Route("/_stub/revoke-all", admin_revoke_all, methods=["POST"]),
    Route("/_stub/state", admin_state, methods=["GET"]),
]
# ---------------------------------------------------------------- Confluence REST subset (persona "confluence")

def _space_json(key: str) -> dict[str, Any]:
    sp = seed.SPACES[key]
    return {"id": int(sp.id), "key": sp.key, "name": sp.name, "type": "global"}


def _page_json(p: seed.Page, with_body: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": p.id, "type": "page", "status": "current", "title": p.title, "space": _space_json(p.space),
        "version": {"number": p.version, "by": _cf_user_json(p.author), "when": p.created},
        "_links": {"webui": f"/pages/viewpage.action?pageId={p.id}", "self": f"{BASE_URL}/rest/api/content/{p.id}"},
    }
    if with_body:
        out["body"] = {"storage": {"value": p.body, "representation": "storage"}}
    return out


def _cf_user_json(name: str) -> dict[str, Any]:
    u = seed.USERS[name]
    return {"type": "known", "username": u.name, "userKey": u.key, "displayName": u.display_name}


@api("READ")
async def cf_current_user(_: Request, caller: Caller) -> Response:
    return JSONResponse(_cf_user_json(caller.username))


@api("READ")
async def cf_search(request: Request, caller: Caller) -> Response:
    qp = request.query_params
    start, limit = int(qp.get("start", 0)), min(int(qp.get("limit", 25)), 100)
    try:
        pred = compile_cql(qp.get("cql", ""))
    except CqlError as e:
        return JSONResponse({"statusCode": 400, "message": str(e)}, status_code=400)
    visible = seed.visible_spaces(caller.username)
    hits = [p for p in seed.PAGES.values() if p.space in visible and pred(p)]
    page = hits[start:start + limit]
    return JSONResponse({"results": [_page_json(p) for p in page], "start": start, "limit": limit,
                         "size": len(page), "totalSize": len(hits), "_links": {"base": BASE_URL}})


@api("READ")
async def cf_get_content(request: Request, caller: Caller) -> Response:
    p = seed.PAGES.get(request.path_params["id"])
    if not p or p.space not in seed.visible_spaces(caller.username):
        # Confluence doesn't reveal whether content you can't see exists.
        return JSONResponse({"statusCode": 404, "message": "No content found with id: "
                             f"ContentId{{id={request.path_params['id']}}}"}, status_code=404)
    return JSONResponse(_page_json(p, with_body=True))


if PERSONA == "confluence":
    routes += [
        Route("/rest/api/user/current", cf_current_user, methods=["GET"]),
        Route("/rest/api/content/search", cf_search, methods=["GET"]),
        Route("/rest/api/content/{id}", cf_get_content, methods=["GET"]),
    ]

if PERSONA == "jira":
    routes += [
        Route("/rest/api/2/myself", myself, methods=["GET"]),
        Route("/rest/api/2/search", search, methods=["GET", "POST"]),
        Route("/rest/api/2/issue/{key}", get_issue, methods=["GET"]),
        Route("/rest/api/2/issue/{key}/comment", list_comments, methods=["GET"]),
        Route("/rest/api/2/issue/{key}/comment", add_comment, methods=["POST"]),
    ]

app = Starlette(routes=routes)
