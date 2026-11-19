"""identity: AgentCore-Identity-shaped service (SPEC §6.3, architecture §3.2 B3–B14, §3.3).

Operation names and request/response fields mirror AgentCore Identity, so call
sites port to boto3 `bedrock-agentcore` / `bedrock-agentcore-control`. The
transport (POST /identities/<Operation>, JSON) is ours.

Planes:
  control  CreateWorkloadIdentity, CreateOauth2CredentialProvider    X-Identity-Admin (≈ IAM admin)
  data     GetWorkloadAccessTokenFor{JWT,UserId}, GetResourceOauth2Token,
           CompleteResourceTokenAuth                                 Bearer service token (aud=identity) + CALLER_ACL
  browser  GET /identities/oauth2/callback                           the OAuth `state` is the only credential
"""

import base64
import contextlib
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from html import escape
from urllib.parse import urlencode

import jwt
from cryptography.exceptions import InvalidTag
from playground_common import fingerprint, ledger
from playground_common.http import async_client
from playground_common.jwt_authz import AuthorizerConfig, AuthzError, MultiIssuerAuthorizer
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from identity import db, wat
from identity.bao import bao
from identity.settings import (
    ADMIN_TOKEN,
    CALLBACK_URL,
    CALLER_ACL,
    IDP_DISCOVERY_URL,
    REFRESH_SKEW,
    SERVICE,
    SESSION_TTL,
    USER_TOKEN_AUDIENCES,
)

http = async_client()  # outbound HTTPS (IdP JWKS, provider token endpoints) via mitmproxy
callers = MultiIssuerAuthorizer(
    [AuthorizerConfig("rhsso-services", IDP_DISCOVERY_URL, ["identity"], sorted(set().union(*CALLER_ACL.values())))],
    http)
users = MultiIssuerAuthorizer([AuthorizerConfig("rhsso-users", IDP_DISCOVERY_URL, USER_TOKEN_AUDIENCES)], http)
SESSION_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


class ApiError(Exception):
    def __init__(self, status: int, kind: str, message: str):
        super().__init__(message)
        self.status, self.kind, self.message = status, kind, message


def _err(e: ApiError) -> JSONResponse:
    return JSONResponse({"__type": e.kind, "message": e.message}, status_code=e.status)


def _now() -> datetime:
    return datetime.now(UTC)


def _h(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def _vault_aad(workload: str, user_id: str, provider: str) -> str:
    return f"vault|{workload}|{user_id}|{provider}"


# ------------------------------------------------------------------ auth helpers

async def _caller(request: Request, op: str) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise ApiError(401, "UnauthorizedException", "service token required")
    tok = auth[7:].strip()
    try:
        _, claims = await callers.validate(tok)
    except AuthzError as e:
        ledger.emit(SERVICE, "caller.rejected", token=tok, label="T7?", op=op, reason=e.reason)
        raise ApiError(401, "UnauthorizedException", e.reason) from None
    azp = claims.get("azp") or claims.get("client_id")
    if azp not in CALLER_ACL[op]:
        ledger.emit(SERVICE, "caller.denied", token=tok, label="T7", op=op, azp=azp)
        raise ApiError(403, "AccessDeniedException", f"{azp} may not call {op}")
    return azp


async def _user_id_from_token(token: str, label: str, op: str) -> str:
    try:
        _, c = await users.validate(token)
    except AuthzError as e:
        ledger.emit(SERVICE, "user_token.rejected", token=token, label=f"{label}?", op=op, reason=e.reason)
        raise ApiError(400, "ValidationException", f"userToken rejected: {e.reason}") from None
    ledger.emit(SERVICE, "user_token.validated", token=token, label=label, claims=c, op=op)
    return f"{c['iss']}|{c['sub']}"  # invariant 3: the user id comes only from a verified token


def _admin(request: Request) -> None:
    if not hmac.compare_digest(request.headers.get("x-identity-admin", ""), ADMIN_TOKEN):
        raise ApiError(403, "AccessDeniedException", "admin token required")


def api(fn):
    async def handler(request: Request) -> Response:
        try:
            body = await request.json() if request.method == "POST" else {}
            return JSONResponse(await fn(request, body))
        except ApiError as e:
            return _err(e)
    return handler


# ------------------------------------------------------------------ control plane

@api
async def create_workload_identity(request: Request, body: dict) -> dict:
    _admin(request)
    name, urls = body["name"], body.get("allowedResourceOauth2ReturnUrls", [])
    async with db.pool.connection() as conn:
        await conn.execute("""insert into workload_identities(name, allowed_return_urls) values (%s, %s)
                              on conflict (name) do update set allowed_return_urls = excluded.allowed_return_urls""",
                           (name, urls))
    ledger.emit(SERVICE, "control.workload_identity", name=name, return_urls=urls)
    return {"name": name, "workloadIdentityArn": f"arn:playground:identity:workload-identity/{name}",
            "allowedResourceOauth2ReturnUrls": urls}


@api
async def create_oauth2_credential_provider(request: Request, body: dict) -> dict:
    _admin(request)
    name = body["name"]
    if body.get("credentialProviderVendor") != "CustomOauth2":
        raise ApiError(400, "ValidationException", "playground supports CustomOauth2 only")
    cfg = body["oauth2ProviderConfigInput"]["customOauth2ProviderConfig"]
    meta = cfg["oauthDiscovery"].get("authorizationServerMetadata")
    if meta is None:  # Jira DC has no discovery document, so explicit metadata is the only option
        raise ApiError(400, "ValidationException", "authorizationServerMetadata required (discoveryUrl not supported)")
    secret_path = f"credential-providers/{name}"
    await bao.kv_put(secret_path, {"clientSecret": cfg["clientSecret"]})
    hierarchy = body.get("x-playground", {}).get("scopeHierarchy", [])
    async with db.pool.connection() as conn:
        await conn.execute(
            """insert into credential_providers values (%s, 'CustomOauth2', %s, %s, %s, %s, %s, %s, now())
               on conflict (name) do update set issuer = excluded.issuer,
                 authorization_endpoint = excluded.authorization_endpoint, token_endpoint = excluded.token_endpoint,
                 client_id = excluded.client_id, client_secret_path = excluded.client_secret_path,
                 scope_hierarchy = excluded.scope_hierarchy""",
            (name, meta.get("issuer"), meta["authorizationEndpoint"], meta["tokenEndpoint"], cfg["clientId"],
             secret_path, hierarchy))
    ledger.emit(SERVICE, "control.credential_provider", name=name, client_id=cfg["clientId"],
                secret_ref=f"bao:secret/{secret_path}")
    return {"name": name, "credentialProviderArn": f"arn:playground:identity:oauth2credentialprovider/{name}",
            "clientSecretArn": f"bao:secret/{secret_path}", "callbackUrl": CALLBACK_URL}


@api
async def admin_vault(request: Request, _: dict) -> dict:
    """Debug view: metadata only (no ciphertext, no tokens)."""
    _admin(request)
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            """select workload_name, user_id, provider_name, scopes, downstream_user, access_expires_at,
                      refresh_rotated_at, created_at, updated_at, length(access_ct) as access_ct_bytes,
                      left(wrapped_dek, 9) as dek_wrapping from token_vault order by updated_at""")).fetchall()
    return {"entries": [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()} for r in rows]}


# ------------------------------------------------------------------ data plane: workload access tokens

@api
async def get_wat_for_jwt(request: Request, body: dict) -> dict:
    await _caller(request, "GetWorkloadAccessTokenForJWT")
    workload = await _workload(body["workloadName"])
    user_id = await _user_id_from_token(body["userToken"], "T1", "GetWorkloadAccessTokenForJWT")
    tok = wat.mint(workload["name"], user_id)
    ledger.emit(SERVICE, "wat.minted", token=tok, label="T3", workload=workload["name"], user_id=user_id)
    return {"workloadAccessToken": tok}


@api
async def get_wat_for_user_id(request: Request, body: dict) -> dict:
    await _caller(request, "GetWorkloadAccessTokenForUserId")  # the trusted caller vouches for userId
    workload = await _workload(body["workloadName"])
    tok = wat.mint(workload["name"], body["userId"])
    ledger.emit(SERVICE, "wat.minted", token=tok, label="T3", workload=workload["name"], user_id=body["userId"],
                via="userId")
    return {"workloadAccessToken": tok}


async def _workload(name: str) -> dict:
    async with db.pool.connection() as conn:
        row = await (await conn.execute("select * from workload_identities where name = %s", (name,))).fetchone()
    if not row:
        raise ApiError(404, "ResourceNotFoundException", f"workload identity {name} not found")
    return row


async def _provider(name: str) -> dict:
    async with db.pool.connection() as conn:
        row = await (await conn.execute("select * from credential_providers where name = %s", (name,))).fetchone()
    if not row:
        raise ApiError(404, "ResourceNotFoundException", f"credential provider {name} not found")
    return row


# ------------------------------------------------------------------ data plane: GetResourceOauth2Token

def _covers(granted: list[str], requested: list[str], hierarchy: list[str]) -> bool:
    """Do the vaulted scopes satisfy the request? With a provider hierarchy (Jira: READ<WRITE<…) a higher
    scope covers lower ones. That's a playground extension: how AgentCore compares scopes is unverified."""
    if hierarchy and all(s in hierarchy for s in granted + requested):
        return max(map(hierarchy.index, granted), default=-1) >= max(map(hierarchy.index, requested), default=-1)
    return set(requested) <= set(granted)


async def _provider_token_call(provider: dict, form: dict[str, str]) -> tuple[int, dict]:
    secret = (await bao.kv_get(provider["client_secret_path"]))["clientSecret"]
    r = await http.post(provider["token_endpoint"],
                        data={"client_id": provider["client_id"], "client_secret": secret} | form)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"error": "non_json_response"}


async def _vault_get(workload: str, user_id: str, provider: dict, scopes: list[str]) -> str | None:
    """Return a usable T4 or None (→ consent needed). Refreshes under a row lock (S7)."""
    key = (workload, user_id, provider["name"])
    aad = _vault_aad(*key)
    async with db.pool.connection() as conn, conn.transaction():
        row = await (await conn.execute(
            """select * from token_vault where workload_name = %s and user_id = %s and provider_name = %s
               for update""", key)).fetchone()
        if row is None:
            ledger.emit(SERVICE, "vault.miss", workload=workload, user_id=user_id, provider=provider["name"])
            return None
        if not _covers(row["scopes"], scopes, provider["scope_hierarchy"]):
            ledger.emit(SERVICE, "vault.insufficient_scope", user_id=user_id, granted=row["scopes"], requested=scopes)
            return None
        try:
            t = await bao.open(aad, row["wrapped_dek"], access=row["access_ct"], refresh=row["refresh_ct"])
        except InvalidTag:
            # Ciphertext doesn't belong to this row (copied/tampered). Treat it as absent.
            await conn.execute("delete from token_vault where workload_name = %s and user_id = %s "
                               "and provider_name = %s", key)
            ledger.emit(SERVICE, "vault.corrupt_purged", user_id=user_id, provider=provider["name"],
                        reason="AES-GCM tag mismatch (AAD binds ciphertext to its row)")
            return None
        if row["access_expires_at"] > _now() + timedelta(seconds=REFRESH_SKEW):
            ledger.emit(SERVICE, "vault.hit", token=t["access"], label="T4", user_id=user_id, provider=provider["name"])
            return t["access"]
        if not t["refresh"]:
            await conn.execute("delete from token_vault where workload_name = %s and user_id = %s "
                               "and provider_name = %s", key)
            return None
        ledger.emit(SERVICE, "vault.refresh_start", token=t["refresh"], label="T5", user_id=user_id)
        status, resp = await _provider_token_call(provider, {"grant_type": "refresh_token",
                                                             "refresh_token": t["refresh"]})
        if status == 200:
            wrapped, ct = await bao.seal(aad, access=resp["access_token"],
                                         refresh=resp.get("refresh_token") or t["refresh"])
            await conn.execute(
                """update token_vault set access_ct = %s, refresh_ct = %s, wrapped_dek = %s, access_expires_at = %s,
                   refresh_rotated_at = now(), updated_at = now()
                   where workload_name = %s and user_id = %s and provider_name = %s""",
                (ct["access"], ct["refresh"], wrapped, _now() + timedelta(seconds=int(resp.get("expires_in", 3600))),
                 *key))
            ledger.emit(SERVICE, "vault.refreshed", token=resp["access_token"], label="T4", user_id=user_id,
                        rotated=bool(resp.get("refresh_token")))
            return resp["access_token"]
        if status in (400, 401) and resp.get("error") == "invalid_grant":
            await conn.execute("delete from token_vault where workload_name = %s and user_id = %s "
                               "and provider_name = %s", key)
            ledger.emit(SERVICE, "vault.purged", user_id=user_id, provider=provider["name"],
                        reason=f"refresh invalid_grant: {resp.get('error_description')}")
            return None
        ledger.emit(SERVICE, "vault.refresh_failed", user_id=user_id, status=status, error=resp.get("error"))
        raise ApiError(502, "ServiceException", f"provider refresh failed ({status})")


async def _start_session(workload: dict, user_id: str, provider: dict, scopes: list[str], return_url: str) -> dict:
    verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(24)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session_uri = SESSION_URI_PREFIX + secrets.token_urlsafe(18)
    async with db.pool.connection() as conn:
        await conn.execute(
            """insert into oauth_sessions(session_uri, state_hash, workload_name, user_id, provider_name, scopes,
                 return_url, pkce_verifier_ct, status, expires_at)
               values (%s, %s, %s, %s, %s, %s, %s, %s, 'IN_PROGRESS', %s)""",
            (session_uri, _h(state), workload["name"], user_id, provider["name"], scopes, return_url,
             await bao.encrypt(verifier), _now() + timedelta(seconds=SESSION_TTL)))
    url = provider["authorization_endpoint"] + "?" + urlencode({
        "client_id": provider["client_id"], "redirect_uri": CALLBACK_URL, "response_type": "code",
        "scope": " ".join(scopes), "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    ledger.emit(SERVICE, "session.created", token=session_uri, label="T6", user_id=user_id,
                provider=provider["name"], scopes=scopes, return_url=return_url)
    return {"authorizationUrl": url, "sessionUri": session_uri, "sessionStatus": "IN_PROGRESS"}


@api
async def get_resource_oauth2_token(request: Request, body: dict) -> dict:
    caller = await _caller(request, "GetResourceOauth2Token")
    try:
        workload_name, user_id = wat.verify(body["workloadIdentityToken"])
    except jwt.PyJWTError as e:
        raise ApiError(400, "ValidationException", f"invalid workloadIdentityToken: {e.__class__.__name__}") from None
    workload = await _workload(workload_name)
    provider = await _provider(body["resourceCredentialProviderName"])
    if body.get("oauth2Flow") != "USER_FEDERATION":
        raise ApiError(400, "ValidationException", "playground supports oauth2Flow=USER_FEDERATION only")
    scopes = body.get("scopes") or []
    return_url = body.get("resourceOauth2ReturnUrl", "")
    if return_url not in workload["allowed_return_urls"]:
        raise ApiError(400, "ValidationException", "resourceOauth2ReturnUrl not allowed for this workload")
    ledger.emit(SERVICE, "token.requested", token=body["workloadIdentityToken"], label="T3", caller=caller,
                user_id=user_id, provider=provider["name"], scopes=scopes, force=bool(body.get("forceAuthentication")))
    if not body.get("forceAuthentication"):
        access = await _vault_get(workload_name, user_id, provider, scopes)
        if access:
            return {"accessToken": access}
    return await _start_session(workload, user_id, provider, scopes, return_url)


# ------------------------------------------------------------------ browser: provider callback

def _page(title: str, msg: str, status: int) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>{escape(title)}</title>"
                        f"<body style='font-family:system-ui;max-width:36em;margin:3em auto'>"
                        f"<h1>{escape(title)}</h1><p>{escape(msg)}</p></body>", status_code=status)


async def oauth2_callback(request: Request) -> Response:
    q = request.query_params
    state = q.get("state", "")
    async with db.pool.connection() as conn, conn.transaction():
        s = await (await conn.execute("select * from oauth_sessions where state_hash = %s for update",
                                      (_h(state),))).fetchone()
        if s is None:
            ledger.emit(SERVICE, "callback.rejected", reason="unknown state")
            return _page("Sign-in link not recognised", "This authorization response does not match any session.", 400)
        uri = s["session_uri"]
        back = s["return_url"] + "?" + urlencode({"session_id": uri})

        async def fail(reason: str) -> Response:
            await conn.execute("update oauth_sessions set status = 'FAILED', failure = %s where session_uri = %s",
                               (reason, uri))
            ledger.emit(SERVICE, "callback.failed", token=uri, label="T6", reason=reason)
            return RedirectResponse(back + "&" + urlencode({"error": reason}), status_code=302)

        if s["status"] != "IN_PROGRESS":
            return _page("Already used", f"This sign-in session is {s['status']}.", 400)
        if s["expires_at"] < _now():
            return await fail("session_expired")
        if err := q.get("error"):
            return await fail(err)
        provider = await _provider(s["provider_name"])
        verifier = await bao.decrypt(s["pkce_verifier_ct"])
        status, resp = await _provider_token_call(provider, {
            "grant_type": "authorization_code", "code": q.get("code", ""), "redirect_uri": CALLBACK_URL,
            "code_verifier": verifier})
        if status != 200:
            return await fail(f"token_exchange_failed:{resp.get('error')}")
        wrapped, ct = await bao.seal(f"pending|{uri}", access=resp["access_token"], refresh=resp.get("refresh_token"))
        granted = (resp.get("scope") or " ".join(s["scopes"])).split()
        await conn.execute(
            """update oauth_sessions set status = 'PENDING_BINDING', pending_access_ct = %s, pending_refresh_ct = %s,
                 pending_wrapped_dek = %s, pending_expires_at = %s, pending_scopes = %s where session_uri = %s""",
            (ct["access"], ct["refresh"], wrapped, _now() + timedelta(seconds=int(resp.get("expires_in", 3600))),
             granted, uri))
    ledger.emit(SERVICE, "callback.tokens_parked", token=resp["access_token"], label="T4", session=fingerprint(uri),
                user_id=s["user_id"], scopes=granted)
    ledger.emit(SERVICE, "callback.tokens_parked", token=resp.get("refresh_token"), label="T5", session=fingerprint(uri))
    return RedirectResponse(back, status_code=302)


# ------------------------------------------------------------------ data plane: CompleteResourceTokenAuth

@api
async def complete_resource_token_auth(request: Request, body: dict) -> dict:
    await _caller(request, "CompleteResourceTokenAuth")
    uri, ident = body.get("sessionUri", ""), body.get("userIdentifier") or {}
    if "userToken" in ident:
        user_id = await _user_id_from_token(ident["userToken"], "T2", "CompleteResourceTokenAuth")
    elif "userId" in ident:
        user_id = ident["userId"]
    else:
        raise ApiError(400, "ValidationException", "userIdentifier.userToken or .userId required")
    async with db.pool.connection() as conn, conn.transaction():
        s = await (await conn.execute("select * from oauth_sessions where session_uri = %s for update",
                                      (uri,))).fetchone()
        if s is None:
            raise ApiError(404, "ResourceNotFoundException", "session not found")
        if s["status"] != "PENDING_BINDING":
            raise ApiError(400, "ValidationException", f"session is {s['status']}")
        wipe = """update oauth_sessions set status = %s, failure = %s, pending_access_ct = null,
                  pending_refresh_ct = null, pending_wrapped_dek = null where session_uri = %s"""
        if s["expires_at"] < _now():
            await conn.execute(wipe, ("FAILED", "session_expired", uri))
            raise ApiError(400, "ValidationException", "session expired")
        if user_id != s["user_id"]:
            # B13: whoever finished the consent is not who started it (consent hijack, S9).
            await conn.execute(wipe, ("FAILED", "binding_mismatch", uri))
            ledger.emit(SERVICE, "binding.mismatch", token=uri, label="T6", started_by=s["user_id"],
                        completed_by=user_id)
        else:
            t = await bao.open(f"pending|{uri}", s["pending_wrapped_dek"], access=s["pending_access_ct"],
                               refresh=s["pending_refresh_ct"])
            key = (s["workload_name"], s["user_id"], s["provider_name"])
            wrapped, ct = await bao.seal(_vault_aad(*key), access=t["access"], refresh=t["refresh"])
            await conn.execute(
                """insert into token_vault(workload_name, user_id, provider_name, scopes, access_ct, refresh_ct,
                     wrapped_dek, access_expires_at) values (%s, %s, %s, %s, %s, %s, %s, %s)
                   on conflict (workload_name, user_id, provider_name) do update set scopes = excluded.scopes,
                     access_ct = excluded.access_ct, refresh_ct = excluded.refresh_ct,
                     wrapped_dek = excluded.wrapped_dek, access_expires_at = excluded.access_expires_at,
                     refresh_rotated_at = null, updated_at = now()""",
                (*key, s["pending_scopes"], ct["access"], ct["refresh"], wrapped, s["pending_expires_at"]))
            await conn.execute(wipe, ("COMPLETED", None, uri))
            ledger.emit(SERVICE, "binding.ok", token=uri, label="T6", user_id=user_id)
            ledger.emit(SERVICE, "vault.store", token=t["access"], label="T4", user_id=user_id,
                        provider=s["provider_name"], scopes=s["pending_scopes"], dek=wrapped[:9] + "…")
            return {}
    raise ApiError(403, "AccessDeniedException", "user does not match the user who started this session")


# ------------------------------------------------------------------ playground extensions (portal "Connected apps")

@api
async def list_user_connections(request: Request, body: dict) -> dict:
    await _caller(request, "x-ListUserConnections")
    async with db.pool.connection() as conn:
        rows = await (await conn.execute(
            """select workload_name, provider_name, scopes, access_expires_at, created_at, updated_at
               from token_vault where user_id = %s order by provider_name""", (body["userId"],))).fetchall()
    return {"connections": [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()}
                            for r in rows]}


@api
async def delete_user_connection(request: Request, body: dict) -> dict:
    """Forget the vaulted tokens. Jira DC has no revocation endpoint (stub-fidelity F16/F17), so an
    already-issued T4 stays valid at Jira until it expires, unless the user also revokes it in Jira."""
    await _caller(request, "x-DeleteUserConnection")
    async with db.pool.connection() as conn:
        n = (await conn.execute(
            "delete from token_vault where user_id = %s and workload_name = %s and provider_name = %s",
            (body["userId"], body["workloadName"], body["providerName"]))).rowcount
    ledger.emit(SERVICE, "vault.deleted_by_user", user_id=body["userId"], provider=body["providerName"], rows=n)
    return {"deleted": n}


# ------------------------------------------------------------------ app

async def healthz(_: Request) -> Response:
    return JSONResponse({"ok": True})


@contextlib.asynccontextmanager
async def lifespan(_app):
    await db.init()
    await bao.renew_self()  # periodic token: renewing on start keeps it alive across restarts
    yield
    await db.pool.close()


app = Starlette(lifespan=lifespan, routes=[
    Route("/healthz", healthz),
    Route("/identities/CreateWorkloadIdentity", create_workload_identity, methods=["POST"]),
    Route("/identities/CreateOauth2CredentialProvider", create_oauth2_credential_provider, methods=["POST"]),
    Route("/identities/GetWorkloadAccessTokenForJWT", get_wat_for_jwt, methods=["POST"]),
    Route("/identities/GetWorkloadAccessTokenForUserId", get_wat_for_user_id, methods=["POST"]),
    Route("/identities/GetResourceOauth2Token", get_resource_oauth2_token, methods=["POST"]),
    Route("/identities/CompleteResourceTokenAuth", complete_resource_token_auth, methods=["POST"]),
    Route("/identities/oauth2/callback", oauth2_callback, methods=["GET"]),
    Route("/identities/x-ListUserConnections", list_user_connections, methods=["POST"]),
    Route("/identities/x-DeleteUserConnection", delete_user_connection, methods=["POST"]),
    Route("/admin/vault", admin_vault, methods=["GET"]),
])
