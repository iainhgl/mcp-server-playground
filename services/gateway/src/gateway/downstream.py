"""Outbound side of the gateway (architecture §3.2 B2–B6, B15–B16; §3.3 C5–C6).

Per tool call:
  T7 (gateway-svc, cached)  →  identity GetWorkloadAccessTokenForJWT(T1) → T3
  → identity GetResourceOauth2Token(T3, provider, scopes) → {accessToken: T4} | {authorizationUrl}
  → Jira with Bearer T4 (never T1: invariant 2)
T4 is held for exactly one downstream call and never stored or logged.
"""

import os
import time
from dataclasses import dataclass
from typing import Any

import httpx2
from playground_common import fingerprint, ledger
from playground_common.http import async_client

SERVICE = "gateway"
http = async_client()


@dataclass
class ConsentRequired(Exception):
    url: str
    session_uri: str
    provider: str
    scopes: list[str]
    t3: str  # the same user's workload token, so the gateway can poll the session (elicitation/complete)


class DownstreamError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ServiceToken:
    """The gateway's own credential for identity (T7, ≈ IAM role credentials). Cached until near expiry."""

    def __init__(self, token_url: str, client_id: str, secret: str):
        self.token_url, self.client_id, self.secret = token_url, client_id, secret
        self._tok, self._exp = "", 0.0

    async def get(self) -> str:
        if time.time() > self._exp - 30:
            r = await http.post(self.token_url, data={"grant_type": "client_credentials", "client_id": self.client_id,
                                                      "client_secret": self.secret})
            r.raise_for_status()
            body = r.json()
            self._tok, self._exp = body["access_token"], time.time() + body.get("expires_in", 300)
            ledger.emit(SERVICE, "service_token.minted", token=self._tok, label="T7", client_id=self.client_id)
        return self._tok


class Identity:
    def __init__(self, cfg: dict[str, Any], token_url: str):
        self.base = cfg["url"].rstrip("/")
        self.workload = cfg["workloadName"]
        self.return_url = cfg["returnUrl"]
        self.svc = ServiceToken(token_url, cfg["serviceClientId"], os.environ["GATEWAY_SVC_CLIENT_SECRET"])

    async def _call(self, op: str, body: dict) -> dict:
        r = await http.post(f"{self.base}/{op}", json=body,
                            headers={"Authorization": f"Bearer {await self.svc.get()}"})
        if r.is_error:
            raise DownstreamError(502, f"identity {op} failed: {r.status_code} {r.text[:200]}")
        return r.json()

    async def workload_token(self, t1: str) -> str:
        t3 = (await self._call("GetWorkloadAccessTokenForJWT",
                               {"workloadName": self.workload, "userToken": t1}))["workloadAccessToken"]
        ledger.emit(SERVICE, "wat.received", token=t3, label="T3")
        return t3

    async def resource_token(self, t3: str, provider: str, scopes: list[str], force: bool = False) -> str:
        out = await self._call("GetResourceOauth2Token", {
            "workloadIdentityToken": t3, "resourceCredentialProviderName": provider, "scopes": scopes,
            "oauth2Flow": "USER_FEDERATION", "resourceOauth2ReturnUrl": self.return_url,
            "forceAuthentication": force})
        if "accessToken" in out:
            ledger.emit(SERVICE, "resource_token.received", token=out["accessToken"], label="T4", provider=provider)
            return out["accessToken"]
        ledger.emit(SERVICE, "consent.required", token=out["sessionUri"], label="T6", provider=provider,
                    scopes=scopes, force=force)
        raise ConsentRequired(out["authorizationUrl"], out["sessionUri"], provider, scopes, t3)

    async def session_status(self, t3: str, session_uri: str) -> str:
        out = await self._call("x-GetConsentSessionStatus", {"workloadIdentityToken": t3, "sessionUri": session_uri})
        return out["sessionStatus"]

    async def token_rejected(self, t3: str, provider: str, t4: str) -> str:
        """Tell identity the provider rejected this T4. Returns REFRESHED | PURGED | SUPERSEDED | ABSENT."""
        out = await self._call("x-ResourceTokenRejected", {
            "workloadIdentityToken": t3, "resourceCredentialProviderName": provider,
            "accessTokenFingerprint": fingerprint(t4)})
        return out["status"]


class Target:
    """≈ an AgentCore Gateway OpenAPI target with an OAuth (USER_FEDERATION) credential provider."""

    def __init__(self, cfg: dict[str, Any], identity: Identity):
        self.name, self.base = cfg["name"], cfg["baseUrl"].rstrip("/")
        self.provider = cfg["credentialProvider"]["name"]
        self.identity = identity

    async def _send(self, t4: str, method: str, path: str, **kw) -> httpx2.Response:
        r = await http.request(method, f"{self.base}{path}", headers={"Authorization": f"Bearer {t4}"}, **kw)
        ledger.emit(SERVICE, "downstream.call", token=t4, label="T4", target=self.name, method=method, path=path,
                    status=r.status_code)
        return r

    async def call(self, t1: str, scopes: list[str], method: str, path: str, **kw) -> httpx2.Response:
        t3 = await self.identity.workload_token(t1)
        t4 = await self.identity.resource_token(t3, self.provider, scopes)
        r = await self._send(t4, method, path, **kw)
        if r.status_code != 401:
            return r
        # C6: Jira rejected a T4 the vault thought was valid (e.g. the user revoked the app in Jira).
        # Report it so identity can refresh once, or purge the dead entry (the portal then shows
        # "Not connected"). Then ask again: either a fresh T4 (retry once) or ConsentRequired.
        status = await self.identity.token_rejected(t3, self.provider, t4)
        ledger.emit(SERVICE, "downstream.unauthorized", token=t4, label="T4", target=self.name, vault=status)
        t4b = await self.identity.resource_token(t3, self.provider, scopes)
        if t4b != t4:
            r = await self._send(t4b, method, path, **kw)
            if r.status_code != 401:
                return r
        # Still rejected with whatever the vault holds: only a new consent can help.
        await self.identity.resource_token(t3, self.provider, scopes, force=True)
        return r  # unreachable: force=True always raises ConsentRequired
