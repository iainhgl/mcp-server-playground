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
from playground_common import ledger
from playground_common.http import async_client

SERVICE = "gateway"
http = async_client()


@dataclass
class ConsentRequired(Exception):
    url: str
    session_uri: str
    provider: str
    scopes: list[str]


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
        raise ConsentRequired(out["authorizationUrl"], out["sessionUri"], provider, scopes)


class Target:
    """≈ an AgentCore Gateway OpenAPI target with an OAuth (USER_FEDERATION) credential provider."""

    def __init__(self, cfg: dict[str, Any], identity: Identity):
        self.name, self.base = cfg["name"], cfg["baseUrl"].rstrip("/")
        self.provider = cfg["credentialProvider"]["name"]
        self.identity = identity

    async def call(self, t1: str, scopes: list[str], method: str, path: str, **kw) -> httpx2.Response:
        t3 = await self.identity.workload_token(t1)
        t4 = await self.identity.resource_token(t3, self.provider, scopes)
        r = await http.request(method, f"{self.base}{path}", headers={"Authorization": f"Bearer {t4}"}, **kw)
        ledger.emit(SERVICE, "downstream.call", token=t4, label="T4", target=self.name, method=method, path=path,
                    status=r.status_code)
        if r.status_code == 401:
            # C6: Jira rejected a token the vault thought was valid (revoked in Jira). The old grant is
            # useless, so start a fresh consent. (Phase 5 may try one forced refresh first.)
            ledger.emit(SERVICE, "downstream.unauthorized", token=t4, label="T4", target=self.name)
            await self.identity.resource_token(t3, self.provider, scopes, force=True)
        return r
