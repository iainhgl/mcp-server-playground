"""Inbound JWT authorizer, shaped like AgentCore Gateway's `customJWTAuthorizer`
(discoveryUrl, allowedAudience, allowedClients), with support for several of
them at once (SPEC §6.2, §12 option B).

The authorizer is chosen by the token's *unverified* `iss`. That claim is only
used to find the right JWKS. The token is then fully verified against that
issuer: signature, iss, aud, exp/nbf/iat, client.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx2
import jwt

from playground_common.tokens import unverified_claims

ALLOWED_ALGS = ("RS256", "PS256", "ES256")
JWKS_MIN_REFRESH_S = 30


class AuthzError(Exception):
    """Token rejected. `reason` is safe to log and to return to the client."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class AuthorizerConfig:
    name: str
    discovery_url: str
    allowed_audience: list[str]
    allowed_clients: list[str] = field(default_factory=lambda: ["*"])

    @property
    def expected_issuer(self) -> str:
        # OIDC discovery lives at <issuer>/.well-known/openid-configuration.
        return self.discovery_url.split("/.well-known/")[0]


class JwtAuthorizer:
    def __init__(self, cfg: AuthorizerConfig, http: httpx2.AsyncClient):
        self.cfg = cfg
        self._http = http
        self._issuer: str | None = None
        self._jwks_uri: str | None = None
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    @property
    def issuer(self) -> str:
        return self._issuer or self.cfg.expected_issuer

    async def _refresh(self) -> None:
        async with self._lock:
            if time.monotonic() - self._fetched_at < JWKS_MIN_REFRESH_S and self._keys:
                return
            if not self._jwks_uri:
                meta = (await self._http.get(self.cfg.discovery_url)).raise_for_status().json()
                if meta["issuer"] != self.cfg.expected_issuer:
                    raise AuthzError(f"discovery issuer mismatch: {meta['issuer']}")
                self._issuer, self._jwks_uri = meta["issuer"], meta["jwks_uri"]
            jwks = (await self._http.get(self._jwks_uri)).raise_for_status().json()
            self._keys = {
                k["kid"]: jwt.PyJWK(k).key
                for k in jwks["keys"]
                if k.get("use", "sig") == "sig" and k.get("alg", "RS256") in ALLOWED_ALGS
            }
            self._fetched_at = time.monotonic()

    async def _key(self, kid: str | None) -> Any:
        if kid not in self._keys:
            await self._refresh()  # key rotation: unknown kid triggers a (rate-limited) refetch
        if kid not in self._keys:
            raise AuthzError(f"unknown signing key kid={kid}")
        return self._keys[kid]

    async def validate(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise AuthzError("malformed token")
        if header.get("alg") not in ALLOWED_ALGS:
            raise AuthzError(f"disallowed alg {header.get('alg')}")
        key = await self._key(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[header["alg"]],
                audience=self.cfg.allowed_audience,
                issuer=self.issuer,
                leeway=30,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            raise AuthzError("token expired")
        except jwt.InvalidAudienceError:
            raise AuthzError(f"audience not allowed (want one of {self.cfg.allowed_audience})")
        except jwt.InvalidIssuerError:
            raise AuthzError("issuer mismatch")
        except jwt.InvalidSignatureError:
            raise AuthzError("bad signature")
        except jwt.PyJWTError as e:
            raise AuthzError(f"invalid token: {e.__class__.__name__}")

        client = claims.get("azp") or claims.get("client_id")
        if "*" not in self.cfg.allowed_clients and client not in self.cfg.allowed_clients:
            raise AuthzError(f"client {client} not allowed")
        # Keycloak marks access tokens typ=Bearer; this keeps ID/refresh tokens out.
        if claims.get("typ") not in (None, "Bearer"):
            raise AuthzError(f"not an access token (typ={claims.get('typ')})")
        return claims


class MultiIssuerAuthorizer:
    def __init__(self, configs: list[AuthorizerConfig], http: httpx2.AsyncClient):
        self._by_issuer = {c.expected_issuer: JwtAuthorizer(c, http) for c in configs}

    @property
    def issuers(self) -> list[str]:
        return list(self._by_issuer)

    async def validate(self, token: str) -> tuple[str, dict[str, Any]]:
        """Returns (authorizer name, verified claims) or raises AuthzError."""
        iss = (unverified_claims(token) or {}).get("iss")
        authz = self._by_issuer.get(iss)
        if authz is None:
            raise AuthzError(f"untrusted issuer {iss!r}")
        return authz.cfg.name, await authz.validate(token)
