"""OpenBao client + envelope encryption (≈ AWS KMS + Secrets Manager).

Envelope encryption per vault row:
  1. transit/datakey/plaintext/vault-dek → (DEK plaintext, DEK wrapped by vault-dek)
  2. AES-256-GCM(T4/T5) with the DEK, AAD = the row's identity (workload|user|provider)
  3. store ciphertext + wrapped DEK, discard the plaintext DEK
Reading needs transit/decrypt, so Postgres alone yields nothing. The AAD means
ciphertext copied into another user's row fails to decrypt.

Talks to OpenBao directly over the Docker network: not through mitmproxy, which
would otherwise display plaintext data keys.
"""

import base64
import os
from pathlib import Path

import httpx2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from identity.settings import BAO_ADDR, BAO_TOKEN_FILE, BAO_TRANSIT_KEY


class Bao:
    def __init__(self) -> None:
        self._http = httpx2.AsyncClient(base_url=f"{BAO_ADDR}/v1", trust_env=False, timeout=10)

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": Path(BAO_TOKEN_FILE).read_text().strip()}

    async def _call(self, method: str, path: str, json: dict | None = None) -> dict:
        r = await self._http.request(method, path, json=json, headers=self._headers())
        r.raise_for_status()
        return r.json() if r.content else {}

    async def renew_self(self) -> None:
        await self._call("POST", "/auth/token/renew-self", {})

    # ---- transit (≈ KMS) ----
    async def datakey(self) -> tuple[bytes, str]:
        d = (await self._call("POST", f"/transit/datakey/plaintext/{BAO_TRANSIT_KEY}", {"bits": 256}))["data"]
        return base64.b64decode(d["plaintext"]), d["ciphertext"]

    async def unwrap(self, wrapped: str) -> bytes:
        d = (await self._call("POST", f"/transit/decrypt/{BAO_TRANSIT_KEY}", {"ciphertext": wrapped}))["data"]
        return base64.b64decode(d["plaintext"])

    async def encrypt(self, data: str) -> str:
        d = await self._call("POST", f"/transit/encrypt/{BAO_TRANSIT_KEY}",
                             {"plaintext": base64.b64encode(data.encode()).decode()})
        return d["data"]["ciphertext"]

    async def decrypt(self, ct: str) -> str:
        return (await self.unwrap(ct)).decode()

    # ---- KV v2 (≈ Secrets Manager) ----
    async def kv_put(self, path: str, data: dict) -> None:
        await self._call("POST", f"/secret/data/{path}", {"data": data})

    async def kv_get(self, path: str) -> dict:
        return (await self._call("GET", f"/secret/data/{path}"))["data"]["data"]

    # ---- envelope ----
    async def seal(self, aad: str, **plain: str | None) -> tuple[str, dict[str, bytes | None]]:
        dek, wrapped = await self.datakey()
        gcm = AESGCM(dek)
        out: dict[str, bytes | None] = {}
        for k, v in plain.items():
            if v is None:
                out[k] = None
                continue
            nonce = os.urandom(12)
            out[k] = nonce + gcm.encrypt(nonce, v.encode(), aad.encode())
        return wrapped, out

    async def open(self, aad: str, wrapped: str, **cts: bytes | None) -> dict[str, str | None]:
        """Raises cryptography.exceptions.InvalidTag if the AAD doesn't match (row swapped/tampered)."""
        gcm = AESGCM(await self.unwrap(wrapped))
        return {k: (gcm.decrypt(bytes(v[:12]), bytes(v[12:]), aad.encode()).decode() if v is not None else None)
                for k, v in cts.items()}


bao = Bao()
