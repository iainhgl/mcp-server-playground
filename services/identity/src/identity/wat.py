"""Workload access token (T3): binds *which workload* (gateway) to *which user* (iss|sub).

AgentCore's version is opaque. Ours is an HS256 JWT signed by identity, so its claims
show up in the ledger. Only identity can mint or verify it.
"""

import secrets
import time

import jwt

from identity.settings import PUBLIC_URL, WAT_KEY, WAT_TTL

AUD = "identity:workload-access"


def mint(workload: str, user_id: str) -> str:
    now = int(time.time())
    return jwt.encode({"iss": PUBLIC_URL, "aud": AUD, "sub": user_id, "wl": workload, "iat": now,
                       "exp": now + WAT_TTL, "jti": secrets.token_hex(8)}, WAT_KEY, algorithm="HS256")


def verify(token: str) -> tuple[str, str]:
    """Returns (workload, user_id). Raises jwt.PyJWTError."""
    c = jwt.decode(token, WAT_KEY, algorithms=["HS256"], audience=AUD, issuer=PUBLIC_URL,
                   options={"require": ["exp", "sub", "wl"]})
    return c["wl"], c["sub"]
