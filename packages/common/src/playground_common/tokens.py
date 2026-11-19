"""Token helpers that never expose a raw token (SPEC §3 invariant 6)."""

import hashlib
from typing import Any

import jwt


def fingerprint(token: str) -> str:
    """Stable, non-reversible id for correlating a token across services/logs."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def unverified_claims(token: str) -> dict[str, Any] | None:
    """Decode a JWT payload WITHOUT verifying it. Use only for routing/logging
    (e.g. picking the authorizer by `iss`), never for an authorization decision."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
