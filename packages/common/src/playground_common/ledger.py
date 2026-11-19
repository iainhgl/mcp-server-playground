"""Token ledger (SPEC §7).

Every service emits one event per token receive/validate/mint/store/refresh/use/revoke.
Phase 1 writes JSON lines to stdout, prefixed `LEDGER `, so `make ledger` can
follow them. A later phase also persists them to Postgres for the portal viewer.

Only fingerprints and selected non-secret claims are recorded, never raw tokens.
"""

import json
import sys
from datetime import UTC, datetime
from typing import Any

from playground_common.tokens import fingerprint

_CLAIMS = ("iss", "sub", "aud", "azp", "client_id", "scope", "exp", "preferred_username")


def emit(
    service: str,
    event: str,
    *,
    token: str | None = None,
    label: str | None = None,
    claims: dict[str, Any] | None = None,
    **extra: Any,
) -> None:
    rec: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "service": service,
        "event": event,
    }
    if label:
        rec["token"] = label
    if token:
        rec["fp"] = fingerprint(token)
    if claims:
        rec |= {k: claims[k] for k in _CLAIMS if k in claims}
    rec |= {k: v for k, v in extra.items() if v is not None}
    print("LEDGER " + json.dumps(rec, default=str), file=sys.stdout, flush=True)
