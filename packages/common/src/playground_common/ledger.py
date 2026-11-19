"""Token ledger (SPEC §7).

Every service emits one event per token receive/validate/mint/store/refresh/use/revoke:
- always as a JSON line on stdout, prefixed `LEDGER ` (`make ledger` follows these)
- and, if LEDGER_DATABASE_URL is set, also into the `ledger` Postgres DB (role
  `ledger_writer`, INSERT only) so the portal's /ledger viewer can show one timeline
  across services. Writes are queued to a background thread and never block or fail
  the request. When the DB is down, events are dropped from the DB but still go to stdout.

Only fingerprints and selected non-secret claims are recorded, never raw tokens.
"""

import json
import os
import queue
import sys
import threading
from datetime import UTC, datetime
from typing import Any

from playground_common.tokens import fingerprint

_CLAIMS = ("iss", "sub", "aud", "azp", "client_id", "scope", "exp", "preferred_username")
_DSN = os.environ.get("LEDGER_DATABASE_URL")
_q: queue.Queue = queue.Queue(maxsize=10_000)
_started = threading.Event()


def _writer() -> None:
    import psycopg  # only needed when persistence is on

    conn = None
    while True:
        rec = _q.get()
        try:
            if conn is None or conn.closed:
                conn = psycopg.connect(_DSN, autocommit=True, connect_timeout=3)
            conn.execute(
                "insert into events(ts, service, event, token_label, fp, data) values (%s, %s, %s, %s, %s, %s)",
                (rec["ts"], rec["service"], rec["event"], rec.get("token"), rec.get("fp"), json.dumps(rec, default=str)))
        except Exception as e:  # noqa: BLE001 - the ledger must never break the service
            print(f"ledger: db write failed ({e.__class__.__name__}); event kept on stdout only", file=sys.stderr)
            conn = None


def _ensure_writer() -> None:
    if _DSN and not _started.is_set():
        _started.set()
        threading.Thread(target=_writer, name="ledger-writer", daemon=True).start()


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
    if _DSN:
        _ensure_writer()
        try:
            _q.put_nowait(rec)
        except queue.Full:
            pass
