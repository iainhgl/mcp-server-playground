"""Persistent state (SQLite on a volume) for the stub's OAuth provider.

Tokens, codes and PATs are stored only as SHA-256 hashes, the way a real
provider should. The raw value exists only in the response that issued it.
"""

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

SCHEMA = """
create table if not exists web_sessions (
  id text primary key, username text not null, xsrf text not null, created_at real not null);
create table if not exists clients (
  client_id text primary key, client_secret_hash text not null, name text not null,
  redirect_uri text not null, scope text not null, require_pkce integer not null default 0);
create table if not exists auth_codes (
  code_hash text primary key, client_id text not null, username text not null, redirect_uri text not null,
  scope text not null, code_challenge text, code_challenge_method text,
  expires_at real not null, used integer not null default 0);
create table if not exists grants (
  id integer primary key autoincrement, client_id text not null, username text not null,
  scope text not null, created_at real not null, revoked_at real);
create table if not exists tokens (
  hash text primary key, kind text not null, grant_id integer not null, client_id text not null,
  username text not null, scope text not null, expires_at real not null, created_at real not null,
  revoked integer not null default 0, rotated integer not null default 0);
create table if not exists pats (
  hash text primary key, username text not null, name text not null, created_at real not null,
  expires_at real, revoked integer not null default 0);
create table if not exists comments (
  id integer primary key autoincrement, issue_key text not null, author text not null,
  body text not null, created text not null);
create table if not exists faults (k text primary key, v text not null);
"""

DEFAULT_FAULTS: dict[str, Any] = {
    "access_ttl": 7200,  # Jira DC default ≈ 2 h (SPEC §6.5, to confirm on the real instance: R4)
    "refresh_ttl": 90 * 24 * 3600,  # ≈ 90 d (to confirm: R4)
    "force_401": False,  # every API call answers 401
    "force_invalid_grant": False,  # every refresh answers invalid_grant
    "latency_ms": 0,
    "refresh_reuse_revokes_grant": False,  # OAuth 2.1 reuse detection (DC behaviour unknown: R4)
}

CODE_TTL = 600


def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class TokenRow:
    kind: str
    grant_id: int
    client_id: str
    username: str
    scope: str
    expires_at: float
    revoked: bool
    rotated: bool


class Store:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        # Re-entrant: helpers such as faults() run inside tx() on the same thread.
        self._lock = threading.RLock()
        self._db.executescript(SCHEMA)

    def q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def tx(self, fn):
        """Run fn(conn) in one IMMEDIATE transaction (refresh rotation must be atomic)."""
        with self._lock:
            self._db.execute("begin immediate")
            try:
                out = fn(self._db)
                self._db.execute("commit")
                return out
            except BaseException:
                self._db.execute("rollback")
                raise

    # ---- faults ----
    def faults(self) -> dict[str, Any]:
        return DEFAULT_FAULTS | {r["k"]: json.loads(r["v"]) for r in self.q("select k, v from faults")}

    def set_faults(self, changes: dict[str, Any]) -> dict[str, Any]:
        for k, v in changes.items():
            if k not in DEFAULT_FAULTS:
                raise KeyError(k)
            self.q("insert into faults(k, v) values(?, ?) on conflict(k) do update set v = excluded.v",
                   (k, json.dumps(v)))
        return self.faults()

    def reset_faults(self) -> None:
        self.q("delete from faults")

    # ---- web sessions (JSESSIONID) ----
    def new_session(self, username: str) -> tuple[str, str]:
        sid, xsrf = secrets.token_hex(16).upper(), secrets.token_hex(20)
        self.q("insert into web_sessions values(?, ?, ?, ?)", (sid, username, xsrf, time.time()))
        return sid, xsrf

    def session(self, sid: str | None) -> sqlite3.Row | None:
        if not sid:
            return None
        rows = self.q("select * from web_sessions where id = ?", (sid,))
        return rows[0] if rows else None

    def end_session(self, sid: str) -> None:
        self.q("delete from web_sessions where id = ?", (sid,))

    # ---- incoming application links (OAuth clients) ----
    def upsert_client(self, client_id: str, secret: str, name: str, redirect_uri: str, scope: str,
                      require_pkce: bool) -> None:
        self.q("""insert into clients values(?, ?, ?, ?, ?, ?) on conflict(client_id) do update set
                  client_secret_hash = excluded.client_secret_hash, name = excluded.name,
                  redirect_uri = excluded.redirect_uri, scope = excluded.scope, require_pkce = excluded.require_pkce""",
               (client_id, h(secret), name, redirect_uri, scope, int(require_pkce)))

    def client(self, client_id: str | None) -> sqlite3.Row | None:
        rows = self.q("select * from clients where client_id = ?", (client_id or "",))
        return rows[0] if rows else None

    # ---- authorization codes ----
    def new_code(self, client_id: str, username: str, redirect_uri: str, scope: str,
                 challenge: str | None, method: str | None) -> str:
        code = secrets.token_urlsafe(24)
        self.q("insert into auth_codes values(?, ?, ?, ?, ?, ?, ?, ?, 0)",
               (h(code), client_id, username, redirect_uri, scope, challenge, method, time.time() + CODE_TTL))
        return code

    def consume_code(self, code: str) -> sqlite3.Row | None:
        def fn(db):
            rows = db.execute("select * from auth_codes where code_hash = ?", (h(code),)).fetchall()
            if not rows:
                return None
            db.execute("update auth_codes set used = 1 where code_hash = ?", (h(code),))
            return rows[0]
        return self.tx(fn)

    # ---- grants + tokens ----
    def new_grant(self, client_id: str, username: str, scope: str) -> int:
        def fn(db):
            return db.execute("insert into grants(client_id, username, scope, created_at) values(?, ?, ?, ?)",
                              (client_id, username, scope, time.time())).lastrowid
        return self.tx(fn)

    def issue_pair(self, db, grant_id: int, client_id: str, username: str, scope: str) -> dict[str, Any]:
        f = self.faults()
        now = time.time()
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        db.execute("insert into tokens values(?, 'access', ?, ?, ?, ?, ?, ?, 0, 0)",
                   (h(access), grant_id, client_id, username, scope, now + f["access_ttl"], now))
        db.execute("insert into tokens values(?, 'refresh', ?, ?, ?, ?, ?, ?, 0, 0)",
                   (h(refresh), grant_id, client_id, username, scope, now + f["refresh_ttl"], now))
        return {"access_token": access, "refresh_token": refresh, "token_type": "bearer",
                "expires_in": int(f["access_ttl"]), "scope": scope}

    def token(self, raw: str) -> TokenRow | None:
        rows = self.q("""select t.*, g.revoked_at from tokens t join grants g on g.id = t.grant_id
                         where t.hash = ?""", (h(raw),))
        if not rows:
            return None
        r = rows[0]
        return TokenRow(r["kind"], r["grant_id"], r["client_id"], r["username"], r["scope"], r["expires_at"],
                        bool(r["revoked"]) or r["revoked_at"] is not None, bool(r["rotated"]))

    def rotate(self, raw_refresh: str, client_id: str) -> tuple[str, dict[str, Any] | TokenRow]:
        """Refresh-token grant with rotation. Returns ("ok", new pair) or (error_code, row|None)."""
        def fn(db):
            rows = db.execute("""select t.*, g.revoked_at from tokens t join grants g on g.id = t.grant_id
                                 where t.hash = ? and t.kind = 'refresh'""", (h(raw_refresh),)).fetchall()
            if not rows:
                return "unknown", None
            r = rows[0]
            if r["client_id"] != client_id:
                return "wrong_client", None
            if r["rotated"]:
                if self.faults()["refresh_reuse_revokes_grant"]:
                    db.execute("update grants set revoked_at = ? where id = ?", (time.time(), r["grant_id"]))
                return "reused", None
            if r["revoked"] or r["revoked_at"] is not None:
                return "revoked", None
            if r["expires_at"] < time.time():
                return "expired", None
            db.execute("update tokens set rotated = 1 where hash = ?", (h(raw_refresh),))
            return "ok", self.issue_pair(db, r["grant_id"], r["client_id"], r["username"], r["scope"])
        return self.tx(fn)

    def grants_for(self, username: str) -> list[sqlite3.Row]:
        return self.q("""select g.*, c.name as client_name from grants g join clients c on c.client_id = g.client_id
                         where g.username = ? and g.revoked_at is null order by g.created_at""", (username,))

    def revoke_grant(self, grant_id: int, username: str | None = None) -> int:
        if username is None:
            return len(self.q("update grants set revoked_at = ? where id = ? and revoked_at is null returning id",
                              (time.time(), grant_id)))
        return len(self.q("""update grants set revoked_at = ? where id = ? and username = ? and revoked_at is null
                             returning id""", (time.time(), grant_id, username)))

    def revoke_all(self) -> int:
        return len(self.q("update grants set revoked_at = ? where revoked_at is null returning id", (time.time(),)))

    # ---- personal access tokens ----
    def new_pat(self, username: str, name: str) -> str:
        raw = secrets.token_urlsafe(33)
        self.q("insert into pats values(?, ?, ?, ?, null, 0)", (h(raw), username, name, time.time()))
        return raw

    def pat(self, raw: str) -> sqlite3.Row | None:
        rows = self.q("select * from pats where hash = ? and revoked = 0", (h(raw),))
        return rows[0] if rows else None

    def pats_for(self, username: str) -> list[sqlite3.Row]:
        return self.q("select * from pats where username = ? and revoked = 0", (username,))

    # ---- comments ----
    def add_comment(self, issue_key: str, author: str, body: str, created: str) -> int:
        def fn(db):
            return db.execute("insert into comments(issue_key, author, body, created) values(?, ?, ?, ?)",
                              (issue_key, author, body, created)).lastrowid
        return self.tx(fn)

    def comments(self, issue_key: str) -> list[sqlite3.Row]:
        return self.q("select * from comments where issue_key = ? order by id", (issue_key,))

    # ---- debug view (no secrets) ----
    def state(self) -> dict[str, Any]:
        return {
            "grants": [dict(r) for r in self.q("select * from grants")],
            "tokens": [{**dict(r), "hash": r["hash"][:12]} for r in self.q(
                "select hash, kind, grant_id, username, scope, expires_at, revoked, rotated from tokens")],
            "faults": self.faults(),
        }
