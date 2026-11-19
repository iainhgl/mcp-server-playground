"""Postgres schema and pool (SPEC §6.3).

Nothing here is a usable credential on its own:
- token_vault / oauth_sessions hold AES-GCM ciphertext + an OpenBao-wrapped data key
- client secrets live in OpenBao KV. Only their path is stored here
"""

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from identity.settings import DATABASE_URL

SCHEMA = """
create table if not exists workload_identities (
  name text primary key,
  allowed_return_urls text[] not null,
  created_at timestamptz not null default now()
);
create table if not exists credential_providers (
  name text primary key,
  vendor text not null,
  issuer text,
  authorization_endpoint text not null,
  token_endpoint text not null,
  client_id text not null,
  client_secret_path text not null,          -- OpenBao KV path (≈ Secrets Manager ARN)
  scope_hierarchy text[] not null default '{}',
  created_at timestamptz not null default now()
);
create table if not exists oauth_sessions (   -- T6
  session_uri text primary key,
  state_hash text unique not null,           -- sha256(state); the raw state only exists in the browser URL
  workload_name text not null,
  user_id text not null,                     -- iss|sub of the user who STARTED the flow
  provider_name text not null,
  scopes text[] not null,
  return_url text not null,
  pkce_verifier_ct text not null,            -- OpenBao transit ciphertext
  status text not null,                      -- IN_PROGRESS → PENDING_BINDING → COMPLETED | FAILED
  pending_access_ct bytea,                   -- T4/T5 parked between callback and binding
  pending_refresh_ct bytea,
  pending_wrapped_dek text,
  pending_expires_at timestamptz,
  pending_scopes text[],
  failure text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create table if not exists token_vault (
  workload_name text not null,
  user_id text not null,                     -- iss|sub, from a VERIFIED user token only (invariant 3)
  provider_name text not null,
  scopes text[] not null,
  downstream_user text,
  access_ct bytea not null,                  -- nonce || AES-256-GCM(T4), AAD = workload|user|provider
  refresh_ct bytea,                          -- nonce || AES-256-GCM(T5), same AAD
  wrapped_dek text not null,                 -- data key wrapped by OpenBao transit key vault-dek (≈ KMS)
  access_expires_at timestamptz not null,
  refresh_rotated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (workload_name, user_id, provider_name)
);
"""

pool = AsyncConnectionPool(DATABASE_URL, open=False, min_size=2, max_size=20, kwargs={"row_factory": dict_row})


async def init() -> None:
    await pool.open()
    async with pool.connection() as conn:
        await conn.execute(SCHEMA)
