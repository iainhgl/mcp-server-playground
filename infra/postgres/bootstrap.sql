-- Idempotent, runs on every `up` (unlike init.sh, which only runs on a fresh volume).
-- The token ledger (SPEC §7): services write through `ledger_writer` (INSERT only),
-- and the portal reads (SELECT only). Rows hold fingerprints and non-secret claims only.

SELECT 'CREATE DATABASE ledger' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ledger')\gexec

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ledger_writer') THEN
    CREATE ROLE ledger_writer LOGIN;
  END IF;
END $$;
ALTER ROLE ledger_writer PASSWORD :'writer_pw';

\connect ledger
CREATE TABLE IF NOT EXISTS events (
  id          bigserial PRIMARY KEY,
  ts          timestamptz NOT NULL,
  service     text NOT NULL,
  event       text NOT NULL,
  token_label text,
  fp          text,
  data        jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
GRANT CONNECT ON DATABASE ledger TO ledger_writer, portal;
GRANT INSERT ON events TO ledger_writer;
GRANT USAGE ON SEQUENCE events_id_seq TO ledger_writer;
GRANT SELECT ON events TO portal;
