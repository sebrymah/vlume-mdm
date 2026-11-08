-- 0048: the platform owner's own accounts, and a record of what they do.
--
-- Until now the owner of the platform had no sign-in of its own: it ran a
-- command-line tool on the server. This gives it a web console, and a console
-- needs people who can sign in to it. These are NOT tenant people. They belong
-- to no organisation, there is no tenant_id on any row here, and the
-- application role that serves every organisation's console is granted
-- NOTHING on these tables, so a bug in any customer-facing page cannot read an
-- owner's password hash or authenticator secret. Only the operator role, the
-- one the command-line tool already uses, can.
--
-- Two things are stricter than the customer version of the same idea:
--   * an active owner account ALWAYS has its second factor. The database
--     refuses an active account without one, so there is no way to be signed
--     in to this console on a password alone, whatever the code says;
--   * there is no "forgot my password" by email. A reset is a link another
--     owner (or the command line) makes, because the mailbox of an account that
--     can suspend every customer should not be the only thing guarding it.

BEGIN;

CREATE TABLE IF NOT EXISTS operator_accounts (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email              text NOT NULL UNIQUE CHECK (email <> '' AND email = lower(email)),
  name               text NOT NULL DEFAULT '',
  status             text NOT NULL DEFAULT 'invited' CHECK (status IN ('invited', 'active', 'disabled')),
  password_hash      text NOT NULL DEFAULT '',
  password_set_at    timestamptz,
  totp_secret_sealed bytea,
  totp_enabled       boolean NOT NULL DEFAULT false,
  totp_last_step     bigint NOT NULL DEFAULT 0,
  recovery_hashes    text[] NOT NULL DEFAULT '{}',
  failed_count       integer NOT NULL DEFAULT 0,
  locked_until       timestamptz,
  created_by         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  last_sign_in_at    timestamptz,
  CHECK (status <> 'active' OR (password_hash <> '' AND totp_enabled)),
  CHECK (NOT totp_enabled OR totp_secret_sealed IS NOT NULL)
);
ALTER TABLE operator_accounts OWNER TO mdm_owner;
GRANT SELECT, INSERT, UPDATE ON operator_accounts TO mdm_operator;

-- An invitation, or a password reset: 256 random bits in a link, kept as their
-- SHA-256, good once and for a limited time.
CREATE TABLE IF NOT EXISTS operator_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id  uuid NOT NULL REFERENCES operator_accounts(id) ON DELETE CASCADE,
  purpose     text NOT NULL CHECK (purpose IN ('invite', 'reset')),
  token_hash  bytea NOT NULL UNIQUE,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE operator_tokens OWNER TO mdm_owner;
GRANT SELECT, INSERT, UPDATE ON operator_tokens TO mdm_operator;
CREATE INDEX IF NOT EXISTS operator_tokens_by_account ON operator_tokens (account_id, purpose);

-- What owners do. Append-only: the operator role can add a line and read them,
-- and can neither change nor remove one, so the record of who suspended whom,
-- who changed whose plan, cannot be tidied afterwards by the person it is about.
CREATE TABLE IF NOT EXISTS operator_events (
  id      bigserial PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  actor   text NOT NULL CHECK (actor <> ''),
  action  text NOT NULL CHECK (action <> ''),
  target  text NOT NULL DEFAULT '',
  detail  text NOT NULL DEFAULT ''
);
ALTER TABLE operator_events OWNER TO mdm_owner;
GRANT SELECT, INSERT ON operator_events TO mdm_operator;
GRANT USAGE ON SEQUENCE operator_events_id_seq TO mdm_operator;
CREATE INDEX IF NOT EXISTS operator_events_by_time ON operator_events (at DESC);

COMMIT;
