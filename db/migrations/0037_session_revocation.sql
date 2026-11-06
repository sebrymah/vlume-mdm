-- 0037_session_revocation.sql
-- Signing one person out.
--
-- Sessions are signed tokens, not rows, so there is nothing to delete.
-- Tenant-wide revocation compares a session's start against a stamp on
-- the tenant; this is the same idea one person at a time: a stamp on the
-- person's row in tenant_admins, compared on every request against the
-- session's start, which renewal never moves. A person with no row yet
-- gets one when they are signed out, lapsed (so it takes no seat), so
-- anyone can be signed out by subject, seat or no seat.

BEGIN;

ALTER TABLE tenant_admins
  ADD COLUMN IF NOT EXISTS sessions_invalid_before timestamptz NOT NULL DEFAULT to_timestamp(0);

COMMIT;
