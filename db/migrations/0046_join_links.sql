-- 0046: join links.
--
-- A link anyone can open, protected by a six-digit code sent by a different
-- route, with a limit on how many devices it will enrol and how long it lasts.
-- A single phone is a link with a limit of one; a field team of five hundred is
-- a link with a limit of five hundred. Neither needs the person to have an
-- account.
--
-- What is stored, and what is not:
--   secret_hash  SHA-256 of the 256-bit secret in the link. A copy of this
--                table is not a set of working links.
--   code_hash    argon2id of the six-digit code. Six digits is a small space,
--                so the hash is slow on purpose, and guessing is also limited
--                (failed_count / locked_until) so nobody gets to try a million.
--   Google's enrolment token is NOT stored here and is not made until a
--   correct code is entered: each successful use makes a fresh one-time token.
--   That is how the device limit is enforced, because Google cannot count.

BEGIN;

CREATE TABLE IF NOT EXISTS join_links (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name          text NOT NULL CHECK (name <> '' AND char_length(name) <= 80),
  secret_hash   bytea NOT NULL UNIQUE,
  code_hash     text NOT NULL,
  ownership     text NOT NULL CHECK (ownership IN ('company', 'personal')),
  -- Only for a link meant for one named person; empty for a team.
  assigned_to   text NOT NULL DEFAULT '',
  max_uses      integer NOT NULL CHECK (max_uses BETWEEN 1 AND 5000),
  uses          integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
  expires_at    timestamptz NOT NULL,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'cancelled')),
  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  cancelled_by  text,
  cancelled_at  timestamptz,
  -- Wrong-code accounting: ten wrong tries inside an hour pause the link for
  -- an hour. Per link, not per person, because the people are strangers.
  failed_count  integer NOT NULL DEFAULT 0,
  failed_since  timestamptz,
  locked_until  timestamptz,
  CHECK (uses <= max_uses),
  CHECK (status = 'active' OR (cancelled_by IS NOT NULL AND cancelled_at IS NOT NULL))
);
ALTER TABLE join_links OWNER TO mdm_owner;
ALTER TABLE join_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE join_links FORCE ROW LEVEL SECURITY;
CREATE POLICY join_links_tenant_isolation ON join_links
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
-- No DELETE for the application: a cancelled or finished link stays, so the
-- devices that came through it can still be traced to it.
GRANT SELECT, INSERT, UPDATE ON join_links TO mdm_app;
GRANT SELECT, DELETE ON join_links TO mdm_reaper;
CREATE INDEX IF NOT EXISTS join_links_by_tenant ON join_links (tenant_id, created_at DESC);

-- Which link a token came from, and a third source for it.
ALTER TABLE android_enrollment_tokens DROP CONSTRAINT IF EXISTS android_enrollment_tokens_source_check;
ALTER TABLE android_enrollment_tokens
  ADD CONSTRAINT android_enrollment_tokens_source_check CHECK (source IN ('admin', 'self', 'join'));
ALTER TABLE android_enrollment_tokens ADD COLUMN IF NOT EXISTS join_id uuid REFERENCES join_links(id);
CREATE INDEX IF NOT EXISTS android_tokens_by_join ON android_enrollment_tokens (join_id) WHERE join_id IS NOT NULL;

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_compliance_history','device_certificates',
               'device_apps','device_recovery_keys','device_macs',
               'enrolments','devices','people','local_tokens','local_accounts','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','compliance_snapshots','tenant_domains','tenant_keys','tenant_admins',
               'command_signing_keys','tenant_enrolment','join_links']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
