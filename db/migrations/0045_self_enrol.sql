-- 0045: people enrol their own phone.
--
-- Until now a device got a token because an administrator made one, one at a
-- time. For a few hundred people that is a week of typing. This lets an
-- organisation send everybody ONE link; each person signs in, and gets a code
-- for their own phone, tied to their own address.
--
-- What is stored:
--   tenant_enrolment   one row per tenant: whether people may do this at all,
--                      and for which kind of phone. Off until an administrator
--                      turns it on.
--   android_enrollment_tokens.source
--                      who asked for the token: an administrator, or the
--                      person themselves. The per-person limit counts the
--                      second kind only, so an IT admin issuing fifty tokens
--                      for a team is not stopped by a limit meant for a
--                      stranger-proofing a self-service page.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_enrolment (
  tenant_id   uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
  -- off:      nobody enrols themselves
  -- personal: a person's own phone, as a work profile
  -- any:      that, or a new company phone set up at the welcome screen
  self_enrol  text NOT NULL DEFAULT 'off' CHECK (self_enrol IN ('off', 'personal', 'any')),
  updated_by  text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenant_enrolment OWNER TO mdm_owner;
ALTER TABLE tenant_enrolment ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_enrolment FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_enrolment_tenant_isolation ON tenant_enrolment
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_enrolment TO mdm_app;
GRANT SELECT, DELETE ON tenant_enrolment TO mdm_reaper;

ALTER TABLE android_enrollment_tokens
  ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'admin'
  CHECK (source IN ('admin', 'self'));
CREATE INDEX IF NOT EXISTS android_tokens_self_by_person
  ON android_enrollment_tokens (tenant_id, created_by, created_at) WHERE source = 'self';

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_compliance_history','device_certificates',
               'device_apps','device_recovery_keys','device_macs',
               'enrolments','devices','people','local_tokens','local_accounts','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','compliance_snapshots','tenant_domains','tenant_keys','tenant_admins',
               'command_signing_keys','tenant_enrolment']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
