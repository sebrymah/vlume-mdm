-- 0026_tenant_keys.sql
-- T3: one key per tenant, rotated on its own.
--
-- Until now every sealed value (identity client secrets, notification
-- endpoints, DKIM keys, the device-signing key) was sealed under the one
-- platform key. Rotating that key meant re-sealing every tenant's rows at
-- once, which is the opposite of "one tenant's rotation touches only its
-- data". Now each tenant has its own data key, generated when the tenant
-- is created, sealed under the platform's master key, and used for every
-- value of that tenant's. A sealed value says which version sealed it.
-- Rotation makes a new version, re-seals this tenant's values under it,
-- and retires the old one; nothing of any other tenant's moves.
--
-- Values sealed before this migration are under the master key in the
-- old format; they still open, and are re-sealed under the tenant's key
-- the first time that tenant rotates.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_keys (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  version    integer NOT NULL CHECK (version > 0),
  key_sealed bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  PRIMARY KEY (tenant_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS tenant_keys_one_current
  ON tenant_keys (tenant_id) WHERE retired_at IS NULL;

ALTER TABLE tenant_keys OWNER TO mdm_owner;
ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_keys_tenant_isolation ON tenant_keys
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_keys TO mdm_app;
-- The operator seeds version 1 at creation and reads nothing back.
GRANT INSERT ON tenant_keys TO mdm_operator;
CREATE POLICY tenant_keys_operator_seed ON tenant_keys
  FOR INSERT TO mdm_operator WITH CHECK (true);
GRANT SELECT, DELETE ON tenant_keys TO mdm_reaper;

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_certificates',
               'enrolments','devices','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','tenant_domains','tenant_keys']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
