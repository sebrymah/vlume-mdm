-- 0036_signing_keys.sql
-- Command signing keys, stored.
--
-- Every command a device acts on is signed by its tenant's key, and the
-- device verifies the signature before it does anything. Until now the key
-- lived in memory (the development provider): gone at a restart, never
-- rotated, unprotected. Now it is a row per tenant and version, the
-- private half sealed under the tenant's own key, the public half in the
-- clear for the device route, under row-level security like everything
-- else of the tenant's. Rotation makes a new version and keeps the old
-- one, because a command signed yesterday is still on its way to a laptop
-- that was off.

BEGIN;

CREATE TABLE IF NOT EXISTS command_signing_keys (
  tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  version            integer NOT NULL CHECK (version > 0),
  private_key_sealed bytea NOT NULL,
  public_key         bytea NOT NULL,          -- PKIX DER
  created_at         timestamptz NOT NULL DEFAULT now(),
  retired_at         timestamptz,
  PRIMARY KEY (tenant_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS command_signing_keys_one_current
  ON command_signing_keys (tenant_id) WHERE retired_at IS NULL;
ALTER TABLE command_signing_keys OWNER TO mdm_owner;
ALTER TABLE command_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE command_signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY command_signing_keys_tenant_isolation ON command_signing_keys
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON command_signing_keys TO mdm_app;
GRANT SELECT, DELETE ON command_signing_keys TO mdm_reaper;
GRANT SELECT, INSERT ON command_signing_keys TO mdm_importer;

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_certificates',
               'device_apps','device_recovery_keys',
               'enrolments','devices','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','tenant_domains','tenant_keys','tenant_admins',
               'command_signing_keys']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
