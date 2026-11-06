-- 0027_apps_escrow.sql
-- F3 installed-app inventory, F11 recovery-key escrow.
--
-- APPS: what a device reports it has installed, replaced wholesale on each
-- report, so the table is the device's current list and nothing older. An
-- administrator asks "who has Zoom 5.x" across the fleet; the answer is a
-- query on this table under row-level security like any other.
--
-- ESCROW: the disk-encryption recovery key, handed up by the agent and
-- sealed under the tenant's key. Revealing it is a separate act with a
-- reason, by the roles that hold key.retrieve, and every reveal is counted
-- on the row and written to the audit log: a recovery key that has been
-- looked at is a recovery key that has been looked at.

BEGIN;

CREATE TABLE IF NOT EXISTS device_apps (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  device_id  uuid NOT NULL,
  identifier text NOT NULL,
  name       text NOT NULL,
  version    text NOT NULL DEFAULT '',
  seen_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, device_id, identifier),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE device_apps OWNER TO mdm_owner;
ALTER TABLE device_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_apps FORCE ROW LEVEL SECURITY;
CREATE POLICY device_apps_tenant_isolation ON device_apps
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_apps TO mdm_app;
CREATE INDEX IF NOT EXISTS device_apps_by_name ON device_apps (tenant_id, lower(name));

CREATE TABLE IF NOT EXISTS device_recovery_keys (
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  device_id      uuid NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('filevault','bitlocker','other')),
  key_sealed     bytea NOT NULL,
  escrowed_at    timestamptz NOT NULL DEFAULT now(),
  revealed_count integer NOT NULL DEFAULT 0,
  last_revealed_at timestamptz,
  PRIMARY KEY (tenant_id, device_id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE device_recovery_keys OWNER TO mdm_owner;
ALTER TABLE device_recovery_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_recovery_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY device_recovery_keys_tenant_isolation ON device_recovery_keys
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON device_recovery_keys TO mdm_app;

GRANT SELECT, DELETE ON device_apps, device_recovery_keys TO mdm_reaper;
CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_certificates',
               'device_apps','device_recovery_keys',
               'enrolments','devices','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','tenant_domains','tenant_keys']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
