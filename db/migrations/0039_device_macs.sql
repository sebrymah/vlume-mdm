-- 0039: the hardware addresses a device reports, for the network's door.
--
-- A network access control (NAC) knows a device by the MAC address it
-- authenticated with (RADIUS Calling-Station-Id), not by its serial. The
-- agent reports its interfaces' hardware addresses with every report; the
-- feed answers by either. One MAC belongs to one device per tenant: a MAC
-- reported by a second device moves to it, because the latest report is
-- the truth about where that interface is, and the move is audited.

BEGIN;

CREATE TABLE IF NOT EXISTS device_macs (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  device_id  uuid NOT NULL,
  mac        text NOT NULL CHECK (mac ~ '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'),
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, mac),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE device_macs OWNER TO mdm_owner;
ALTER TABLE device_macs ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_macs FORCE ROW LEVEL SECURITY;
CREATE POLICY device_macs_tenant_isolation ON device_macs
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_macs TO mdm_app;
CREATE INDEX IF NOT EXISTS device_macs_by_device ON device_macs (tenant_id, device_id);
GRANT SELECT, DELETE ON device_macs TO mdm_reaper;

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_certificates',
               'device_apps','device_recovery_keys','device_macs',
               'enrolments','devices','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','tenant_domains','tenant_keys','tenant_admins',
               'command_signing_keys']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
