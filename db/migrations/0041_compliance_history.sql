-- 0041: what a device's verdict was, and what the fleet looked like, over time.
--
-- device_compliance holds one row per device: the latest report and the
-- latest verdict. That answers "how is this laptop" and never "when did it
-- stop being fine". Two things close that.
--
-- A verdict history: one row per device per CHANGE of verdict (its state,
-- or which rules were failing or unreadable). A device reporting the same
-- thing every fifteen minutes adds nothing; the day it fails adds a row,
-- and the day it is put right adds another. Written in the same
-- transaction as the verdict, from the same evaluation.
--
-- A fleet snapshot: the dashboard's counts, once a day per tenant, taken
-- by the gateway under a tenant claim, because the operator's own role may
-- not read devices (--break-operatorreach) and so the usage snapshot job,
-- which runs on the operator's pool, cannot take this one.

BEGIN;

CREATE TABLE IF NOT EXISTS device_compliance_history (
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  device_id    uuid NOT NULL,
  reported_at  timestamptz NOT NULL,
  evaluated_at timestamptz NOT NULL,
  state        text NOT NULL CHECK (state IN ('compliant','not_compliant','state_unknown')),
  findings     jsonb NOT NULL DEFAULT '[]'::jsonb,
  policies     jsonb NOT NULL DEFAULT '[]'::jsonb,
  PRIMARY KEY (tenant_id, device_id, evaluated_at),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE device_compliance_history OWNER TO mdm_owner;
ALTER TABLE device_compliance_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_compliance_history FORCE ROW LEVEL SECURITY;
CREATE POLICY device_compliance_history_tenant_isolation ON device_compliance_history
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, DELETE ON device_compliance_history TO mdm_app;
GRANT SELECT, DELETE ON device_compliance_history TO mdm_reaper;

CREATE TABLE IF NOT EXISTS compliance_snapshots (
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  taken_on      date NOT NULL,
  total         integer NOT NULL,
  compliant     integer NOT NULL,
  not_compliant integer NOT NULL,
  state_unknown integer NOT NULL,
  quarantined   integer NOT NULL,
  never_seen    integer NOT NULL,
  PRIMARY KEY (tenant_id, taken_on)
);
ALTER TABLE compliance_snapshots OWNER TO mdm_owner;
ALTER TABLE compliance_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY compliance_snapshots_tenant_isolation ON compliance_snapshots
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_snapshots TO mdm_app;
GRANT SELECT, DELETE ON compliance_snapshots TO mdm_reaper;

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_compliance_history','device_certificates',
               'device_apps','device_recovery_keys','device_macs',
               'enrolments','devices','people','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','compliance_snapshots','tenant_domains','tenant_keys','tenant_admins',
               'command_signing_keys']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
