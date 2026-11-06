-- 0032_admin_seats.sql
-- T8: administrator seats, enforced.
--
-- A seat is a person with an administrative role (anything but employee)
-- who has signed in within the last 30 days. The plan says how many a
-- tenant has. Nobody is listed here until they sign in, because the
-- identity provider owns the people: this table is the console's own
-- memory of who has used it, inside row-level security like everything
-- else of the tenant's. Employees never take a seat; the self-service
-- role is part of every plan, not a thing that is counted.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_admins (
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  subject       text NOT NULL,
  email         text NOT NULL DEFAULT '',
  name          text NOT NULL DEFAULT '',
  role          text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject)
);
ALTER TABLE tenant_admins OWNER TO mdm_owner;
ALTER TABLE tenant_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_admins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_admins_tenant_isolation ON tenant_admins
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_admins TO mdm_app;
GRANT SELECT, DELETE ON tenant_admins TO mdm_reaper;
CREATE INDEX IF NOT EXISTS tenant_admins_by_seen ON tenant_admins (tenant_id, last_seen_at);

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_certificates',
               'device_apps','device_recovery_keys',
               'enrolments','devices','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','tenant_domains','tenant_keys','tenant_admins']
$$ LANGUAGE sql IMMUTABLE;

-- ---------------------------------------------------------------- metering
-- Seats in use is a billing number like the others, so it comes out of the
-- same function. The return type changes, so the function is replaced.
GRANT SELECT ON tenant_admins TO mdm_meter;
DROP FUNCTION IF EXISTS app.tenant_usage(uuid);
CREATE FUNCTION app.tenant_usage(t uuid)
RETURNS TABLE (
  active_devices    bigint,
  enrolled_30d      bigint,
  commands_30d      bigint,
  notifications_30d bigint,
  storage_bytes     bigint,
  admin_seats_used  bigint
) AS $$
  SELECT
    (SELECT count(*) FROM devices WHERE tenant_id = t AND state <> 'retired'),
    (SELECT count(*) FROM devices WHERE tenant_id = t AND created_at > now() - interval '30 days'),
    (SELECT count(*) FROM commands WHERE tenant_id = t AND requested_at > now() - interval '30 days'),
    (SELECT count(*) FROM notifications WHERE tenant_id = t AND created_at > now() - interval '30 days'),
    (SELECT coalesce(sum(pg_column_size(d.*)), 0) FROM devices d WHERE d.tenant_id = t)
      + (SELECT coalesce(sum(pg_column_size(c.*)), 0) FROM device_compliance c WHERE c.tenant_id = t)
      + (SELECT coalesce(sum(pg_column_size(a.*)), 0) FROM audit_events a WHERE a.tenant_id = t)
      + (SELECT coalesce(sum(pg_column_size(m.*)), 0) FROM commands m WHERE m.tenant_id = t)
      + (SELECT coalesce(sum(pg_column_size(n.*)), 0) FROM notifications n WHERE n.tenant_id = t),
    (SELECT count(*) FROM tenant_admins WHERE tenant_id = t AND last_seen_at > now() - interval '30 days')
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, app;
ALTER FUNCTION app.tenant_usage(uuid) OWNER TO mdm_meter;
REVOKE ALL ON FUNCTION app.tenant_usage(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.tenant_usage(uuid) TO mdm_operator;

ALTER TABLE usage_snapshots
  ADD COLUMN IF NOT EXISTS seats_used  integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS admin_seats integer NOT NULL DEFAULT 0;

COMMIT;
