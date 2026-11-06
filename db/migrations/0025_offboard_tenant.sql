-- 0025_offboard_tenant.sql
-- T10: a tenant leaves, and the deletion is verified.
--
-- Three steps, each the operator's, each deliberate: suspend (visitors are
-- told, nothing runs), export (the tenant's Super Admin downloads
-- everything from the console while the status says exporting), offboard
-- (every row of theirs is deleted, every key of theirs with it, and the
-- residue is counted and must be zero).
--
-- The deletion runs as mdm_reaper, a role nobody can log in as, which
-- holds DELETE on every tenant table and nothing else, through ONE
-- function the operator may execute only once the tenant is suspended or
-- exporting. Key destruction is literal: tenant_ca holds the sealed
-- device-signing key, tenant_identity the sealed client secret,
-- sending_domains the sealed DKIM key, notification_targets the sealed
-- endpoints; all four tables are emptied for the tenant. The tenants row
-- itself stays, status offboarded, with no hostname, as the billing
-- record that a tenant existed. offboarding_log is the operator's proof.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_reaper') THEN
    CREATE ROLE mdm_reaper NOLOGIN BYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO mdm_reaper;
GRANT SELECT, DELETE ON
  command_approvals, commands, device_compliance, device_certificates, enrolments, devices,
  policies, audit_events, tenant_branding, tenant_identity, tenant_role_map, tenant_ca,
  notification_targets, notifications, sending_domains, integration_tokens,
  android_enrollment_tokens, android_enterprises, siem_cursors, signups, usage_snapshots,
  tenant_domains
  TO mdm_reaper;
GRANT SELECT, UPDATE ON tenants TO mdm_reaper;

CREATE TABLE IF NOT EXISTS offboarding_log (
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  slug        text NOT NULL,
  offboarded_at timestamptz NOT NULL DEFAULT now(),
  offboarded_by text NOT NULL,
  deleted     jsonb NOT NULL,
  residue     bigint NOT NULL,
  PRIMARY KEY (tenant_id, offboarded_at)
);
ALTER TABLE offboarding_log OWNER TO mdm_owner;
GRANT SELECT, INSERT ON offboarding_log TO mdm_operator;

-- Every tenant table, in an order foreign keys allow.
CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_certificates',
               'enrolments','devices','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','tenant_domains']
$$ LANGUAGE sql IMMUTABLE;

-- The deletion. Refuses an active tenant: suspension first, on purpose.
CREATE OR REPLACE FUNCTION app.offboard_tenant(t uuid)
RETURNS TABLE (table_name text, deleted bigint) AS $$
DECLARE tbl text; n bigint; st text;
BEGIN
  SELECT status INTO st FROM tenants WHERE id = t;
  IF st IS NULL THEN
    RAISE EXCEPTION 'no such tenant %', t;
  END IF;
  IF st NOT IN ('suspended','exporting') THEN
    RAISE EXCEPTION 'tenant % is %, not suspended or exporting: suspend it first', t, st
      USING ERRCODE = 'check_violation';
  END IF;
  -- The audit chain refuses deletes from the application role by trigger;
  -- the reaper is not that role, and this is the one deletion that is
  -- meant.
  FOREACH tbl IN ARRAY app.tenant_tables() LOOP
    EXECUTE format('DELETE FROM %I WHERE tenant_id = $1', tbl) USING t;
    GET DIAGNOSTICS n = ROW_COUNT;
    table_name := tbl; deleted := n;
    RETURN NEXT;
  END LOOP;
  UPDATE tenants SET status = 'offboarded', features = '{}'::jsonb WHERE id = t;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, app;

-- The proof: rows left anywhere for this tenant. Must be zero.
CREATE OR REPLACE FUNCTION app.tenant_residue(t uuid)
RETURNS TABLE (table_name text, remaining bigint) AS $$
DECLARE tbl text; n bigint;
BEGIN
  FOREACH tbl IN ARRAY app.tenant_tables() LOOP
    EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id = $1', tbl) INTO n USING t;
    table_name := tbl; remaining := n;
    RETURN NEXT;
  END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, app;

ALTER FUNCTION app.offboard_tenant(uuid) OWNER TO mdm_reaper;
ALTER FUNCTION app.tenant_residue(uuid) OWNER TO mdm_reaper;
REVOKE ALL ON FUNCTION app.offboard_tenant(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.tenant_residue(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.offboard_tenant(uuid) TO mdm_operator;
GRANT EXECUTE ON FUNCTION app.tenant_residue(uuid) TO mdm_operator;

COMMIT;
