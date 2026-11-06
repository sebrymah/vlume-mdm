-- 0021_plans_metering.sql
-- T8 plans and quotas, T9 usage metering.
--
-- QUOTAS live on the tenant row (0003 said why: a quota outside the
-- database disagrees with the invoice). This adds the admin-seat count and
-- the feature flags, and ENFORCES the device cap where it cannot be
-- forgotten: a trigger on devices. The application refuses first, with a
-- message; the trigger refuses second, for any writer that forgets.
--
-- METERING is the one place the operator legitimately needs numbers from
-- inside tenants, and the one place it must not get rows. app.tenant_usage
-- is SECURITY DEFINER, owned by mdm_meter, a role nobody can log in as
-- whose one property is that row-level security does not apply to it. The
-- function returns counts and bytes and nothing else; the operator may
-- EXECUTE it and still cannot SELECT from devices, which the probe test
-- keeps proving. The bypass is contained to the body of one function whose
-- output has no names in it. usage_snapshots is history for billing (SD
-- 10: no existing table holds counts over time).

BEGIN;

ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS admin_seats integer NOT NULL DEFAULT 3,
  ADD COLUMN IF NOT EXISTS features    jsonb   NOT NULL DEFAULT '{}'::jsonb;

UPDATE tenants SET admin_seats = 10 WHERE plan = 'growth' AND admin_seats = 3;
UPDATE tenants SET admin_seats = 50 WHERE plan = 'scale'  AND admin_seats = 3;

-- ---------------------------------------------------------------- the cap
CREATE OR REPLACE FUNCTION app.check_device_cap() RETURNS trigger AS $$
DECLARE cap integer; have integer;
BEGIN
  SELECT device_cap INTO cap FROM tenants WHERE id = NEW.tenant_id;
  SELECT count(*) INTO have FROM devices
   WHERE tenant_id = NEW.tenant_id AND state <> 'retired';
  IF have >= cap THEN
    RAISE EXCEPTION 'device cap reached: % of % devices are in use (tenant %)', have, cap, NEW.tenant_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS device_cap ON devices;
CREATE TRIGGER device_cap
  BEFORE INSERT ON devices
  FOR EACH ROW EXECUTE FUNCTION app.check_device_cap();

-- ---------------------------------------------------------------- metering
CREATE OR REPLACE FUNCTION app.tenant_usage(t uuid)
RETURNS TABLE (
  active_devices    bigint,
  enrolled_30d      bigint,
  commands_30d      bigint,
  notifications_30d bigint,
  storage_bytes     bigint
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
      + (SELECT coalesce(sum(pg_column_size(n.*)), 0) FROM notifications n WHERE n.tenant_id = t)
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, app;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_meter') THEN
    CREATE ROLE mdm_meter NOLOGIN BYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO mdm_meter;
GRANT SELECT ON devices, device_compliance, audit_events, commands, notifications, tenants TO mdm_meter;
ALTER FUNCTION app.tenant_usage(uuid) OWNER TO mdm_meter;
REVOKE ALL ON FUNCTION app.tenant_usage(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.tenant_usage(uuid) TO mdm_operator;

CREATE TABLE IF NOT EXISTS usage_snapshots (
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  taken_on          date NOT NULL,
  active_devices    integer NOT NULL,
  enrolled_30d      integer NOT NULL,
  commands_30d      integer NOT NULL,
  notifications_30d integer NOT NULL,
  storage_bytes     bigint  NOT NULL,
  device_cap        integer NOT NULL,
  plan              text    NOT NULL,
  PRIMARY KEY (tenant_id, taken_on)
);
ALTER TABLE usage_snapshots OWNER TO mdm_owner;
GRANT SELECT, INSERT ON usage_snapshots TO mdm_operator;
-- Not the application role: a tenant's console has no business reading
-- the operator's billing history, including its own.

COMMIT;
