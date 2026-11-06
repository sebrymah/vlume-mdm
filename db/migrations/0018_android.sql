-- 0018_android.sql
-- Android Enterprise: the Google half of the vendor dependency.
--
-- Android devices are managed through Google's Android Management API. The
-- operator holds ONE service account for the platform; each tenant binds
-- its OWN enterprise to it by signing in with a Google account, so what a
-- tenant's devices do is decided under that tenant's enterprise and nobody
-- else's. This migration records the binding and the enrolment tokens the
-- API hands out, and gives a device the name Google knows it by.
--
-- What is NOT here: a credential. The service account lives with the
-- operator's configuration, never in a tenant table, and the enrolment
-- token's VALUE is shown once and not stored: a copy of this table is not
-- a way to enrol a device.

BEGIN;

CREATE TABLE IF NOT EXISTS android_enterprises (
  tenant_id     uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
  -- Google's resource name, enterprises/LC0123abcd.
  name          text NOT NULL UNIQUE,
  display_name  text NOT NULL,
  bound_by      text NOT NULL,
  bound_at      timestamptz NOT NULL DEFAULT now(),
  last_synced_at timestamptz,
  last_sync_error text
);

ALTER TABLE android_enterprises OWNER TO mdm_owner;
ALTER TABLE android_enterprises ENABLE ROW LEVEL SECURITY;
ALTER TABLE android_enterprises FORCE ROW LEVEL SECURITY;
CREATE POLICY android_enterprises_tenant_isolation ON android_enterprises
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON android_enterprises TO mdm_app;

CREATE TABLE IF NOT EXISTS android_enrollment_tokens (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  -- Google's resource name for the token, so a device that enrolled with
  -- it can be matched back to who it was made for.
  name          text NOT NULL UNIQUE,
  label         text NOT NULL,
  assigned_to   text NOT NULL DEFAULT '',
  ownership     text NOT NULL DEFAULT 'company'
                CHECK (ownership IN ('company','personal')),
  created_by    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);

ALTER TABLE android_enrollment_tokens OWNER TO mdm_owner;
ALTER TABLE android_enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE android_enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY android_enrollment_tokens_tenant_isolation ON android_enrollment_tokens
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON android_enrollment_tokens TO mdm_app;

-- The name Google knows a device by: enterprises/X/devices/Y. Commands go
-- to that name, and a sync matches on it.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS android_name text;
CREATE UNIQUE INDEX IF NOT EXISTS devices_android_name
  ON devices (tenant_id, android_name) WHERE android_name IS NOT NULL;

COMMIT;
