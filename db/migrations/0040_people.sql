-- 0040: the people the platform has met.
--
-- 0009 said there must be no people table, because this platform holds no
-- directory: a tenant's people live at its identity provider. That is
-- still true, and this table is not a directory. It is the record of who
-- the platform has actually met: a person who signed in (their subject,
-- the one identifier the provider never reuses), a person an administrator
-- assigned a device to by typing an address, a person HR said has left.
-- One row per person, kept after they leave, so a device assigned to a
-- leaver stays assigned to THAT leaver, and an address reused by the next
-- hire does not inherit it. That is the limit 0009 wrote down and this
-- closes.
--
-- The link from a device is a foreign key to the row, and the row is
-- matched by subject first and by email only while nobody with that email
-- has left. assigned_to stays, as what was typed; the key beside it is
-- what the device is assigned to.

BEGIN;

CREATE TABLE IF NOT EXISTS people (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  subject     text NOT NULL DEFAULT '',
  email       text NOT NULL DEFAULT '',
  name        text NOT NULL DEFAULT '',
  source      text NOT NULL CHECK (source IN ('sign_in','assignment','hr')),
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  left_at     timestamptz,
  left_by     text,
  left_reason text,
  CHECK (subject <> '' OR email <> ''),
  CHECK (email = lower(email)),
  CHECK (left_at IS NULL OR (left_by IS NOT NULL AND left_by <> '')),
  UNIQUE (tenant_id, id)
);
ALTER TABLE people OWNER TO mdm_owner;
ALTER TABLE people ENABLE ROW LEVEL SECURITY;
ALTER TABLE people FORCE ROW LEVEL SECURITY;
CREATE POLICY people_tenant_isolation ON people
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON people TO mdm_app;
GRANT SELECT, DELETE ON people TO mdm_reaper;

-- One active person per subject, and one per email. A person who has
-- left holds neither, so the next hire with the same address is a new row.
CREATE UNIQUE INDEX IF NOT EXISTS people_active_subject
  ON people (tenant_id, subject) WHERE subject <> '' AND left_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS people_active_email
  ON people (tenant_id, email) WHERE email <> '' AND left_at IS NULL;

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS person_id uuid;
ALTER TABLE devices
  DROP CONSTRAINT IF EXISTS devices_person_fk;
ALTER TABLE devices
  ADD CONSTRAINT devices_person_fk FOREIGN KEY (tenant_id, person_id)
  REFERENCES people (tenant_id, id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS devices_by_person_id ON devices (tenant_id, person_id) WHERE person_id IS NOT NULL;

ALTER TABLE enrolments
  ADD COLUMN IF NOT EXISTS person_id uuid;
ALTER TABLE enrolments
  DROP CONSTRAINT IF EXISTS enrolments_person_fk;
ALTER TABLE enrolments
  ADD CONSTRAINT enrolments_person_fk FOREIGN KEY (tenant_id, person_id)
  REFERENCES people (tenant_id, id) ON DELETE SET NULL;

-- What was typed before this, turned into people. An address is an email;
-- anything else is taken as the provider's subject.
INSERT INTO people (tenant_id, subject, email, source)
SELECT DISTINCT tenant_id,
       CASE WHEN assigned_to LIKE '%@%' THEN '' ELSE assigned_to END,
       CASE WHEN assigned_to LIKE '%@%' THEN lower(assigned_to) ELSE '' END,
       'assignment'
  FROM (SELECT tenant_id, assigned_to FROM devices WHERE assigned_to <> ''
        UNION
        SELECT tenant_id, assigned_to FROM enrolments WHERE assigned_to <> '') typed
ON CONFLICT DO NOTHING;

UPDATE devices d SET person_id = p.id
  FROM people p
 WHERE d.person_id IS NULL AND d.assigned_to <> '' AND p.tenant_id = d.tenant_id AND p.left_at IS NULL
   AND ((d.assigned_to LIKE '%@%' AND p.email = lower(d.assigned_to))
     OR (d.assigned_to NOT LIKE '%@%' AND p.subject = d.assigned_to));

UPDATE enrolments e SET person_id = p.id
  FROM people p
 WHERE e.person_id IS NULL AND e.assigned_to <> '' AND p.tenant_id = e.tenant_id AND p.left_at IS NULL
   AND ((e.assigned_to LIKE '%@%' AND p.email = lower(e.assigned_to))
     OR (e.assigned_to NOT LIKE '%@%' AND p.subject = e.assigned_to));

-- Devices and enrolments are deleted before people when a tenant goes:
-- the list is walked in order, and the key is SET NULL in any case.
CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_certificates',
               'device_apps','device_recovery_keys','device_macs',
               'enrolments','devices','people','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','tenant_domains','tenant_keys','tenant_admins',
               'command_signing_keys']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
