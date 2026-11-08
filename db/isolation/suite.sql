-- suite.sql — requirement T13, the cross-tenant isolation suite.
--
-- The technical specification promotes this from a risk mitigation to a
-- requirement, because it is the control standing between the platform and
-- its worst outcome. It runs on every release. Any pass-through fails the
-- build. There is no override flag.
--
-- The fixture is two tenants with deliberately overlapping data: the same
-- device name, the same serial, the same policy name. If separation ever
-- depended on values happening to differ, these assertions would catch it.
--
-- Every assertion raises on failure, so a non-zero exit from psql is the
-- build gate.

\set ON_ERROR_STOP on
\set QUIET on

\set tenant_a '11111111-1111-1111-1111-111111111111'
\set tenant_b '22222222-2222-2222-2222-222222222222'
\set tenant_c '33333333-3333-3333-3333-333333333333'

RESET ROLE;

-- ---------------------------------------------------------------- fixture
DELETE FROM notifications;
DELETE FROM notification_targets;
DELETE FROM device_compliance;
DELETE FROM device_certificates;
DELETE FROM enrolments;
DELETE FROM tenant_ca;
DELETE FROM audit_events;
DELETE FROM devices;
DELETE FROM local_tokens;
DELETE FROM local_accounts;
DELETE FROM tenant_enrolment;
DELETE FROM people;
DELETE FROM compliance_snapshots;
DELETE FROM policies;
DELETE FROM tenant_role_map;
DELETE FROM tenant_identity;
DELETE FROM tenants WHERE id IN (:'tenant_a', :'tenant_b');

INSERT INTO tenants (id, name, slug, status) VALUES
  (:'tenant_a', 'Kalesi Foods',  'kalesi', 'active'),
  (:'tenant_b', 'Arbor Health',  'arbor',  'active');

-- Identical names and serials across both tenants, on purpose.
INSERT INTO devices (tenant_id, name, serial, os_family) VALUES
  (:'tenant_a', 'HQ-MBP-001', 'C02XK4YTQ6NV', 'macos'),
  (:'tenant_a', 'HQ-WIN-004', 'SN-00000004',  'windows'),
  (:'tenant_b', 'HQ-MBP-001', 'C02XK4YTQ6NV', 'macos'),
  (:'tenant_b', 'HQ-WIN-004', 'SN-00000004',  'windows'),
  (:'tenant_b', 'HQ-IPH-009', 'SN-00000009',  'ios');

-- The people the platform has met (0040), for the person isolation
-- assertions: one device of tenant A's is t.eze's, the other o.martins'.
INSERT INTO people (tenant_id, subject, email, source) VALUES
  (:'tenant_a', 't.eze',     't.eze@kalesi.example',     'assignment'),
  (:'tenant_a', 'o.martins', 'o.martins@kalesi.example', 'assignment');
UPDATE devices SET person_id = (SELECT id FROM people WHERE tenant_id = :'tenant_a' AND subject = 't.eze')
 WHERE tenant_id = :'tenant_a' AND name = 'HQ-MBP-001';
UPDATE devices SET person_id = (SELECT id FROM people WHERE tenant_id = :'tenant_a' AND subject = 'o.martins')
 WHERE tenant_id = :'tenant_a' AND name = 'HQ-WIN-004';

INSERT INTO policies (tenant_id, name, version) VALUES
  (:'tenant_a', 'Head office baseline', 1),
  (:'tenant_b', 'Head office baseline', 1);

INSERT INTO audit_events (tenant_id, actor, action, object_ref) VALUES
  (:'tenant_a', 'f.okonkwo', 'policy.created', 'Head office baseline'),
  (:'tenant_a', 'o.martins', 'device.locked',  'HQ-MBP-001'),
  (:'tenant_b', 'j.okafor',  'policy.created', 'Head office baseline');

\echo ''
\echo '=== T13 cross-tenant isolation suite ==='
\echo ''

-- ======================================================= group 1: reads
SET ROLE mdm_app;
DO $$ BEGIN PERFORM set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', false); END $$;

DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM devices;
  IF n <> 2 THEN
    RAISE EXCEPTION 'FAIL 1.1 tenant A should see 2 devices, saw %', n;
  END IF;
  RAISE NOTICE 'PASS 1.1  tenant A sees only its own 2 devices';
END $$;

DO $$
DECLARE n int;
BEGIN
  -- The forgotten WHERE clause. Identical serial exists in both tenants.
  SELECT count(*) INTO n FROM devices WHERE serial = 'C02XK4YTQ6NV';
  IF n <> 1 THEN
    RAISE EXCEPTION 'FAIL 1.2 a shared serial returned % rows, expected 1', n;
  END IF;
  RAISE NOTICE 'PASS 1.2  a serial held by both tenants returns one row, not two';
END $$;

DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM policies;
  IF n <> 1 THEN
    RAISE EXCEPTION 'FAIL 1.3 tenant A should see 1 policy, saw %', n;
  END IF;
  RAISE NOTICE 'PASS 1.3  an identically named policy in both tenants stays separate';
END $$;

DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM audit_events;
  IF n <> 2 THEN
    RAISE EXCEPTION 'FAIL 1.4 tenant A should see 2 audit rows, saw %', n;
  END IF;
  RAISE NOTICE 'PASS 1.4  audit log is tenant-scoped';
END $$;

-- ======================================================= group 2: fails closed
DO $$ BEGIN PERFORM set_config('app.tenant_id', '', false); END $$;

DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM devices;
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL 2.1 unset tenant returned % device rows, expected 0', n;
  END IF;
  RAISE NOTICE 'PASS 2.1  no tenant set returns nothing, rather than everything';
END $$;

DO $$ BEGIN PERFORM set_config('app.tenant_id', '33333333-3333-3333-3333-333333333333', false); END $$;

DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM devices;
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL 2.2 unknown tenant returned % device rows, expected 0', n;
  END IF;
  RAISE NOTICE 'PASS 2.2  a tenant id that owns nothing sees nothing';
END $$;

-- ======================================================= group 3: writes
DO $$ BEGIN PERFORM set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', false); END $$;

DO $$
BEGIN
  INSERT INTO devices (tenant_id, name, serial, os_family)
    VALUES ('22222222-2222-2222-2222-222222222222', 'planted', 'SN-PLANT', 'macos');
  RAISE EXCEPTION 'FAIL 3.1 tenant A inserted a row belonging to tenant B';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'PASS 3.1  tenant A cannot insert a row owned by tenant B';
END $$;

DO $$
DECLARE n int;
BEGIN
  UPDATE devices SET name = 'overwritten' WHERE serial = 'SN-00000009';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL 3.2 tenant A updated % of tenant B''s rows', n;
  END IF;
  RAISE NOTICE 'PASS 3.2  tenant A cannot update tenant B''s rows';
END $$;

DO $$
DECLARE n int;
BEGIN
  DELETE FROM devices WHERE serial = 'SN-00000009';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL 3.3 tenant A deleted % of tenant B''s rows', n;
  END IF;
  RAISE NOTICE 'PASS 3.3  tenant A cannot delete tenant B''s rows';
END $$;

-- ======================================================= group 4: append-only audit
DO $$
BEGIN
  UPDATE audit_events SET action = 'rewritten' WHERE true;
  RAISE EXCEPTION 'FAIL 4.1 the application role updated an audit record';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'PASS 4.1  the application role cannot update an audit record';
END $$;

DO $$
BEGIN
  DELETE FROM audit_events WHERE true;
  RAISE EXCEPTION 'FAIL 4.2 the application role deleted an audit record';
EXCEPTION WHEN insufficient_privilege THEN
  RAISE NOTICE 'PASS 4.2  the application role cannot delete an audit record';
END $$;

DO $$
DECLARE bad bigint;
BEGIN
  SELECT app.verify_audit_chain('11111111-1111-1111-1111-111111111111') INTO bad;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL 4.3 tenant A audit chain breaks at row %', bad;
  END IF;
  RAISE NOTICE 'PASS 4.3  tenant A audit chain verifies end to end';
END $$;

-- ======================================================= group 5: the structure itself
RESET ROLE;

DO $$
DECLARE bypass boolean;
BEGIN
  SELECT rolbypassrls INTO bypass FROM pg_roles WHERE rolname = 'mdm_app';
  IF bypass THEN
    RAISE EXCEPTION 'FAIL 5.1 mdm_app can bypass row-level security';
  END IF;
  RAISE NOTICE 'PASS 5.1  the application role cannot bypass row-level security';
END $$;

DO $$
DECLARE t text; missing text := '';
BEGIN
  FOREACH t IN ARRAY ARRAY['devices','policies','audit_events','tenant_branding',
                       'commands','command_approvals','tenant_identity','tenant_role_map',
                       'tenant_ca','device_certificates','enrolments','device_compliance',
                       'notification_targets','notifications','integration_tokens',
                       'android_enterprises','android_enrollment_tokens','siem_cursors','tenant_keys',
                       'device_apps','device_recovery_keys','tenant_admins','command_signing_keys',
                       'device_macs','people','device_compliance_history','compliance_snapshots',
                       'local_accounts','local_tokens','tenant_enrolment'] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class
       WHERE relname = t AND relrowsecurity AND relforcerowsecurity
    ) THEN
      missing := missing || t || ' ';
    END IF;
  END LOOP;
  IF missing <> '' THEN
    RAISE EXCEPTION 'FAIL 5.2 row-level security not enabled and forced on: %', missing;
  END IF;
  RAISE NOTICE 'PASS 5.2  every tenant-scoped table has row-level security enabled and forced';
END $$;

DO $$
DECLARE t text; missing text := '';
BEGIN
  FOREACH t IN ARRAY ARRAY['devices','policies','audit_events','tenant_branding',
                       'commands','command_approvals','tenant_identity','tenant_role_map',
                       'tenant_ca','device_certificates','enrolments','device_compliance',
                       'notification_targets','notifications','integration_tokens',
                       'android_enterprises','android_enrollment_tokens','siem_cursors','tenant_keys',
                       'device_apps','device_recovery_keys','tenant_admins','command_signing_keys',
                       'device_macs','people','device_compliance_history','compliance_snapshots',
                       'local_accounts','local_tokens','tenant_enrolment'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = t) THEN
      missing := missing || t || ' ';
    END IF;
  END LOOP;
  IF missing <> '' THEN
    RAISE EXCEPTION 'FAIL 5.3 no isolation policy on: %', missing;
  END IF;
  RAISE NOTICE 'PASS 5.3  every tenant-scoped table carries an isolation policy';
END $$;

DO $$
DECLARE t text; missing text := '';
BEGIN
  -- A tenant-scoped table without a non-null tenant_id is a table that will
  -- one day hold a row belonging to nobody.
  FOREACH t IN ARRAY ARRAY['devices','policies','audit_events','tenant_branding',
                       'commands','command_approvals','tenant_identity','tenant_role_map',
                       'tenant_ca','device_certificates','enrolments','device_compliance',
                       'notification_targets','notifications','integration_tokens',
                       'android_enterprises','android_enrollment_tokens','siem_cursors','tenant_keys',
                       'device_apps','device_recovery_keys','tenant_admins','command_signing_keys',
                       'device_macs','people','device_compliance_history','compliance_snapshots',
                       'local_accounts','local_tokens','tenant_enrolment'] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
       WHERE table_name = t AND column_name = 'tenant_id' AND is_nullable = 'NO'
    ) THEN
      missing := missing || t || ' ';
    END IF;
  END LOOP;
  IF missing <> '' THEN
    RAISE EXCEPTION 'FAIL 5.4 tenant_id missing or nullable on: %', missing;
  END IF;
  RAISE NOTICE 'PASS 5.4  tenant_id is present and not null on every tenant-scoped table';
END $$;

-- ------------------------------------------- 6. person isolation (0042)
--
-- Inside a tenant, an employee's transaction is held to the devices of
-- the person it belongs to by the database itself, whatever the SQL
-- asks for. Every other role reads the tenant.

SET ROLE mdm_app;
DO $$ BEGIN
  PERFORM set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', false);
  PERFORM set_config('app.role', 'employee', false);
  PERFORM set_config('app.subject', 't.eze', false);
  PERFORM set_config('app.email', 't.eze@kalesi.example', false);
END $$;

DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM devices;
  IF n <> 1 THEN
    RAISE EXCEPTION 'FAIL 6.1 an employee should see their 1 device, saw %', n;
  END IF;
  RAISE NOTICE 'PASS 6.1  an employee''s transaction sees only their own device';
END $$;

DO $$
DECLARE n int;
BEGIN
  UPDATE devices SET name = 'mine now' WHERE name = 'HQ-WIN-004';
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL 6.2 an employee changed a colleague''s device (% rows)', n;
  END IF;
  RAISE NOTICE 'PASS 6.2  an employee''s transaction cannot touch a colleague''s device';
END $$;

DO $$ BEGIN PERFORM set_config('app.subject', 'nobody-yet', false); PERFORM set_config('app.email', '', false); END $$;
DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM devices;
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL 6.3 an employee nobody has met should see 0 devices, saw %', n;
  END IF;
  RAISE NOTICE 'PASS 6.3  an employee the platform has not met sees nothing';
END $$;

DO $$ BEGIN PERFORM set_config('app.role', 'it_admin', false); PERFORM set_config('app.subject', 'o.martins', false); END $$;
DO $$
DECLARE n int;
BEGIN
  SELECT count(*) INTO n FROM devices;
  IF n <> 2 THEN
    RAISE EXCEPTION 'FAIL 6.4 an administrator should see the tenant''s 2 devices, saw %', n;
  END IF;
  RAISE NOTICE 'PASS 6.4  an administrator''s transaction reads the whole tenant';
END $$;

RESET ROLE;

DO $$ BEGIN RAISE NOTICE '';
  RAISE NOTICE '=== all 18 assertions passed ==='; END $$;
