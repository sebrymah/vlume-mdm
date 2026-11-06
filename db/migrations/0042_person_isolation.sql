-- 0042: a second control for person isolation.
--
-- Tenant isolation has two independent controls: the repository functions
-- and row-level security. Person isolation inside a tenant had one, the
-- predicate in data.MyDevices, because an administrator legitimately
-- reads every row and a policy strong enough to stop an employee would
-- stop them too.
--
-- The claim now reaches the database as well as the tenant does: its role,
-- subject and email are transaction settings beside app.tenant_id. With
-- the role known, the database can say what the Go predicate says: an
-- employee's transaction sees the devices of the person it belongs to and
-- nothing else, whatever the SQL asked for. A restrictive policy, ANDed
-- with the tenant one, on devices and on the verdicts of devices; for
-- every other role it is true and changes nothing.

BEGIN;

CREATE OR REPLACE FUNCTION app.claim_role() RETURNS text
  LANGUAGE sql STABLE
  AS $$ SELECT coalesce(current_setting('app.role', true), '') $$;
CREATE OR REPLACE FUNCTION app.claim_subject() RETURNS text
  LANGUAGE sql STABLE
  AS $$ SELECT coalesce(current_setting('app.subject', true), '') $$;
CREATE OR REPLACE FUNCTION app.claim_email() RETURNS text
  LANGUAGE sql STABLE
  AS $$ SELECT lower(coalesce(current_setting('app.email', true), '')) $$;
GRANT EXECUTE ON FUNCTION app.claim_role(), app.claim_subject(), app.claim_email() TO mdm_app, mdm_operator;

-- Who the transaction belongs to, as the platform knows them (0040): the
-- same clause data.activePerson uses, in SQL. Null when nobody.
CREATE OR REPLACE FUNCTION app.current_person() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$
    SELECT id FROM people
     WHERE tenant_id = app.current_tenant() AND left_at IS NULL
       AND ( (app.claim_subject() <> '' AND subject = app.claim_subject())
          OR (subject = '' AND app.claim_email() <> '' AND email = app.claim_email()) )
     LIMIT 1
  $$;
GRANT EXECUTE ON FUNCTION app.current_person() TO mdm_app;

DROP POLICY IF EXISTS devices_person_isolation ON devices;
CREATE POLICY devices_person_isolation ON devices
  AS RESTRICTIVE FOR ALL TO mdm_app
  USING (app.claim_role() <> 'employee' OR person_id = app.current_person())
  WITH CHECK (app.claim_role() <> 'employee' OR person_id = app.current_person());

-- A verdict is readable by an employee only for a device they can see,
-- which the devices policy above already decides.
DROP POLICY IF EXISTS device_compliance_person_isolation ON device_compliance;
CREATE POLICY device_compliance_person_isolation ON device_compliance
  AS RESTRICTIVE FOR ALL TO mdm_app
  USING (app.claim_role() <> 'employee' OR device_id IN (SELECT id FROM devices))
  WITH CHECK (app.claim_role() <> 'employee' OR device_id IN (SELECT id FROM devices));

COMMIT;
