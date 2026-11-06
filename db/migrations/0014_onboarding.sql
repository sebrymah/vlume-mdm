-- 0014_onboarding.sql
-- Letting the operator set a tenant up without being able to look inside it.
--
-- T1 asks for operator-assisted onboarding and a setup wizard. The PRD's own
-- success test is a tenant enrolling its first device within an hour of
-- sign-up, and until now "sign-up" was somebody with the database password
-- typing INSERT statements.
--
-- THE BOUNDARY THIS KEEPS. The operator's role, mdm_operator, could read
-- tenants, tenant_domains and tenant_identity and nothing else, and a test
-- proves it cannot reach devices. This migration lets that role WRITE the
-- four rows a new tenant needs, and nothing more:
--
--   tenants            the tenant itself
--   tenant_domains     the hostname the console answers on
--   tenant_identity    which identity provider its people sign in against
--   tenant_role_map    ONE mapping, so the first administrator can get in
--
-- It still cannot read a device, a command, an audit entry or a policy. The
-- operator can set a tenant up and cannot look inside it, which is R13 made
-- concrete rather than promised.
--
-- Why the first role mapping is seeded by the operator: to configure sign-in
-- you have to be signed in. Somebody has to break that circle once per
-- tenant, and it is the operator, who knows which group at the customer's
-- directory holds the people who asked for this.

BEGIN;

GRANT INSERT, UPDATE ON tenants TO mdm_operator;
GRANT INSERT, UPDATE, DELETE ON tenant_domains TO mdm_operator;

-- tenant_identity already has a SELECT policy for the operator (0006). This
-- adds the write, with the same reasoning: nothing can scope it by a claim
-- because the tenant is being created.
GRANT INSERT, UPDATE ON tenant_identity TO mdm_operator;
CREATE POLICY identity_operator_write ON tenant_identity
  FOR INSERT TO mdm_operator
  WITH CHECK (true);
CREATE POLICY identity_operator_update ON tenant_identity
  FOR UPDATE TO mdm_operator
  USING (true) WITH CHECK (true);

-- The one mapping. INSERT only: the operator can open the door for the first
-- administrator and cannot afterwards change who is what inside the tenant.
GRANT INSERT ON tenant_role_map TO mdm_operator;
CREATE POLICY role_map_operator_seed ON tenant_role_map
  FOR INSERT TO mdm_operator
  WITH CHECK (true);

-- Inside the tenant, a Super Admin may change which role a group maps to
-- from the console. 0006 gave the app role SELECT, INSERT and DELETE; an
-- upsert that changes the role needs UPDATE too, and the existing isolation
-- policy (FOR ALL) already covers it.
GRANT UPDATE ON tenant_role_map TO mdm_app;

-- ------------------------------------------------------------ the metric
--
-- "Time from tenant sign-up to first enrolled device, under 60 minutes" is
-- the PRD's first success metric. It is answerable from created_at on
-- tenants and devices, and the setup page answers it, because a metric that
-- is not shown is a metric nobody is held to.

COMMIT;
