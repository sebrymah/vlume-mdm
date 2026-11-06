-- 0001_tenancy.sql
-- The tenant isolation foundation. This is the first migration on purpose:
-- the technical specification of 27 Oct 2026 requires tenant_id and row-level
-- security to exist before anything else, because retrofitting tenancy is the
-- named failure mode for this product class.
--
-- Three roles, and the separation between them is the control:
--   mdm_owner     owns the tables and runs migrations. Never serves traffic.
--   mdm_app       the application. NOBYPASSRLS. Sees exactly one tenant at a time.
--   mdm_operator  the operator console. Tenant metadata only, no device data.

BEGIN;

-- ---------------------------------------------------------------- roles
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_owner') THEN
    CREATE ROLE mdm_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_app') THEN
    CREATE ROLE mdm_app NOLOGIN NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_operator') THEN
    CREATE ROLE mdm_operator NOLOGIN NOBYPASSRLS;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS app;
GRANT USAGE ON SCHEMA app TO mdm_app, mdm_operator;

-- ---------------------------------------------------------------- tenant context
-- The tenant for the current transaction. Returns NULL when unset, and NULL
-- compared to anything is not true, so every policy below fails closed.
--
-- The value is set by the data layer from the signed tenant claim on the
-- request. It is never set from anything a user can type. That is the one
-- rule this whole design rests on, and it is enforced in the data layer,
-- not here.
CREATE OR REPLACE FUNCTION app.current_tenant() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

GRANT EXECUTE ON FUNCTION app.current_tenant() TO mdm_app, mdm_operator;

-- ---------------------------------------------------------------- tenants
-- Operator-scoped. Deliberately NOT row-level secured: it is the one table
-- that legitimately spans tenants, and it holds no device, policy, key or
-- audit data. The operator console reads it through mdm_operator.
CREATE TABLE IF NOT EXISTS tenants (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text        NOT NULL,
  slug          text        NOT NULL UNIQUE,
  plan          text        NOT NULL DEFAULT 'starter',
  region        text        NOT NULL DEFAULT 'eu-west',
  status        text        NOT NULL DEFAULT 'provisioning'
                CHECK (status IN ('provisioning','active','near_cap','suspended','exporting','offboarded')),
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenants OWNER TO mdm_owner;
GRANT SELECT ON tenants TO mdm_operator;
GRANT SELECT ON tenants TO mdm_app;

COMMIT;
