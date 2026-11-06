-- 0002_core.sql
-- The first tenant-scoped tables, each carrying the same pattern, plus the
-- append-only audit log.
--
-- The pattern, applied without exception:
--   tenant_id uuid NOT NULL REFERENCES tenants(id)
--   ENABLE ROW LEVEL SECURITY
--   FORCE ROW LEVEL SECURITY        -- so the owner is bound by it too
--   a policy USING and WITH CHECK app.current_tenant()
--
-- FORCE matters. Without it a table owner silently bypasses every policy,
-- and "we remembered to set it" is not a control.

BEGIN;

-- ---------------------------------------------------------------- devices
CREATE TABLE IF NOT EXISTS devices (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name          text        NOT NULL,
  serial        text        NOT NULL,
  os_family     text        NOT NULL CHECK (os_family IN ('macos','ios','ipados','android','windows')),
  ownership     text        NOT NULL DEFAULT 'company' CHECK (ownership IN ('company','personal')),
  state         text        NOT NULL DEFAULT 'awaiting_first_boot'
                CHECK (state IN ('awaiting_first_boot','compliant','not_compliant','state_unknown','quarantined','retired')),
  last_report_at timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  -- Uniqueness is per tenant, never global. Two tenants may legitimately
  -- hold the same serial, and the isolation suite depends on that being true.
  UNIQUE (tenant_id, serial)
);

ALTER TABLE devices OWNER TO mdm_owner;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;

CREATE POLICY devices_tenant_isolation ON devices
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON devices TO mdm_app;

-- ---------------------------------------------------------------- policies
CREATE TABLE IF NOT EXISTS policies (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name          text        NOT NULL,
  version       integer     NOT NULL DEFAULT 1,
  body          jsonb       NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name, version)
);

ALTER TABLE policies OWNER TO mdm_owner;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;

CREATE POLICY policies_tenant_isolation ON policies
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON policies TO mdm_app;

-- ---------------------------------------------------------------- audit
-- Append-only, hash-chained, per tenant. Two independent protections:
--   1. UPDATE and DELETE are never granted to the application role.
--   2. Each row carries the hash of its predecessor, so a deletion performed
--      outside the application is detectable rather than merely prevented.
-- The second is the one being sold. The first only stops us.
CREATE TABLE IF NOT EXISTS audit_events (
  id            bigserial PRIMARY KEY,
  tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  occurred_at   timestamptz NOT NULL DEFAULT now(),
  actor         text        NOT NULL,
  action        text        NOT NULL,
  object_ref    text,
  detail        jsonb       NOT NULL DEFAULT '{}'::jsonb,
  prev_hash     text,
  hash          text        NOT NULL
);

ALTER TABLE audit_events OWNER TO mdm_owner;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_tenant_isolation ON audit_events
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());

-- Deliberately no UPDATE, no DELETE. R9 of the specification.
GRANT SELECT, INSERT ON audit_events TO mdm_app;
GRANT USAGE ON SEQUENCE audit_events_id_seq TO mdm_app;

-- The chain. Computed per tenant, so one tenant's history is independent of
-- every other's. Serialisation under concurrency is handled by the advisory
-- lock: two inserts for the same tenant cannot interleave and produce a fork.
CREATE OR REPLACE FUNCTION app.audit_chain() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
DECLARE
  last_hash text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('audit_chain:' || NEW.tenant_id::text));

  SELECT a.hash INTO last_hash
    FROM audit_events a
   WHERE a.tenant_id = NEW.tenant_id
   ORDER BY a.id DESC
   LIMIT 1;

  NEW.prev_hash := last_hash;
  NEW.hash := encode(
    sha256(convert_to(
      coalesce(last_hash, '')
      || '|' || NEW.tenant_id::text
      || '|' || NEW.actor
      || '|' || NEW.action
      || '|' || coalesce(NEW.object_ref, '')
      || '|' || NEW.detail::text
    , 'UTF8')), 'hex');

  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS audit_chain_trg ON audit_events;
CREATE TRIGGER audit_chain_trg
  BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION app.audit_chain();

-- Verifies a tenant's chain from the beginning. Returns the id of the first
-- row that does not follow from its predecessor, or NULL when the chain holds.
CREATE OR REPLACE FUNCTION app.verify_audit_chain(p_tenant uuid) RETURNS bigint
  LANGUAGE plpgsql STABLE
  AS $$
DECLARE
  r          record;
  expected   text;
  running    text := NULL;
BEGIN
  FOR r IN
    SELECT * FROM audit_events WHERE tenant_id = p_tenant ORDER BY id ASC
  LOOP
    expected := encode(
      sha256(convert_to(
        coalesce(running, '')
        || '|' || r.tenant_id::text
        || '|' || r.actor
        || '|' || r.action
        || '|' || coalesce(r.object_ref, '')
        || '|' || r.detail::text
      , 'UTF8')), 'hex');

    IF r.hash IS DISTINCT FROM expected OR r.prev_hash IS DISTINCT FROM running THEN
      RETURN r.id;
    END IF;
    running := r.hash;
  END LOOP;

  RETURN NULL;
END
$$;

GRANT EXECUTE ON FUNCTION app.verify_audit_chain(uuid) TO mdm_app, mdm_operator;

COMMIT;
