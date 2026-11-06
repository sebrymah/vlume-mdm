-- 0035_tenant_import.sql
-- T11: moving a tenant to another region.
--
-- A region is a deployment with a database of its own. Moving a tenant is
-- an export on the source (a move bundle: every table, sealed values
-- intact, the tenant's keys re-sealed under a transport key the
-- destination chose), an import here, and an offboarding there. The
-- import inserts rows across every tenant table, which the operator's
-- role may not do by itself; so it goes through functions owned by
-- mdm_importer, a role nobody can log in as, which may insert and nothing
-- else, one row at a time, each checked to carry the tenant being
-- imported and to land in a tenant table. The audit chain trigger
-- re-chains the imported audit rows in order, so the destination's chain
-- verifies; the bundle keeps the source's hashes as the record.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_importer') THEN
    CREATE ROLE mdm_importer NOLOGIN BYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO mdm_importer;
DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY app.tenant_tables() LOOP
    EXECUTE format('GRANT INSERT, SELECT ON %I TO mdm_importer', tbl);
  END LOOP;
END $$;
GRANT USAGE, UPDATE ON SEQUENCE audit_events_id_seq, command_approvals_id_seq TO mdm_importer;
-- The triggers an insert fires run as the importer: the device cap reads
-- the plan off the tenants row, the audit chain reads the previous row.
GRANT SELECT ON tenants TO mdm_importer;

-- The move bundle carries the tenant's hostnames, read under the tenant's
-- own claim like every other table of its own. Until now the application
-- role could not read tenant_domains at all (resolution is the
-- directory's, on the operator's role); a read of its own rows is all it
-- gets.
ALTER TABLE tenant_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_domains FORCE ROW LEVEL SECURITY;
GRANT SELECT ON tenant_domains TO mdm_app;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'tenant_domains' AND policyname = 'tenant_domains_app_read') THEN
    CREATE POLICY tenant_domains_app_read ON tenant_domains
      FOR SELECT TO mdm_app USING (tenant_id = app.current_tenant());
  END IF;
  -- The operator resolves every hostname to its tenant: that is the shell,
  -- and the shell is the operator's. Row-level security is now on for the
  -- application role's sake, so the operator's reach is stated as a policy
  -- rather than lost.
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'tenant_domains' AND policyname = 'tenant_domains_operator') THEN
    CREATE POLICY tenant_domains_operator ON tenant_domains
      FOR ALL TO mdm_operator USING (true) WITH CHECK (true);
  END IF;
END $$;

-- One row. The tenant on the row has to be the tenant being imported, and
-- the table has to be one of the tenant's: a bundle that says otherwise
-- is refused here, whatever the tool checked.
CREATE OR REPLACE FUNCTION app.import_tenant_row(t uuid, tbl text, r jsonb) RETURNS void AS $$
DECLARE cols text;
BEGIN
  IF NOT tbl = ANY(app.tenant_tables()) THEN
    RAISE EXCEPTION 'import: % is not a tenant table', tbl USING ERRCODE = 'check_violation';
  END IF;
  IF (r->>'tenant_id')::uuid IS DISTINCT FROM t THEN
    RAISE EXCEPTION 'import: a row for % names another tenant', tbl USING ERRCODE = 'check_violation';
  END IF;
  -- Only the columns the row carries, so a column it leaves out takes
  -- the table's default (a serial id, a timestamp) rather than NULL. A key
  -- that is not a column of the table is an error, as it should be.
  SELECT string_agg(format('%I', k), ',') INTO cols FROM jsonb_object_keys(r) AS k;
  EXECUTE format('INSERT INTO %I (%s) SELECT %s FROM jsonb_populate_record(NULL::%I, $1)', tbl, cols, cols, tbl) USING r;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, app;

-- After the rows: the sequences behind serial ids move past what was
-- imported, so the next row the tenant writes does not collide with one
-- it brought.
CREATE OR REPLACE FUNCTION app.import_tenant_finish(t uuid) RETURNS void AS $$
DECLARE tbl text; seq text; mx bigint;
BEGIN
  FOREACH tbl IN ARRAY app.tenant_tables() LOOP
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'id') THEN
      CONTINUE;
    END IF;
    seq := pg_get_serial_sequence(tbl, 'id');
    IF seq IS NOT NULL THEN
      EXECUTE format('SELECT max(id) FROM %I', tbl) INTO mx;
      IF mx IS NOT NULL THEN
        PERFORM setval(seq, GREATEST(mx, (SELECT last_value FROM pg_sequences WHERE schemaname || '.' || sequencename = seq)));
      END IF;
    END IF;
  END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, app;

ALTER FUNCTION app.import_tenant_row(uuid, text, jsonb) OWNER TO mdm_importer;
ALTER FUNCTION app.import_tenant_finish(uuid) OWNER TO mdm_importer;
REVOKE ALL ON FUNCTION app.import_tenant_row(uuid, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.import_tenant_finish(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.import_tenant_row(uuid, text, jsonb) TO mdm_operator;
GRANT EXECUTE ON FUNCTION app.import_tenant_finish(uuid) TO mdm_operator;

COMMIT;
