-- 99_lockdown.sql: closes Supabase's own front door to the platform's tables.
--
-- Supabase gives its API roles (anon, authenticated, service_role) rights on
-- every object the migrating user creates, through default privileges. This
-- platform never uses Supabase's API: its tables are reached only through the
-- mdm_app and mdm_operator logins. Left alone, those default rights would
-- make every table reachable by anyone holding the project's public key, held
-- back only by row-level security (which some tables, by design, do not use).
--
-- Run before the migrations (so nothing is ever granted) and after (to catch
-- anything that was). It ends by CHECKING, and fails loudly if any right is left.
-- On a database without those roles it does nothing.

DO $$
DECLARE
  r text; s text; left_over int;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r);
    FOREACH s IN ARRAY ARRAY['public', 'app'] LOOP
      CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = s);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON TABLES FROM %I', s, r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON SEQUENCES FROM %I', s, r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON FUNCTIONS FROM %I', s, r);
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', s, r);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', s, r);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM %I', s, r);
    END LOOP;
  END LOOP;

  SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,
                 LATERAL aclexplode(c.relacl) a JOIN pg_roles g ON g.oid = a.grantee
           WHERE n.nspname IN ('public', 'app') AND g.rolname IN ('anon', 'authenticated', 'service_role'))
       + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace,
                 LATERAL aclexplode(p.proacl) a JOIN pg_roles g ON g.oid = a.grantee
           WHERE n.nspname IN ('public', 'app') AND g.rolname IN ('anon', 'authenticated', 'service_role'))
    INTO left_over;
  IF left_over > 0 THEN
    RAISE EXCEPTION 'lockdown failed: % rights are still held by Supabase API roles', left_over;
  END IF;
END
$$;
