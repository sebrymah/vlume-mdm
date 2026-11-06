-- 00_roles.sql: run ONCE, first, as Supabase's own `postgres` role.
--
-- Why this file exists. The migrations were written for a database where the
-- migrating user is a superuser. On Supabase it is not: `postgres` may create
-- roles, but it cannot hand a table to a role it cannot SET ROLE to, and
-- ALTER TABLE ... OWNER TO would stop at 0001. So the seven roles are made
-- here, the same way the migrations would make them (the migrations skip a
-- role that already exists), and `postgres` is made able to act as each one.
--
-- None of the seven can log in except through the passwords set in
-- 01_logins.sql, and the three that serve traffic cannot bypass row-level
-- security. The four that can are reached only through SECURITY DEFINER
-- functions, as before.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_owner')     THEN CREATE ROLE mdm_owner     NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_app')       THEN CREATE ROLE mdm_app       NOLOGIN NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_operator')  THEN CREATE ROLE mdm_operator  NOLOGIN NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_reaper')    THEN CREATE ROLE mdm_reaper    NOLOGIN BYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_meter')     THEN CREATE ROLE mdm_meter     NOLOGIN BYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_importer')  THEN CREATE ROLE mdm_importer  NOLOGIN BYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_keymaster') THEN CREATE ROLE mdm_keymaster NOLOGIN BYPASSRLS; END IF;
END
$$;

-- Lets the migrating user hand objects to these roles.
GRANT mdm_owner, mdm_reaper, mdm_meter, mdm_importer, mdm_keymaster TO CURRENT_USER;

-- A table can only be handed to a role that may create things in its schema.
-- A superuser is exempt from that check; `postgres` on Supabase is not.
GRANT USAGE, CREATE ON SCHEMA public TO mdm_owner;

-- The four roles that own SECURITY DEFINER functions in schema `app` must be
-- able to create in it for the same reason. Migration 0001 makes the schema
-- with IF NOT EXISTS, so making it here first is safe. These four cannot log
-- in and nobody can SET ROLE to them but this migrating user, so the grant
-- widens nothing a caller can reach.
CREATE SCHEMA IF NOT EXISTS app;
GRANT USAGE, CREATE ON SCHEMA app TO mdm_reaper, mdm_meter, mdm_importer, mdm_keymaster;
