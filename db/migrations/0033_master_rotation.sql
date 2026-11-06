-- 0033_master_rotation.sql
-- T3: rotating the master key.
--
-- The master key seals every tenant's key and nothing else. Rotating it
-- means re-sealing every tenant_keys row under the new master, which is a
-- read and a write of ciphertext across every tenant: exactly what the
-- operator's role may not do by itself, and the probe test keeps it that
-- way. So the two steps are functions owned by mdm_keymaster, a role
-- nobody can log in as, which may read and update key_sealed and nothing
-- else. The operator's tool executes them; the plaintext keys exist only
-- inside the tool, for the length of one run.
--
-- The write is compare-and-swap: a row is replaced only if it still holds
-- the ciphertext the tool read, so two runs cannot overwrite each other
-- and a row changed under the tool's feet is a halt, not a surprise.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mdm_keymaster') THEN
    CREATE ROLE mdm_keymaster NOLOGIN BYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO mdm_keymaster;
GRANT SELECT, UPDATE ON tenant_keys TO mdm_keymaster;

CREATE OR REPLACE FUNCTION app.tenant_key_blobs()
RETURNS TABLE (tenant_id uuid, version integer, key_sealed bytea, retired boolean) AS $$
  SELECT tenant_id, version, key_sealed, retired_at IS NOT NULL
    FROM tenant_keys ORDER BY tenant_id, version
$$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, app;

CREATE OR REPLACE FUNCTION app.reseal_tenant_key(t uuid, v integer, was bytea, now_sealed bytea)
RETURNS boolean AS $$
DECLARE n integer;
BEGIN
  UPDATE tenant_keys SET key_sealed = now_sealed
   WHERE tenant_id = t AND version = v AND key_sealed = was;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n = 1;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, app;

ALTER FUNCTION app.tenant_key_blobs() OWNER TO mdm_keymaster;
ALTER FUNCTION app.reseal_tenant_key(uuid, integer, bytea, bytea) OWNER TO mdm_keymaster;
REVOKE ALL ON FUNCTION app.tenant_key_blobs() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.reseal_tenant_key(uuid, integer, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.tenant_key_blobs() TO mdm_operator;
GRANT EXECUTE ON FUNCTION app.reseal_tenant_key(uuid, integer, bytea, bytea) TO mdm_operator;

COMMIT;
