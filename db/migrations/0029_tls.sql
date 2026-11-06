-- 0029_tls.sql
-- T5: managed TLS for every tenant hostname.
--
-- Certificates are obtained from an ACME authority (Let's Encrypt, or a
-- private one) for the hostnames tenants own, and only those: the host
-- policy is the directory, and a hostname that is not a verified tenant
-- domain gets no certificate, because a stranger pointing a name at this
-- platform must not be able to spend its issuance budget. The cache is
-- the operator's table: certificates and account keys are platform
-- material, not tenant data, and the application role never sees them.

BEGIN;

CREATE TABLE IF NOT EXISTS tls_cache (
  name       text PRIMARY KEY,
  data       bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tls_cache OWNER TO mdm_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON tls_cache TO mdm_operator;

COMMIT;
