-- 0043: SAML single logout.
--
-- Signing out of a SAML tenant ended our session and left the provider's
-- alone, because a logout request most providers insist on is a signed
-- one and the platform had nothing to sign with. Now it has: a signing key
-- and certificate of our own per tenant, made on first need, the key
-- sealed under the tenant's key like its other secrets, the certificate
-- published in our metadata so the provider can verify what we sign. The
-- provider's single logout URL is the one new thing a tenant types.

BEGIN;

ALTER TABLE tenant_identity
  ADD COLUMN IF NOT EXISTS saml_slo_url text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS saml_sp_key_sealed bytea,
  ADD COLUMN IF NOT EXISTS saml_sp_cert text NOT NULL DEFAULT '';

ALTER TABLE tenant_identity DROP CONSTRAINT IF EXISTS saml_slo_is_https;
ALTER TABLE tenant_identity ADD CONSTRAINT saml_slo_is_https CHECK (
  saml_slo_url = '' OR saml_slo_url LIKE 'https://%' OR saml_slo_url LIKE 'http://127.0.0.1%'
);

GRANT SELECT (saml_slo_url, saml_sp_key_sealed, saml_sp_cert) ON tenant_identity TO mdm_operator;

COMMIT;
