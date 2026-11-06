-- 0038: SAML 2.0 sign-in beside OpenID Connect.
--
-- A tenant whose identity provider is not OpenID Connect (an older ADFS, a
-- Shibboleth, an Okta or Entra application set up as SAML) signs in through
-- the same table with a second protocol. The columns map onto the OIDC
-- ones where the meaning is the same, so nothing downstream learns a second
-- shape:
--
--   issuer        the identity provider's entity id (the assertion's Issuer)
--   client_id     OUR entity id, which is the audience the assertion must name
--   redirect_url  OUR assertion consumer service, where the browser posts back
--   role_claim    the attribute carrying the person's groups
--
-- SAML has no client secret: trust runs through the identity provider's
-- signing certificate, held here in the open because it is public.

ALTER TABLE tenant_identity
  ADD COLUMN IF NOT EXISTS protocol         text NOT NULL DEFAULT 'oidc'
    CHECK (protocol IN ('oidc', 'saml')),
  ADD COLUMN IF NOT EXISTS saml_sso_url     text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS saml_certificate text NOT NULL DEFAULT '';

-- The issuer is fetched over the network for OIDC, so it has to be https.
-- For SAML it is a name that is only ever compared, and Okta's entity ids
-- begin with http://, so the check applies to OIDC alone.
ALTER TABLE tenant_identity DROP CONSTRAINT IF EXISTS issuer_is_https;
ALTER TABLE tenant_identity ADD CONSTRAINT issuer_is_https
  CHECK (protocol = 'saml' OR issuer LIKE 'https://%' OR issuer LIKE 'http://127.0.0.1%');

-- A SAML row is complete or it is not a SAML row: the browser is sent to
-- the sign-in URL, and the assertion is checked against the certificate.
ALTER TABLE tenant_identity ADD CONSTRAINT saml_is_complete
  CHECK (protocol <> 'saml' OR (
    (saml_sso_url LIKE 'https://%' OR saml_sso_url LIKE 'http://127.0.0.1%')
    AND saml_certificate LIKE '-----BEGIN CERTIFICATE-----%'));

-- The directory role reads this table column by column (0006): the new
-- columns join that list, and nothing else widens.
GRANT SELECT (protocol, saml_sso_url, saml_certificate) ON tenant_identity TO mdm_operator;
