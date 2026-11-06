-- 0028_logo.sql
-- T4: the tenant's logo and favicon.
--
-- Stored as bytes on the branding row, small (the console refuses anything
-- a page would struggle with), served per hostname without a session so
-- the sign-in error page and the browser tab carry them before anyone has
-- signed in. The type is what the bytes say they are, not what the upload
-- claimed.

BEGIN;

ALTER TABLE tenant_branding
  ADD COLUMN IF NOT EXISTS logo         bytea,
  ADD COLUMN IF NOT EXISTS logo_type    text,
  ADD COLUMN IF NOT EXISTS favicon      bytea,
  ADD COLUMN IF NOT EXISTS favicon_type text;

COMMIT;
