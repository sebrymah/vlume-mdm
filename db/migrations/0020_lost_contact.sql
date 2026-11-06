-- 0020_lost_contact.sql
-- Who a finder should call.
--
-- The lost-mode lock screen names the tenant and asks for the device to be
-- handed in. A phone number and an email address make that an instruction
-- rather than a wish. They are the tenant's, set with the rest of the
-- brand, because they are what a stranger sees: the one surface on which
-- the operator-brand rule and the tenant's own contact details meet.

BEGIN;

ALTER TABLE tenant_branding
  ADD COLUMN IF NOT EXISTS lost_contact_phone text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS lost_contact_email text NOT NULL DEFAULT '';

COMMIT;
