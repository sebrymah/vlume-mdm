-- 0011_email.sql
-- Email as a destination.
--
-- One line of schema and a paragraph of reasoning, because the reasoning is
-- the part worth keeping.
--
-- What a tenant configures here is WHO is written to: an address, or a few.
-- What the operator configures, outside the database entirely, is HOW mail
-- leaves: the server, the credentials, the transport security. That split is
-- deliberate. A tenant-supplied webhook address is a request this platform
-- makes from inside its own network, so it is treated as hostile input and
-- checked at dial time. A tenant-supplied EMAIL address is not: nothing
-- connects to it, it is handed to a mail server the operator chose. The two
-- look similar on the form and are not the same risk at all.
--
-- The risk email brings instead is header injection, and that lives in the
-- channel rather than in the schema. See internal/notify/email.go.

BEGIN;

ALTER TABLE notification_targets
  DROP CONSTRAINT IF EXISTS notification_targets_kind_check;

ALTER TABLE notification_targets
  ADD CONSTRAINT notification_targets_kind_check
  CHECK (kind IN ('webhook', 'log', 'email'));

COMMIT;
