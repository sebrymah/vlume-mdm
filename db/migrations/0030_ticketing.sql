-- 0030_ticketing.sql
-- F20: a ticket in the tenant's own queue.
--
-- Two more kinds of notification target. Everything about how a topic
-- reaches a destination already exists (the target, the outbox, the
-- worker, the retries); these only teach it to open a Jira issue or a
-- ServiceNow incident instead of posting to a chat. The endpoint is the
-- integration's whole configuration as JSON, sealed like every endpoint,
-- because it carries a token.

BEGIN;

ALTER TABLE notification_targets
  DROP CONSTRAINT IF EXISTS notification_targets_kind_check;
ALTER TABLE notification_targets
  ADD CONSTRAINT notification_targets_kind_check
  CHECK (kind IN ('webhook', 'log', 'email', 'syslog', 'jira', 'servicenow'));

COMMIT;
