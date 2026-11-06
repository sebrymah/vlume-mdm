-- 0010_notify.sql
-- Telling someone.
--
-- The thing that prompted this. When the bulk-wipe limiter trips, the
-- console says "your queue is paused and the Security Manager has been
-- told". Nothing in the platform told anyone. The product has been making a
-- claim about a control that did not exist, which is worse than not having
-- the control: an operator reading that line stops looking.
--
-- Two tables, and the shape of them is the whole design.

BEGIN;

-- ------------------------------------------------------- where things go
--
-- A destination per topic, per tenant. NOT a list of people.
--
-- Resolving "everyone who may approve a wipe" would mean holding a
-- directory of a tenant's staff and their roles, and this platform
-- deliberately holds neither: people live at the tenant's own identity
-- provider and we only ever see whoever is in front of us. A tenant points
-- a topic at a channel their security team already watches, which is also
-- how operations teams actually work.
CREATE TABLE IF NOT EXISTS notification_targets (
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  topic      text NOT NULL
             CHECK (topic IN ('device.lost','approval.waiting','limiter.tripped',
                              'device.wiped','enrolment.completed')),
  kind       text NOT NULL CHECK (kind IN ('webhook','log')),
  -- Sealed, because a chat webhook URL IS a credential: anyone holding it
  -- can post into that channel as the integration. Same Sealer as the
  -- identity provider secrets and the tenant authority keys.
  endpoint_sealed bytea NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, topic)
);

ALTER TABLE notification_targets OWNER TO mdm_owner;
ALTER TABLE notification_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_targets_tenant_isolation ON notification_targets
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_targets TO mdm_app;

-- ---------------------------------------------------------- the outbox
--
-- A notification is written in the SAME TRANSACTION as the thing that
-- caused it, and delivered afterwards by a worker. That one decision buys
-- all three properties that matter:
--
--   nothing is lost      the row commits with the event or neither does
--   nothing is blocked   a wipe request does not fail because chat is down
--   nothing is invented  there is no notification without its event
--
-- The alternative, calling the webhook inline, fails all three: a slow
-- endpoint holds the request open, a failed one either loses the message or
-- rolls back a legitimate wipe, and a retry after commit can tell someone
-- about an event that was then rolled back.
CREATE TABLE IF NOT EXISTS notifications (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  topic      text NOT NULL,
  -- What the message says. Rendered at enqueue time, not at send time, so
  -- the message describes the world as it was when the event happened
  -- rather than as it is when chat comes back up.
  subject    text NOT NULL CHECK (subject <> ''),
  body       text NOT NULL,
  object_ref text NOT NULL DEFAULT '',

  -- dedupe_key stops the same event queuing twice while it is still
  -- waiting. Pressing "report lost" five times is one message.
  dedupe_key text NOT NULL,

  state      text NOT NULL DEFAULT 'pending'
             CHECK (state IN ('pending','sent','failed','undeliverable')),
  attempts   integer NOT NULL DEFAULT 0,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  sent_at    timestamptz,

  -- A failure that nobody can see is the same as no notification at all.
  CONSTRAINT failure_says_why
    CHECK (state NOT IN ('failed','undeliverable') OR
           (last_error IS NOT NULL AND last_error <> '')),
  CONSTRAINT sent_has_a_time
    CHECK (state <> 'sent' OR sent_at IS NOT NULL)
);

-- One pending notification per key. Partial, so the same key can queue
-- again later for a genuinely new occurrence.
CREATE UNIQUE INDEX IF NOT EXISTS notifications_one_pending_per_key
  ON notifications (tenant_id, dedupe_key) WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS notifications_due
  ON notifications (next_attempt_at) WHERE state = 'pending';

ALTER TABLE notifications OWNER TO mdm_owner;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY notifications_tenant_isolation ON notifications
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());

-- No DELETE. A notification that was sent, and one that could not be, are
-- both part of the record of what the platform did and did not tell anyone.
GRANT SELECT, INSERT, UPDATE ON notifications TO mdm_app;

COMMIT;
