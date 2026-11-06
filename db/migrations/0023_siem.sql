-- 0023_siem.sql
-- F19: every audit event, forwarded to the tenant's SIEM.
--
-- The audit log is append-only and hash-chained. A SIEM wants a copy of
-- every row as it lands, in a format it already parses (CEF or LEEF over
-- syslog, or JSON to a webhook). This is a STREAM, not a notification: the
-- outbox deduplicates and retries single messages, and an export has to
-- know exactly where it got to. So the destination is an ordinary
-- notification target (topic siem.audit, the existing path) and the
-- position is a cursor per tenant, which is the one new table (SD 10:
-- nothing else records "this tenant has received audit events up to id
-- N"). The cursor moves only after the SIEM has taken the event: a send
-- that fails leaves it where it was, and the next run starts from there.

BEGIN;

-- The topic list in the database had not kept up with the topics the
-- platform announces (0013 was the last to widen it), so a target for the
-- weekly report or for quarantine could not be saved. One list, every
-- topic, on both tables.
ALTER TABLE notification_targets
  DROP CONSTRAINT IF EXISTS notification_targets_topic_check;
ALTER TABLE notification_targets
  ADD CONSTRAINT notification_targets_topic_check
  CHECK (topic IN ('device.lost','approval.waiting','limiter.tripped',
                   'device.wiped','enrolment.completed','certificate.expiring',
                   'device.quarantined','enforcement.halted','device.released',
                   'report.compliance','quota.reached','siem.audit'));
ALTER TABLE notifications
  DROP CONSTRAINT IF EXISTS notifications_topic_check;

ALTER TABLE notification_targets
  DROP CONSTRAINT IF EXISTS notification_targets_kind_check;
ALTER TABLE notification_targets
  ADD CONSTRAINT notification_targets_kind_check
  CHECK (kind IN ('webhook', 'log', 'email', 'syslog'));

CREATE TABLE IF NOT EXISTS siem_cursors (
  tenant_id     uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
  last_audit_id bigint NOT NULL DEFAULT 0,
  sent_total    bigint NOT NULL DEFAULT 0,
  last_sent_at  timestamptz,
  last_error    text
);
ALTER TABLE siem_cursors OWNER TO mdm_owner;
ALTER TABLE siem_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY siem_cursors_tenant_isolation ON siem_cursors
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON siem_cursors TO mdm_app;

COMMIT;
