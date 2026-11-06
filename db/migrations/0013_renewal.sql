-- 0013_renewal.sql
-- Telling somebody that certificates are running out.
--
-- The renewal itself needs no schema: a renewed certificate is a row in
-- device_certificates exactly like the first one, issued by the same
-- authority to the same device. What was missing is the ability to say so
-- when it is not happening.
--
-- A device that is off for a year, or whose agent has stopped, quietly
-- stops being able to authenticate on the day its certificate expires. Until
-- this topic existed, the first anyone knew was a device going silent, which
-- looks exactly like a stolen laptop and is investigated as one.

BEGIN;

ALTER TABLE notification_targets
  DROP CONSTRAINT IF EXISTS notification_targets_topic_check;

ALTER TABLE notification_targets
  ADD CONSTRAINT notification_targets_topic_check
  CHECK (topic IN ('device.lost','approval.waiting','limiter.tripped',
                   'device.wiped','enrolment.completed','certificate.expiring'));

-- The sweep reads this. Without it, finding the certificates that are
-- running out means a sequential scan of every certificate ever issued,
-- most of which expired long ago.
CREATE INDEX IF NOT EXISTS device_certificates_expiring
  ON device_certificates (tenant_id, not_after)
  WHERE revoked_at IS NULL;

COMMIT;
