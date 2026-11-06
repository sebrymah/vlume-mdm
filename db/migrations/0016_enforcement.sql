-- 0016_enforcement.sql
-- F9: automatic quarantine of a non-compliant device, and the brake on it.
--
-- Until now evaluation produced a verdict and stopped, and the README said
-- why: wiring a compliance signal straight to a destructive action routes
-- around the one control a human cannot be talked past, and the first false
-- positive would wipe a fleet. That reasoning still holds for wipe and lock.
-- Quarantine is different in one way that matters: it is reversible by a
-- person in one click, and nothing on the device is erased.
--
-- So quarantine may now happen automatically, under three conditions:
--
--   1. a policy that applies to the device asked for it ("on_failure":
--      "quarantine" in the body). Nothing is enforced by default.
--   2. the verdict is not_compliant. state_unknown never triggers it: not
--      knowing is not a reason to act.
--   3. the brake has not tripped. If more than 5% of the fleet (and at
--      least four devices) are failing, the platform stops quarantining
--      and says so instead, because a sudden mass failure is far more
--      likely a policy change or an agent fault than a fleet gone bad at
--      once (standing directive 1: halt rather than continue silently).
--
-- There is no grace period (standing directive 6). The rule fires on the
-- report that fails, or it does not exist.
--
-- Release is a person's act. The trigger from 0008 that refuses to move a
-- quarantined device back by evaluation stays; it now lets the move through
-- when the transaction has said, in a setting only the release function
-- sets, that a person asked.

BEGIN;

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS quarantined_at     timestamptz,
  ADD COLUMN IF NOT EXISTS quarantined_by     text,
  ADD COLUMN IF NOT EXISTS quarantine_reason  text;

ALTER TABLE devices
  DROP CONSTRAINT IF EXISTS quarantine_names_who_did_it;
ALTER TABLE devices
  ADD CONSTRAINT quarantine_names_who_did_it
  CHECK (quarantined_at IS NULL OR
         (quarantined_by IS NOT NULL AND quarantined_by <> ''));

CREATE OR REPLACE FUNCTION app.check_device_state_transition() RETURNS trigger AS $$
BEGIN
  IF NEW.state IS DISTINCT FROM OLD.state
     AND OLD.state IN ('quarantined','retired')
     AND NEW.state IN ('compliant','not_compliant','state_unknown')
     AND coalesce(current_setting('app.release', true), '') <> 'yes' THEN
    RAISE EXCEPTION
      'a % device cannot be moved to % by evaluation (device %)',
      OLD.state, NEW.state, OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMIT;
