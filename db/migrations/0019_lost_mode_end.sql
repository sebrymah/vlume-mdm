-- 0019_lost_mode_end.sql
-- Ending lost mode is its own command.
--
-- Putting a device in lost mode and taking it out are both things a person
-- does with a reason, under the same role, and each is its own row in the
-- commands table so the audit trail shows who ended it and why. The
-- database's list of command types is the second half of the pipeline's
-- own list (command.Types), and it refused the first lost_mode_end row,
-- which is what it is for.

BEGIN;

ALTER TABLE commands DROP CONSTRAINT IF EXISTS commands_type_check;
ALTER TABLE commands ADD CONSTRAINT commands_type_check
  CHECK (type IN ('lock','lost_mode','lost_mode_end','clear_passcode','wipe_selective','wipe_full'));

COMMIT;
