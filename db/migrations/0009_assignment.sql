-- 0009_assignment.sql
-- Who a device belongs to, and the one thing its holder can say about it.
--
-- The gap this closes. There has never been a link between a person and a
-- device. A tenant's devices were a flat list, and the employee role, which
-- has existed in the matrix since the first sprint holding devices.view_own,
-- had nothing it could view: there was no "own". That is why signing in as
-- an employee produced a 403.
--
-- The link is made at enrolment, because that is the only moment anyone
-- knows: an administrator invites a device FOR someone, and when the device
-- redeems the invitation it inherits the assignment.

BEGIN;

-- ------------------------------------------------------------- the link
--
-- Text rather than a foreign key to a people table, because there is no
-- people table and there must not be one. This platform holds no directory:
-- a tenant's people live at the tenant's own identity provider, and we only
-- ever see who is in front of us. What is stored here is what an
-- administrator typed, matched later against the subject or the email the
-- identity provider sends.
--
-- The honest limit of that: an email address reused after someone leaves
-- would inherit their devices. Keying on the provider's subject avoids it
-- and is unreadable to type, so both are matched and the subject wins. This
-- is written down rather than discovered.
ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS assigned_to text NOT NULL DEFAULT '';

ALTER TABLE enrolments
  ADD COLUMN IF NOT EXISTS assigned_to text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS devices_by_person
  ON devices (tenant_id, lower(assigned_to)) WHERE assigned_to <> '';

-- ---------------------------------------------------- reporting one lost
--
-- The one thing a person can do to their own device, and it deliberately
-- EXECUTES NOTHING. It raises a flag an administrator sees.
--
-- The reason is the same one the policy engine gives for not enforcing
-- automatically: locking and wiping go through the command pipeline, which
-- needs a named reason, a role permitted to ask, and for anything
-- irreversible a second person from a different role. Letting a button on an
-- employee's page reach past all of that would make the most junior account
-- in the product the one that can erase a laptop.
--
-- What it buys is the eleven o'clock at night case: someone's laptop is gone
-- and the person who knows cannot reach the help desk until morning. The
-- flag is on the device the moment they press it, and the decision is still
-- a person's in the morning.
ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS reported_lost_at timestamptz,
  ADD COLUMN IF NOT EXISTS reported_lost_by text,
  ADD COLUMN IF NOT EXISTS reported_lost_note text;

ALTER TABLE devices
  DROP CONSTRAINT IF EXISTS lost_report_names_who_raised_it;
ALTER TABLE devices
  ADD CONSTRAINT lost_report_names_who_raised_it
  CHECK (reported_lost_at IS NULL OR
         (reported_lost_by IS NOT NULL AND reported_lost_by <> ''));

CREATE INDEX IF NOT EXISTS devices_reported_lost
  ON devices (tenant_id) WHERE reported_lost_at IS NOT NULL;

COMMIT;
