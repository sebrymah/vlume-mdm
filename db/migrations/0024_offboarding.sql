-- 0024_offboarding.sql
-- F4: offboarding a device, and everything a leaver holds.
--
-- Offboarding is not deletion. It is a selective wipe through the command
-- pipeline, with its reason and its role, and THEN retirement: the device
-- is marked retired and its certificate revoked the moment the wipe is
-- acknowledged, by the device or by the vendor. Until then it is "being
-- offboarded", which is a state the console shows rather than a flag it
-- hides. A leaver is offboarded by their address: every device assigned
-- to them goes the same way.
--
-- The HR side is a second scope for integration tokens: a token minted for
-- the HR system may say "this person has left" and nothing else, and a
-- token minted for the network may not say it.

BEGIN;

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS offboarding_at timestamptz,
  ADD COLUMN IF NOT EXISTS offboarding_by text,
  ADD COLUMN IF NOT EXISTS offboarded_at  timestamptz;

ALTER TABLE integration_tokens
  ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'network'
    CHECK (scope IN ('network','hr'));

COMMIT;
