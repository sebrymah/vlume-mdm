-- 0022_rollout.sql
-- F7: staged rollout of a policy version to a group of devices.
--
-- A policy name may now have TWO active versions: the live one, which
-- applies to every device the scope covers, and a rolling one, which
-- applies to a stage of them: the devices carrying a tag, a percentage of
-- them chosen by a stable hash of the device id, or both. Promote makes
-- the rolling version live; halt withdraws it and the live one stands.
--
-- A device's stage is decided from its id, so a device that is in the 25%
-- stays in it when the stage widens to 50%: a rollout widens, it does not
-- shuffle. Tags are the groups: plain words on the device row, set from
-- the console by whoever may change policy.

BEGIN;

ALTER TABLE policies
  ADD COLUMN IF NOT EXISTS rollout_percent integer NOT NULL DEFAULT 100
    CHECK (rollout_percent BETWEEN 0 AND 100),
  ADD COLUMN IF NOT EXISTS rollout_tag text;

DROP INDEX IF EXISTS policies_one_active_version;
-- One live version per name...
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_live_version
  ON policies (tenant_id, name) WHERE active AND rollout_percent = 100 AND rollout_tag IS NULL;
-- ...and at most one rolling version per name.
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_rolling_version
  ON policies (tenant_id, name) WHERE active AND (rollout_percent < 100 OR rollout_tag IS NOT NULL);

ALTER TABLE devices ADD COLUMN IF NOT EXISTS tags text[] NOT NULL DEFAULT '{}';

COMMIT;
