-- 0047: policy settings per operating system.
--
-- A policy now carries, beside its rules, a "config" object in its body:
-- the settings it applies, from the catalogue for its operating system
-- (internal/catalog). The body is already jsonb, so storing it needs nothing
-- new. What does need something is Android delivery: a company phone and a
-- work-profile phone are given different Google policies now, and a bound
-- enterprise needs to say when the personal one was last delivered, so a
-- token for a personal phone is never made for a policy Google does not
-- have yet.

BEGIN;

ALTER TABLE android_enterprises
  ADD COLUMN IF NOT EXISTS personal_policy_at timestamptz;

COMMIT;
