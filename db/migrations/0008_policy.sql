-- 0008_policy.sql
-- Policy: what a tenant requires of its devices, and whether each device
-- meets it.
--
-- The policies table has existed since 0002 with a name, a version and a
-- jsonb body. This migration gives it the two things it needed to be usable
-- (who it applies to, and whether it is switched on) and adds the other half
-- of the loop: what each device last reported, and the verdict on it.
--
-- One thing deliberately NOT here: an enforcement table. Non-compliance
-- produces a state and a list of findings and stops. Acting on it goes
-- through the command pipeline, which already requires a named reason, a
-- role that may ask, and for anything irreversible a second person. Wiring a
-- compliance signal straight to a destructive action would route around the
-- one control this platform has that a human cannot be talked past.

BEGIN;

-- ------------------------------------------------------------- who it is for
--
-- Scope is two nullable columns rather than a rules engine. NULL means "any",
-- so a policy with both NULL applies to every device in the tenant, and one
-- with os_family='macos' applies to the Macs. That is a deliberately small
-- vocabulary: device groups and tags are the obvious next want and are listed
-- as not built, because the moment scoping becomes expressive it also becomes
-- impossible to answer "what does this laptop actually have to do" without
-- running the engine.
ALTER TABLE policies
  ADD COLUMN IF NOT EXISTS scope_os_family text
    CHECK (scope_os_family IS NULL OR
           scope_os_family IN ('macos','ios','ipados','android','windows')),
  ADD COLUMN IF NOT EXISTS scope_ownership text
    CHECK (scope_ownership IS NULL OR scope_ownership IN ('company','personal')),
  -- A superseded version stays in the table. Editing a policy writes a new
  -- version and switches the old one off, so "what did we require in March"
  -- is answerable from the row rather than from a backup.
  ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT '';

-- Only one version of a given policy may be live at a time. Without this,
-- two versions of "Baseline" could both apply and the engine would merge a
-- policy with itself, which is harmless today only because the merge takes
-- the stricter value.
CREATE UNIQUE INDEX IF NOT EXISTS policies_one_active_version
  ON policies (tenant_id, name) WHERE active;

-- The composite key the compliance table points at, so a verdict cannot
-- outlive or cross-reference the wrong policy row.
CREATE UNIQUE INDEX IF NOT EXISTS policies_tenant_id_id ON policies (tenant_id, id);

-- --------------------------------------------------- what the device said
--
-- One row per device: the latest report and the latest verdict together,
-- because they are only meaningful as a pair. A verdict without the report
-- it was reached from cannot be explained to the person whose laptop was
-- just marked non-compliant.
--
-- Report history is NOT kept. It is the obvious next want for a product that
-- wants to show a compliance trend, and it is listed as not built rather than
-- half-built here.
CREATE TABLE IF NOT EXISTS device_compliance (
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  device_id    uuid NOT NULL,
  reported_at  timestamptz NOT NULL,
  report       jsonb NOT NULL,
  evaluated_at timestamptz NOT NULL,
  state        text NOT NULL
               CHECK (state IN ('compliant','not_compliant','state_unknown')),
  -- Each finding says which rule failed, what the device said, and which
  -- policy asked for it. A finding that cannot name its policy is a finding
  -- nobody can act on.
  findings     jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- Which policy versions produced this verdict, so a verdict can be
  -- re-explained after the policy has moved on.
  policies     jsonb NOT NULL DEFAULT '[]'::jsonb,

  PRIMARY KEY (tenant_id, device_id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE RESTRICT,

  -- A compliant device with findings against it, or a failing one with none,
  -- is a verdict that disagrees with its own evidence.
  CONSTRAINT compliant_means_nothing_failed
    CHECK (state <> 'compliant' OR jsonb_array_length(findings) = 0),
  CONSTRAINT not_compliant_means_something_failed
    CHECK (state <> 'not_compliant' OR jsonb_array_length(findings) > 0)
);

ALTER TABLE device_compliance OWNER TO mdm_owner;
ALTER TABLE device_compliance ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_compliance FORCE ROW LEVEL SECURITY;
CREATE POLICY device_compliance_tenant_isolation ON device_compliance
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON device_compliance TO mdm_app;

CREATE INDEX IF NOT EXISTS device_compliance_by_state
  ON device_compliance (tenant_id, state);

-- ------------------------------------------- the states evaluation may set
--
-- A device that has been quarantined or retired is in that state because a
-- person put it there. A good report must not quietly undo that: the whole
-- point of quarantining a machine is that it stays quarantined until someone
-- decides otherwise, and a laptop that has just been wiped and is sending
-- cheerful reports is exactly the case this protects.
--
-- So evaluation may only move a device between the three states it owns.
-- Everything else is administrative and is left alone.
CREATE OR REPLACE FUNCTION app.check_device_state_transition() RETURNS trigger AS $$
BEGIN
  IF NEW.state IS DISTINCT FROM OLD.state
     AND OLD.state IN ('quarantined','retired')
     AND NEW.state IN ('compliant','not_compliant','state_unknown') THEN
    RAISE EXCEPTION
      'a % device cannot be moved to % by evaluation (device %)',
      OLD.state, NEW.state, OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS device_state_transition ON devices;
CREATE TRIGGER device_state_transition
  BEFORE UPDATE ON devices
  FOR EACH ROW EXECUTE FUNCTION app.check_device_state_transition();

COMMIT;
