-- 0005_commands.sql
-- The command pipeline. F12 to F15, R1, R4, R6 and R8.
--
-- The rules that matter are enforced here rather than only in Go, because the
-- specification's own words about dual approval are that "the hold is a state
-- in the command lifecycle, not a user-interface confirmation, so it cannot be
-- bypassed by calling the API directly". A rule that lives only in a handler
-- is a rule that one new handler can forget.

BEGIN;

-- A command names a device AND a tenant, and the pair must exist together.
-- Without this a command could reference a device id belonging to another
-- tenant and row-level security would be the only thing stopping it.
ALTER TABLE devices
  ADD CONSTRAINT devices_tenant_id_unique UNIQUE (tenant_id, id);

CREATE TABLE IF NOT EXISTS commands (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid        NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  device_id          uuid        NOT NULL,
  type               text        NOT NULL
                     CHECK (type IN ('lock','lost_mode','clear_passcode','wipe_selective','wipe_full')),
  state              text        NOT NULL DEFAULT 'held'
                     CHECK (state IN ('held','approved','queued','pushed','acknowledged','expired','refused')),
  reversible         boolean     NOT NULL,
  approvals_required smallint    NOT NULL CHECK (approvals_required BETWEEN 1 AND 2),
  requested_by       text        NOT NULL,
  requested_by_role  text        NOT NULL,
  reason             text        NOT NULL,
  payload            jsonb       NOT NULL DEFAULT '{}'::jsonb,

  -- R8: every outbound command is signed. R4: with a one-time code that
  -- expires after 30 minutes and is rejected on replay.
  signature          text,
  nonce              text,
  nonce_expires_at   timestamptz,
  nonce_used_at      timestamptz,

  requested_at       timestamptz NOT NULL DEFAULT now(),
  queued_at          timestamptz,
  pushed_at          timestamptz,
  acknowledged_at    timestamptz,
  refused_at         timestamptz,
  refused_reason     text,

  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE RESTRICT,

  -- Nothing reaches a device unsigned.
  CONSTRAINT signed_once_approved CHECK (
    state NOT IN ('approved','queued','pushed','acknowledged')
    OR (signature IS NOT NULL AND nonce IS NOT NULL AND nonce_expires_at IS NOT NULL)
  ),
  -- A refusal always carries its reason, because a refused action is recorded
  -- as carefully as a permitted one.
  CONSTRAINT refusal_has_a_reason CHECK (
    state <> 'refused' OR (refused_reason IS NOT NULL AND refused_at IS NOT NULL)
  )
);

ALTER TABLE commands OWNER TO mdm_owner;
ALTER TABLE commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE commands FORCE ROW LEVEL SECURITY;
CREATE POLICY commands_tenant_isolation ON commands
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON commands TO mdm_app;

CREATE INDEX IF NOT EXISTS commands_limiter_idx
  ON commands (tenant_id, requested_by, type, requested_at);

-- ---------------------------------------------------------------- approvals
CREATE TABLE IF NOT EXISTS command_approvals (
  id            bigserial PRIMARY KEY,
  tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  command_id    uuid        NOT NULL REFERENCES commands(id) ON DELETE RESTRICT,
  approver      text        NOT NULL,
  approver_role text        NOT NULL,
  decision      text        NOT NULL CHECK (decision IN ('approved','refused')),
  note          text        NOT NULL DEFAULT '',
  decided_at    timestamptz NOT NULL DEFAULT now(),
  -- One person, one decision.
  UNIQUE (command_id, approver)
);

ALTER TABLE command_approvals OWNER TO mdm_owner;
ALTER TABLE command_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE command_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY approvals_tenant_isolation ON command_approvals
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT ON command_approvals TO mdm_app;
GRANT USAGE ON SEQUENCE command_approvals_id_seq TO mdm_app;

-- R6: two approvals, from two distinct roles, neither of them the requester.
--
-- Both halves matter. A requester approving their own request is one person
-- deciding. Two approvals from the same role is one kind of judgement applied
-- twice, which is not what a second opinion means.
CREATE OR REPLACE FUNCTION app.check_approval() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
DECLARE
  c commands%ROWTYPE;
BEGIN
  SELECT * INTO c FROM commands WHERE id = NEW.command_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'approval references a command that does not exist';
  END IF;

  IF NEW.approver = c.requested_by THEN
    RAISE EXCEPTION 'the person who asked for a command may not approve it'
      USING ERRCODE = 'check_violation';
  END IF;

  IF EXISTS (
    SELECT 1 FROM command_approvals a
     WHERE a.command_id = NEW.command_id
       AND a.approver_role = NEW.approver_role
       AND a.decision = 'approved'
  ) THEN
    RAISE EXCEPTION 'two approvals must come from two distinct roles'
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS check_approval_trg ON command_approvals;
CREATE TRIGGER check_approval_trg
  BEFORE INSERT ON command_approvals
  FOR EACH ROW EXECUTE FUNCTION app.check_approval();

COMMIT;
