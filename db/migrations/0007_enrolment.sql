-- 0007_enrolment.sql
-- Enrolment: how a device becomes a device this platform knows about, and
-- how it proves that afterwards.
--
-- The gap this closes. Since the gateway sprint, a request carrying a client
-- certificate whose organisational unit is a tenant and whose common name is
-- a device has been trusted as that device. Nothing issued those
-- certificates and nothing checked that we had. The trust anchor was
-- dangling: correct in shape, attached to nothing.
--
-- So this migration brings three things, and they are in one migration
-- because none of them is useful alone:
--
--   tenant_ca            each tenant's own certificate authority
--   device_certificates  what it has issued, and what has been revoked
--   enrolments           the one-time invitation that gets a device there

BEGIN;

-- ------------------------------------------------------------- the authority
--
-- One authority per tenant, not one for the platform. A shared authority
-- would mean every tenant's devices chain to the same root, so a certificate
-- issued for one tenant would be cryptographically indistinguishable from
-- one issued for another and the only thing keeping them apart would be the
-- organisational unit field. That is a string comparison standing in for a
-- trust boundary. Separate authorities make a Kalesi certificate fail to
-- verify against Arbor's root at all.
CREATE TABLE IF NOT EXISTS tenant_ca (
  tenant_id          uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
  certificate        bytea NOT NULL,          -- DER
  private_key_sealed bytea NOT NULL,          -- sealed, never the key itself
  subject            text  NOT NULL,
  not_before         timestamptz NOT NULL,
  not_after          timestamptz NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ca_validity_is_ordered CHECK (not_after > not_before)
);

ALTER TABLE tenant_ca OWNER TO mdm_owner;
ALTER TABLE tenant_ca ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_ca FORCE ROW LEVEL SECURITY;
CREATE POLICY ca_tenant_isolation ON tenant_ca
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());

-- No DELETE, and no UPDATE of an existing authority. Replacing a tenant's
-- authority invalidates every device certificate it has issued, which is a
-- deliberate operation with its own re-enrolment, not something a writer
-- should be able to do by accident.
GRANT SELECT, INSERT ON tenant_ca TO mdm_app;

-- Deliberately NOT granted to mdm_operator. Unlike tenant_identity, nothing
-- needs this before a tenant is known: enrolment arrives on the tenant's own
-- hostname with a token, and a device arrives on it with a certificate. The
-- carve-out stays at one table.

-- ------------------------------------------------------- what it has issued
CREATE TABLE IF NOT EXISTS device_certificates (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  device_id     uuid NOT NULL,
  -- Hex, because a 128-bit serial does not fit in a bigint and storing it as
  -- numeric invites arithmetic nobody wants performed on a serial number.
  serial        text  NOT NULL,
  fingerprint   bytea NOT NULL,                -- sha256 of the DER
  not_before    timestamptz NOT NULL,
  not_after     timestamptz NOT NULL,
  issued_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz,
  revoked_reason text,

  UNIQUE (tenant_id, serial),
  UNIQUE (tenant_id, fingerprint),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE RESTRICT,
  CONSTRAINT cert_validity_is_ordered CHECK (not_after > not_before),
  -- The same rule the command pipeline has: a refusal that does not say why
  -- is a refusal nobody can act on.
  CONSTRAINT revocation_has_a_reason
    CHECK (revoked_at IS NULL OR (revoked_reason IS NOT NULL AND revoked_reason <> ''))
);

CREATE INDEX IF NOT EXISTS device_certificates_lookup
  ON device_certificates (tenant_id, fingerprint);

ALTER TABLE device_certificates OWNER TO mdm_owner;
ALTER TABLE device_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY device_certificates_tenant_isolation ON device_certificates
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());

-- UPDATE is granted because revocation is an update. DELETE is not: the
-- record of a certificate having existed outlives the certificate, which is
-- what makes it possible to answer "what did that device present in March".
GRANT SELECT, INSERT, UPDATE ON device_certificates TO mdm_app;

-- -------------------------------------------------------- the invitation
--
-- An enrolment is a one-time invitation with an expiry. The token itself is
-- never stored: only its hash, for the same reason a password is never
-- stored. Someone who reads this table cannot enrol a device with what they
-- find there.
CREATE TABLE IF NOT EXISTS enrolments (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  token_hash   bytea NOT NULL,
  -- What an administrator calls it before the device has a name of its own.
  label        text  NOT NULL CHECK (label <> ''),
  ownership    text  NOT NULL CHECK (ownership IN ('company','personal')),
  os_family    text  NOT NULL CHECK (os_family IN ('macos','ios','ipados','android','windows')),
  created_by   text  NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  state        text  NOT NULL DEFAULT 'pending'
               CHECK (state IN ('pending','completed','revoked')),
  opened_at    timestamptz,
  completed_at timestamptz,
  device_id    uuid,

  -- Per tenant, so two tenants' tokens cannot collide into one row and a
  -- token is only ever looked up inside the tenant the hostname named.
  UNIQUE (tenant_id, token_hash),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id) ON DELETE RESTRICT,

  -- The state machine, in the schema rather than only in Go. A completed
  -- enrolment that names no device is the bug this catches: it would mean a
  -- token was spent and nothing came back.
  CONSTRAINT completed_has_a_device
    CHECK (state <> 'completed' OR (device_id IS NOT NULL AND completed_at IS NOT NULL)),
  CONSTRAINT pending_has_no_device
    CHECK (state <> 'pending' OR device_id IS NULL),
  CONSTRAINT enrolment_expires_after_it_is_made
    CHECK (expires_at > created_at)
);

ALTER TABLE enrolments OWNER TO mdm_owner;
ALTER TABLE enrolments ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrolments FORCE ROW LEVEL SECURITY;
CREATE POLICY enrolments_tenant_isolation ON enrolments
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON enrolments TO mdm_app;

-- ----------------------------------------------------- redeeming once, only
--
-- The race this closes: two requests arrive with the same valid token at the
-- same moment, both read state 'pending', both issue a certificate, and the
-- tenant acquires a device they did not enrol. SELECT ... FOR UPDATE in the
-- application would do it, and the application does use it, but a rule this
-- important should not live only in a line of Go that a later refactor can
-- move outside the transaction.
--
-- So the transition is a trigger: pending is the only state a redemption may
-- start from, and only the row that gets there first finds it.
CREATE OR REPLACE FUNCTION app.check_enrolment_transition() RETURNS trigger AS $$
BEGIN
  IF OLD.state = 'completed' AND NEW.state <> 'completed' THEN
    RAISE EXCEPTION 'a completed enrolment cannot be reopened (enrolment %)', OLD.id;
  END IF;
  IF OLD.state = 'revoked' AND NEW.state <> 'revoked' THEN
    RAISE EXCEPTION 'a revoked enrolment cannot be reinstated (enrolment %)', OLD.id;
  END IF;
  IF NEW.state = 'completed' AND OLD.state <> 'pending' THEN
    RAISE EXCEPTION 'only a pending enrolment can be completed (enrolment % was %)',
      OLD.id, OLD.state;
  END IF;
  -- The token is spent. Nothing may move the device it produced, because
  -- that would silently transfer a certificate to another machine.
  IF OLD.device_id IS NOT NULL AND NEW.device_id IS DISTINCT FROM OLD.device_id THEN
    RAISE EXCEPTION 'an enrolment cannot be pointed at a different device (enrolment %)', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS enrolment_transition ON enrolments;
CREATE TRIGGER enrolment_transition
  BEFORE UPDATE ON enrolments
  FOR EACH ROW EXECUTE FUNCTION app.check_enrolment_transition();

COMMIT;
