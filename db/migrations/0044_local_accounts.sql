-- 0044: sign-in for a tenant that has no identity provider.
--
-- Until now a tenant's people were always somebody else's directory:
-- Entra, Google, Okta, an ADFS. A customer without one could not sign in
-- at all. This adds the third mode, `local`: accounts held here, with a
-- password (argon2id, never the password itself) and a second factor
-- (TOTP, the secret sealed under the tenant's own key) that administrative
-- roles must have.
--
-- It is a mode of the tenant, not a second door on every tenant: a tenant
-- with an identity provider takes its people from there and its local
-- accounts, if any, do not sign in. A password account would otherwise be a
-- way round the provider's own controls, offboarding above all.

BEGIN;

ALTER TABLE tenant_identity DROP CONSTRAINT IF EXISTS tenant_identity_protocol_check;
ALTER TABLE tenant_identity ADD CONSTRAINT tenant_identity_protocol_check
  CHECK (protocol IN ('oidc', 'saml', 'local'));

ALTER TABLE tenant_identity DROP CONSTRAINT IF EXISTS issuer_is_https;
ALTER TABLE tenant_identity ADD CONSTRAINT issuer_is_https
  CHECK (protocol IN ('saml', 'local') OR issuer LIKE 'https://%' OR issuer LIKE 'http://127.0.0.1%');

-- Who must have the second factor: the roles that can lock, wipe, approve
-- and read keys ('admins'), or everybody ('everyone'). Only meaningful in
-- local mode.
ALTER TABLE tenant_identity
  ADD COLUMN IF NOT EXISTS local_mfa text NOT NULL DEFAULT 'admins'
    CHECK (local_mfa IN ('admins', 'everyone'));
GRANT SELECT (local_mfa) ON tenant_identity TO mdm_operator;

-- ------------------------------------------------------------- accounts

CREATE TABLE IF NOT EXISTS local_accounts (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  email            text NOT NULL CHECK (email = lower(email) AND email LIKE '_%@_%'),
  name             text NOT NULL DEFAULT '',
  role             text NOT NULL
                   CHECK (role IN ('super_admin','it_admin','security_manager','helpdesk','auditor','employee')),
  status           text NOT NULL CHECK (status IN ('invited','active','disabled')),
  password_hash    text NOT NULL DEFAULT '',
  password_set_at  timestamptz,
  -- The second factor. The secret is sealed under the tenant's key; it is
  -- set when enrolment starts and only counts once totp_enabled is true.
  totp_secret_sealed bytea,
  totp_enabled     boolean NOT NULL DEFAULT false,
  -- The last time-step a code was accepted for. A code is good once.
  totp_last_step   bigint NOT NULL DEFAULT 0,
  -- SHA-256 of each unused recovery code. Spending one removes it.
  recovery_hashes  text[] NOT NULL DEFAULT '{}',
  failed_count     integer NOT NULL DEFAULT 0,
  locked_until     timestamptz,
  created_by       text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_sign_in_at  timestamptz,
  UNIQUE (tenant_id, email),
  UNIQUE (tenant_id, id),
  CHECK (status <> 'active' OR password_hash <> ''),
  CHECK (NOT totp_enabled OR totp_secret_sealed IS NOT NULL)
);
ALTER TABLE local_accounts OWNER TO mdm_owner;
ALTER TABLE local_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE local_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY local_accounts_tenant_isolation ON local_accounts
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
-- No DELETE for the application: an account is disabled, not removed, so
-- the audit log and the devices assigned to it keep a person to point at.
GRANT SELECT, INSERT, UPDATE ON local_accounts TO mdm_app;
GRANT SELECT, DELETE ON local_accounts TO mdm_reaper;

-- The operator opens the door for the first administrator, as it does for
-- the first role mapping, and cannot read or change anything afterwards.
-- INSERT only, and only a Super Admin.
GRANT INSERT ON local_accounts TO mdm_operator;
CREATE POLICY local_accounts_operator_seed ON local_accounts
  FOR INSERT TO mdm_operator
  WITH CHECK (role = 'super_admin' AND status IN ('invited', 'active'));

-- --------------------------------------------------------------- tokens
--
-- An invitation, or a password reset: 256 random bits in a link, kept as
-- their SHA-256, good once and for a limited time. A copy of this table is
-- not a set of working links.

CREATE TABLE IF NOT EXISTS local_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  account_id  uuid NOT NULL,
  purpose     text NOT NULL CHECK (purpose IN ('invite', 'reset')),
  token_hash  bytea NOT NULL UNIQUE,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, account_id) REFERENCES local_accounts (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE local_tokens OWNER TO mdm_owner;
ALTER TABLE local_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE local_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY local_tokens_tenant_isolation ON local_tokens
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON local_tokens TO mdm_app;
GRANT SELECT, DELETE ON local_tokens TO mdm_reaper;
CREATE INDEX IF NOT EXISTS local_tokens_by_account ON local_tokens (tenant_id, account_id, purpose);

GRANT INSERT ON local_tokens TO mdm_operator;
CREATE POLICY local_tokens_operator_seed ON local_tokens
  FOR INSERT TO mdm_operator
  WITH CHECK (purpose = 'invite');

CREATE OR REPLACE FUNCTION app.tenant_tables() RETURNS text[] AS $$
  SELECT ARRAY['command_approvals','commands','device_compliance','device_compliance_history','device_certificates',
               'device_apps','device_recovery_keys','device_macs',
               'enrolments','devices','people','local_tokens','local_accounts','policies','audit_events','tenant_branding',
               'tenant_identity','tenant_role_map','tenant_ca','notification_targets',
               'notifications','sending_domains','integration_tokens',
               'android_enrollment_tokens','android_enterprises','siem_cursors','signups',
               'usage_snapshots','compliance_snapshots','tenant_domains','tenant_keys','tenant_admins',
               'command_signing_keys']
$$ LANGUAGE sql IMMUTABLE;

COMMIT;
