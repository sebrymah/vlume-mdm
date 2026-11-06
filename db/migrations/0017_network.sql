-- 0017_network.sql
-- Network-side revocation: the credential the network uses to ask us.
--
-- F9's second half is "network-access revocation for non-compliant
-- devices". The network is not ours: it is the tenant's Wi-Fi controller,
-- VPN concentrator, ZTNA gateway or NAC, and the way those revoke access is
-- by asking the device-management platform whether a device may be let in.
-- So this migration builds the thing they ask with: a token a tenant's
-- Super Admin mints for one integration, which can read the access feed and
-- nothing else.
--
-- Why a new table (SD 10). No existing credential fits a machine that is
-- not a device. A device certificate names one device and gets the device
-- role. A session is a person who signed in through the identity provider.
-- The development bearer identities are development only. A network
-- controller is none of those: it is a tenant's machine that needs one
-- narrow read, for years, with no person at a keyboard.
--
-- The token is stored as its SHA-256. It is shown once, at creation, and a
-- copy of this table is not a set of working credentials. Revocation is a
-- timestamp, so the record of what existed stays.

BEGIN;

CREATE TABLE IF NOT EXISTS integration_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name         text NOT NULL,
  token_hash   bytea NOT NULL UNIQUE,
  created_by   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz,
  revoked_by   text,
  CHECK (revoked_at IS NULL OR (revoked_by IS NOT NULL AND revoked_by <> ''))
);

ALTER TABLE integration_tokens OWNER TO mdm_owner;
ALTER TABLE integration_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY integration_tokens_tenant_isolation ON integration_tokens
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON integration_tokens TO mdm_app;
-- No DELETE: a revoked token is a record, not a gap.

CREATE INDEX IF NOT EXISTS integration_tokens_live
  ON integration_tokens (tenant_id) WHERE revoked_at IS NULL;

COMMIT;
