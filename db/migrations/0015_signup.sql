-- 0015_signup.sql
-- Self-service sign-up: a stranger with a work email becomes a tenant.
--
-- 0014 let the operator create a tenant. This lets a customer do it to
-- themselves, which means the request arrives from nobody we know, on the
-- one hostname that belongs to no tenant. The whole design is about what a
-- stranger can and cannot cause to happen:
--
--   can:     ask for a sign-up, once per address, within the caps below
--   cannot:  create a tenant until they have proven the address is theirs,
--            by opening a link sent to it
--   cannot:  use that proof twice, or late
--
-- A pending sign-up is NOT a tenant and lives in no tenant, so this table is
-- not tenant-scoped: no tenant_id until the tenant exists, no row-level
-- security, and it is deliberately absent from the isolation suite's list of
-- tenant tables. The operator's role owns it the way it owns tenants.
--
-- The token the link carries is stored as its SHA-256. A copy of this table
-- is not a set of working links.
--
-- Why a new table (SD 10): a sign-up that has not finished has nothing to
-- attach to. A tenants row with status 'provisioning' was the existing path
-- and was rejected: it would reserve a slug and a hostname for a stranger who
-- has not yet proven an email address, and the gateway would resolve it.

BEGIN;

CREATE TABLE IF NOT EXISTS signups (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text        NOT NULL,
  email_domain  text        NOT NULL,
  company       text        NOT NULL,
  -- Where the request came from, for the per-address cap and the log.
  requested_ip  text        NOT NULL,
  token_hash    bytea       NOT NULL UNIQUE,
  requested_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  -- The slug is chosen after the link is opened and before the identity
  -- provider is given; it is a draft, not a reservation. Uniqueness is
  -- checked at the moment the tenant is created, by the tenants table.
  slug          text,
  verified_at   timestamptz,
  finished_at   timestamptz,
  tenant_id     uuid REFERENCES tenants(id) ON DELETE RESTRICT,
  CHECK (finished_at IS NULL OR tenant_id IS NOT NULL)
);

-- The caps count rows in a window by domain and by address.
CREATE INDEX IF NOT EXISTS signups_domain_time ON signups (email_domain, requested_at);
CREATE INDEX IF NOT EXISTS signups_ip_time     ON signups (requested_ip, requested_at);

ALTER TABLE signups OWNER TO mdm_owner;
GRANT SELECT, INSERT, UPDATE ON signups TO mdm_operator;
-- Not the application role. A tenant's console has no business reading
-- who else has asked to become a tenant.

COMMIT;
