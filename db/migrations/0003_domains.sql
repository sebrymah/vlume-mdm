-- 0003_domains.sql
-- Custom domains per tenant (T5), and the plan quotas the gateway rate limits
-- against (T8, R10).
--
-- tenant_domains is the one lookup that is tenant-resolving rather than
-- tenant-scoped: answering "which tenant owns this hostname" necessarily
-- spans tenants, because the caller does not yet know which tenant they are.
--
-- It is therefore NOT readable by mdm_app. It belongs to mdm_operator, which
-- has no access to devices, policies, keys or audit. That separation is the
-- reason this is a second role rather than an exception carved into the first.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_domains (
  host        text PRIMARY KEY,
  tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  verified_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenant_domains OWNER TO mdm_owner;

-- Resolution only. The operator console needs to read it; the application
-- never does, because by the time application code runs the tenant is already
-- decided and carried on the claim.
GRANT SELECT ON tenant_domains TO mdm_operator;

CREATE INDEX IF NOT EXISTS tenant_domains_tenant_idx ON tenant_domains (tenant_id);

-- ---------------------------------------------------------------- plans
-- The quota the gateway enforces. Deliberately on the tenant row rather than
-- in a config file: a quota that lives outside the database is a quota that
-- disagrees with the invoice.
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS api_rate_per_min integer NOT NULL DEFAULT 120,
  ADD COLUMN IF NOT EXISTS device_cap       integer NOT NULL DEFAULT 50;

UPDATE tenants SET api_rate_per_min = 600,  device_cap = 500  WHERE plan = 'growth';
UPDATE tenants SET api_rate_per_min = 2400, device_cap = 2000 WHERE plan = 'scale';

COMMIT;
