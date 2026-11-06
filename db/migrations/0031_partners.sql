-- 0031_partners.sql
-- T7: the reseller tier.
--
-- A partner is an operator-side account that manages many tenants under a
-- shared brand. It holds ONE token, with which it may create tenants,
-- list its own, read their usage, and suspend or resume them. It may not
-- see a tenant that is not its own, and like the operator it may not see
-- inside any tenant: the partner API runs on the operator's role, which
-- the probe test keeps out of every tenant table. "Strict separation
-- between tenants" is therefore two things here: row-level security
-- inside, and partner_id on the shell outside.
--
-- The partner's brand is the DEFAULT a new tenant starts with, written
-- into the tenant's own branding row at creation; the tenant may change
-- it. The operator's role needs to insert that one row, and nothing else
-- in branding.

BEGIN;

CREATE TABLE IF NOT EXISTS partners (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug          text NOT NULL UNIQUE,
  name          text NOT NULL,
  token_hash    bytea UNIQUE,
  product_name  text NOT NULL DEFAULT '',
  brand_colour  text NOT NULL DEFAULT '',
  legal_footer  text NOT NULL DEFAULT '',
  tenant_cap    integer NOT NULL DEFAULT 25,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);
ALTER TABLE partners OWNER TO mdm_owner;
GRANT SELECT, INSERT, UPDATE ON partners TO mdm_operator;

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS partner_id uuid REFERENCES partners(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS tenants_by_partner ON tenants (partner_id) WHERE partner_id IS NOT NULL;

GRANT INSERT ON tenant_branding TO mdm_operator;
CREATE POLICY branding_operator_seed ON tenant_branding
  FOR INSERT TO mdm_operator WITH CHECK (true);

COMMIT;
