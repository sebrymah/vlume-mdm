-- 0004_branding.sql
-- Per-tenant branding (T4). Brand assets live in tenant configuration, never
-- in code, and the console reads them on every request.
--
-- The design document's rule: "brand is a column, never a build". One
-- deployment, one bundle, no per-tenant compilation. That is only true if the
-- theme is data the renderer reads, which is what this table is.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_branding (
  tenant_id     uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
  product_name  text NOT NULL,
  legal_footer  text NOT NULL DEFAULT '',
  brand_colour  text NOT NULL DEFAULT '#0F6E66',
  mark_letter   text NOT NULL DEFAULT '?',
  updated_at    timestamptz NOT NULL DEFAULT now(),

  -- A tenant that has not replaced the placeholder has not gone live. The
  -- console refuses to hide that, and the onboarding wizard will not let a
  -- tenant finish setup while it is still true.
  CONSTRAINT product_name_not_empty CHECK (length(trim(product_name)) > 0)
);

ALTER TABLE tenant_branding OWNER TO mdm_owner;
ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding FORCE ROW LEVEL SECURITY;

CREATE POLICY branding_tenant_isolation ON tenant_branding
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());

GRANT SELECT, INSERT, UPDATE ON tenant_branding TO mdm_app;

COMMIT;
