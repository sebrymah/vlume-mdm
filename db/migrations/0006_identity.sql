-- 0006_identity.sql
-- Per-tenant identity provider configuration, and real sessions.
--
-- Each tenant signs in against their own provider: Kalesi against their
-- Microsoft Entra tenant, Arbor against theirs. There is no shared directory
-- of people and there must not be one, so every column here is tenant-scoped
-- and the resolution path is the hostname, exactly as it is for everything
-- else.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_identity (
  tenant_id            uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE RESTRICT,
  issuer               text NOT NULL,
  client_id            text NOT NULL,
  -- Sealed, never plaintext. The Sealer port is in internal/secrets and the
  -- key vault is its real implementation.
  client_secret_sealed bytea NOT NULL,
  redirect_url         text NOT NULL,
  -- Which claim in the identity token carries the person's groups. Entra
  -- and Google name it differently, and a tenant may use a custom one.
  role_claim           text NOT NULL DEFAULT 'groups',
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT issuer_is_https CHECK (issuer LIKE 'https://%' OR issuer LIKE 'http://127.0.0.1%')
);

ALTER TABLE tenant_identity OWNER TO mdm_owner;
ALTER TABLE tenant_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_identity FORCE ROW LEVEL SECURITY;

-- The application sees one tenant's row, as it does everywhere else.
CREATE POLICY identity_tenant_isolation ON tenant_identity
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE ON tenant_identity TO mdm_app;

-- THE ONE CARVE-OUT IN THE ISOLATION MODEL, and it is here rather than
-- buried so that a reviewer meets it.
--
-- Why it has to exist: a browser arrives at /signin holding nothing. We
-- cannot send it to the right identity provider without reading which
-- provider that tenant uses, and we cannot scope that read by a claim
-- because nobody has signed in yet. Every product with per-tenant sign-in
-- has this read; the choice is whether it is written down.
--
-- How narrow it is: SELECT only, one named role, and that role has no write
-- grant on this table and no read grant on any other tenant table. The only
-- sensitive column it can reach is client_secret_sealed, and that is
-- ciphertext whose key lives in the gateway process, never in the database.
-- An attacker who takes the directory's credential gets a list of which
-- identity providers our customers use, and nothing they can sign in with.
CREATE POLICY identity_directory_read ON tenant_identity
  FOR SELECT TO mdm_operator
  USING (true);
GRANT SELECT (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim)
  ON tenant_identity TO mdm_operator;

-- ---------------------------------------------------------------- role map
-- A group in the provider becomes a role here. Nothing is implied: a person
-- whose groups match nothing gets no role and cannot sign in, rather than
-- quietly receiving a default.
CREATE TABLE IF NOT EXISTS tenant_role_map (
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  claim_value text NOT NULL,
  role        text NOT NULL
              CHECK (role IN ('super_admin','it_admin','security_manager','helpdesk','auditor','employee')),
  PRIMARY KEY (tenant_id, claim_value)
);

ALTER TABLE tenant_role_map OWNER TO mdm_owner;
ALTER TABLE tenant_role_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_role_map FORCE ROW LEVEL SECURITY;
CREATE POLICY role_map_tenant_isolation ON tenant_role_map
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, DELETE ON tenant_role_map TO mdm_app;

-- Deliberately NOT granted to mdm_operator. By the time we read this mapping
-- the identity token has already verified, so the tenant is known and a claim
-- can be minted: the read goes through the app role under row-level security
-- like every other tenant read. The directory role's reach stays as small as
-- it was before this migration, minus the one row it genuinely cannot do
-- without (tenant_identity, which it needs to build the redirect before
-- anyone has signed in, and which holds only a sealed secret).

-- ---------------------------------------------------------------- sessions
-- Sessions are signed tokens rather than rows, so there is no lookup before
-- the tenant is known and no table to keep clean. The cost is that a token
-- cannot be revoked one at a time, so this column revokes all of a tenant's
-- at once: set it to now and every session issued earlier stops working.
--
-- It lives on tenants because the directory already reads that row on every
-- request, which makes the check free.
--
-- 'epoch' rather than '-infinity' on purpose: an infinite timestamp is not
-- representable as a Go time.Time, so the driver would have to be taught a
-- special case to read a column whose whole job is to be compared. 1970 is
-- before every session this platform will ever issue.
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS sessions_invalid_before timestamptz NOT NULL
    DEFAULT 'epoch'::timestamptz;

COMMIT;
