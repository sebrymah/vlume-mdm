-- 0012_sending_domains.sql
-- A tenant's own sending domain, and the key that signs as it.
--
-- The problem this closes. Mail has been leaving through the operator's
-- server with a From address the tenant chooses, so a message claiming to be
-- from security@kalesi.example fails SPF and has no DKIM signature at all.
-- At a customer running DMARC with p=reject, that mail does not arrive. At
-- one running p=none it arrives in a spam folder and nobody reads the
-- notification about their stolen laptop.
--
-- THE CONTROL THAT MATTERS. Nothing here signs mail as a domain until the
-- tenant has PROVEN they control it, and the proof is the DKIM record
-- itself: we generate a key, they publish our public half in their own DNS,
-- and we look it up. Publishing a record at selector._domainkey.theirdomain
-- requires control of that zone. Without that check, a form field would let
-- any tenant have this platform sign mail as any domain in the world.

BEGIN;

CREATE TABLE IF NOT EXISTS sending_domains (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  domain    text NOT NULL CHECK (domain <> '' AND domain NOT LIKE '%@%'),
  -- The DKIM selector. Per tenant and per domain, so two tenants may
  -- legitimately hold the same domain (two business units of one company)
  -- without sharing a key.
  selector  text NOT NULL CHECK (selector <> ''),

  dkim_private_sealed bytea NOT NULL,
  -- The public half is not a secret: it is published in DNS by design, and
  -- keeping it readable is what lets the console show the record to copy.
  dkim_public text NOT NULL,

  -- The local part of the From address. Separate from the domain so a
  -- tenant can be devices@ rather than notifications@ without re-proving
  -- anything.
  from_local text NOT NULL DEFAULT 'notifications'
             CHECK (from_local <> '' AND from_local NOT LIKE '%@%'),

  -- NULL until the DNS record has actually been seen. Everything that
  -- decides whether to sign reads this column and nothing else.
  verified_at     timestamptz,
  last_checked_at timestamptz,
  last_error      text,

  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (tenant_id, domain)
);

-- Deliberately NOT unique on domain alone.
--
-- Two tenants both verifying kalesi.example means two parties both published
-- a record in that zone, which means both control it: they are the same
-- organisation, or one of them is already compromised and a uniqueness
-- constraint here would not be the thing that saved them. A global unique
-- index would also leak, across the tenant boundary, that somebody else has
-- claimed a domain.
CREATE INDEX IF NOT EXISTS sending_domains_verified
  ON sending_domains (tenant_id) WHERE verified_at IS NOT NULL;

ALTER TABLE sending_domains OWNER TO mdm_owner;
ALTER TABLE sending_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE sending_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY sending_domains_tenant_isolation ON sending_domains
  FOR ALL TO mdm_app
  USING (tenant_id = app.current_tenant())
  WITH CHECK (tenant_id = app.current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON sending_domains TO mdm_app;

-- ------------------------------------------------- verification is a fact
--
-- A row cannot claim to be verified without a time, and cannot be verified
-- while also carrying the error from the check that failed. Those two
-- disagreeing is how a console ends up showing a green tick beside a reason
-- it did not work.
ALTER TABLE sending_domains
  DROP CONSTRAINT IF EXISTS verified_has_no_outstanding_error;
ALTER TABLE sending_domains
  ADD CONSTRAINT verified_has_no_outstanding_error
  CHECK (verified_at IS NULL OR last_error IS NULL);

COMMIT;
