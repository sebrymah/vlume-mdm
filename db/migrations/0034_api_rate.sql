-- 0034_api_rate.sql
-- T8: the API rate limit, shared across instances.
--
-- One row per bucket: a key (a tenant id, or a caller address for the
-- routes that have no tenant yet), how many tokens are in it, and when it
-- was last filled. Every instance takes from the same row in one atomic
-- statement, so a plan's limit is the plan's limit however many gateways
-- stand behind the balancer. The table holds no tenant data, only a
-- count against a key the application already knows, which is why it
-- carries no row-level security and the application role may reach it
-- without a tenant claim.

BEGIN;

CREATE TABLE IF NOT EXISTS api_rate (
  key    text PRIMARY KEY,
  tokens double precision NOT NULL,
  last   timestamptz NOT NULL
);
ALTER TABLE api_rate OWNER TO mdm_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_rate TO mdm_app;

COMMIT;
