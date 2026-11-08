#!/usr/bin/env bash
# Read-only check of the platform's database. Changes nothing.
#   export SUPABASE_DB_URL='postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres'
#   ./deploy/supabase/verify.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${SUPABASE_DB_URL:?SUPABASE_DB_URL is not set in this Terminal window. Run the export line first.}"
export SUPABASE_DB_URL
NET=(); [ -n "${APPLY_DOCKER_NETWORK:-}" ] && NET=(--network "$APPLY_DOCKER_NETWORK")
q() { docker run --rm -i ${NET[@]+"${NET[@]}"} -e PGCONNECT_TIMEOUT=15 -e SUPABASE_DB_URL postgres:17-alpine \
        sh -c 'exec psql -X -q -tA "$SUPABASE_DB_URL" -c "$0"' "$1" 2>&1; }
bad=0
check() { # label  actual  expected
  if [ "$2" = "$3" ]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s (got "%s", want "%s")\n' "$1" "$2" "$3"; bad=1; fi
}

echo "Connecting..."
who="$(q "select current_user || ' on ' || current_database()")"
case "$who" in *" on "*) echo "  PASS  connected as $who" ;; *) echo "  FAIL  could not connect:"; echo "$who" | head -3; exit 1 ;; esac

want=$(ls "$HERE"/db/migrations/*.sql | wc -l | tr -d ' ')
check "all $want migrations recorded" "$(q "select count(*) from schema_migrations")" "$want"
check "the seven platform roles exist" "$(q "select count(*) from pg_roles where rolname in ('mdm_owner','mdm_app','mdm_operator','mdm_reaper','mdm_meter','mdm_importer','mdm_keymaster')")" "7"
check "mdm_app can log in" "$(q "select rolcanlogin from pg_roles where rolname='mdm_app'")" "t"
check "mdm_operator can log in" "$(q "select rolcanlogin from pg_roles where rolname='mdm_operator'")" "t"
check "mdm_app cannot bypass row-level security" "$(q "select rolbypassrls from pg_roles where rolname='mdm_app'")" "f"
check "mdm_operator cannot bypass row-level security" "$(q "select rolbypassrls from pg_roles where rolname='mdm_operator'")" "f"
check "tenant data has row-level security forced on" "$(q "select count(*) > 10 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r' and c.relforcerowsecurity")" "t"
check "Supabase's API roles hold no rights on the platform's tables" "$(q "select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace, lateral aclexplode(c.relacl) a join pg_roles g on g.oid=a.grantee where n.nspname in ('public','app') and g.rolname in ('anon','authenticated','service_role')")" "0"
check "no customer data yet (a fresh database)" "$(q "select count(*) from tenants")" "0"
echo
if [ "$bad" = 0 ]; then echo "ALL CHECKS PASSED. The database is set up."; else echo "SOMETHING IS NOT RIGHT. Paste this output to me."; exit 1; fi
