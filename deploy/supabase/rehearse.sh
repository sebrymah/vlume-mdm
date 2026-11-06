#!/usr/bin/env bash
# Applies the preflight and every migration as a role limited the way
# Supabase's `postgres` is (no superuser; may create roles; bypasses RLS),
# on a throwaway Postgres. Stops at the first failing file and names it.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
C=mdm-supa-rehearsal
docker rm -f $C >/dev/null 2>&1
docker run -d --name $C -e POSTGRES_PASSWORD=x -e POSTGRES_DB=postgres postgres:17-alpine >/dev/null
for i in $(seq 1 60); do docker exec $C psql -U postgres -tAc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
docker exec $C psql -U postgres -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE supa NOSUPERUSER CREATEROLE CREATEDB BYPASSRLS LOGIN PASSWORD 'x';" \
  -c "CREATE DATABASE mdm OWNER supa;" >/dev/null
run() { docker exec -i $C psql -v ON_ERROR_STOP=1 -U supa -d mdm -f - < "$1" 2>&1; }
out=$(run "$HERE/deploy/supabase/00_roles.sql") || { echo "FAIL 00_roles.sql"; echo "$out" | grep -m3 ERROR; exit 1; }
for f in "$HERE"/db/migrations/*.sql; do
  out=$(run "$f") || { echo "FAIL $(basename "$f")"; echo "$out" | grep -m3 ERROR; exit 1; }
done
echo "ALL $(ls "$HERE"/db/migrations/*.sql | wc -l | tr -d ' ') MIGRATIONS APPLIED as a non-superuser"

# The isolation suite, run as that same limited role. It needs to act as the
# two serving roles, which the migrating user is not normally able to do.
docker exec $C psql -U supa -d mdm -v ON_ERROR_STOP=1 -c "GRANT mdm_app, mdm_operator TO supa" >/dev/null
out=$(run "$HERE/db/isolation/suite.sql") || { echo "ISOLATION SUITE FAILED on the limited role"; echo "$out" | grep -m5 "ERROR\|FAIL"; exit 1; }
echo "$out" | grep "assertions passed"
# Negative control: the suite must fail when the protection is gone.
docker exec $C psql -U supa -d mdm -v ON_ERROR_STOP=1 -c "ALTER TABLE devices DISABLE ROW LEVEL SECURITY" >/dev/null
if run "$HERE/db/isolation/suite.sql" >/dev/null; then echo "NEGATIVE CONTROL FAILED"; exit 1; fi
echo "NEGATIVE CONTROL PASSED: the suite fails when row-level security is off"
docker rm -f $C >/dev/null 2>&1
