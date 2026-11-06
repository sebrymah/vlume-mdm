#!/usr/bin/env bash
# run.sh — brings up a throwaway PostgreSQL, applies the migrations, and runs
# the T13 cross-tenant isolation suite against it.
#
#   ./run.sh                  apply migrations, run the suite, expect a pass
#   ./run.sh --break-rls      remove the protection first, expect a FAILURE
#
# The second mode is the negative control. A suite that has never failed
# proves nothing, so the build proves the suite is doing work before it
# trusts a pass.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER="mdm-pg-isolation"
IMAGE="postgres:17-alpine"
PGPASS="isolation-suite-local-only"
MODE="${1:-normal}"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> starting $IMAGE as $CONTAINER"
cleanup
docker run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD="$PGPASS" \
  -e POSTGRES_DB=mdm \
  "$IMAGE" >/dev/null

echo "==> waiting for the database to exist and answer"
# pg_isready reports ready during the image's own bootstrap, before the
# requested database has been created. Wait for a real query instead.
READY=0
for i in $(seq 1 60); do
  if docker exec "$CONTAINER" psql -U postgres -d mdm -tAc 'select 1' >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  echo "database did not become available in 60 seconds"
  docker logs "$CONTAINER" 2>&1 | tail -20
  exit 1
fi

psql_file() {
  docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d mdm -f - < "$1"
}

echo "==> applying migrations"
for f in "$HERE"/migrations/*.sql; do
  echo "    $(basename "$f")"
  psql_file "$f" >/dev/null
done

if [ "$MODE" = "--break-rls" ]; then
  echo "==> NEGATIVE CONTROL: removing the isolation policy from devices"
  docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d mdm \
    -c "DROP POLICY devices_tenant_isolation ON devices;" \
    -c "ALTER TABLE devices DISABLE ROW LEVEL SECURITY;" >/dev/null
fi
if [ "$MODE" = "--break-personrls" ]; then
  echo "==> NEGATIVE CONTROL: removing the person isolation policy from devices"
  docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d mdm \
    -c "DROP POLICY devices_person_isolation ON devices;" >/dev/null
fi

echo "==> running the isolation suite"
set +e
docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d mdm -f - \
  < "$HERE/isolation/suite.sql" 2>&1
RESULT=$?
set -e

echo ""
if [ "$MODE" = "--break-rls" ] || [ "$MODE" = "--break-personrls" ]; then
  if [ $RESULT -eq 0 ]; then
    echo "NEGATIVE CONTROL FAILED: the suite passed with the protection removed."
    echo "The suite is not testing what it claims to test."
    exit 1
  fi
  echo "NEGATIVE CONTROL PASSED: the suite caught the removed protection."
  exit 0
fi

if [ $RESULT -ne 0 ]; then
  echo "ISOLATION SUITE FAILED. This fails the build. There is no override."
  exit 1
fi
echo "ISOLATION SUITE PASSED."
