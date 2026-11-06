#!/usr/bin/env bash
# Sets up (or brings up to date) the platform's database on Supabase.
#
#   export SUPABASE_DB_URL='postgresql://postgres:<password>@db.<ref>.supabase.co:5432/postgres'
#   ./deploy/supabase/apply.sh
#
# Safe to run again: roles are created once, each migration is applied once
# (recorded in schema_migrations), and the two login passwords are set only
# when this is the first run or you pass them in (APP_PASSWORD, OPERATOR_PASSWORD).
#
# It needs Docker (it runs psql inside a postgres image, so nothing is
# installed on this Mac) and reads the database password only from the
# environment, never from a file or a command line.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${SUPABASE_DB_URL:?set SUPABASE_DB_URL to the direct connection string of the postgres user}"
IMAGE="postgres:17-alpine"
NET=()
[ -n "${APPLY_DOCKER_NETWORK:-}" ] && NET=(--network "$APPLY_DOCKER_NETWORK")

psql_() { docker run --rm -i "${NET[@]}" -e PGCONNECT_TIMEOUT=15 "$IMAGE" psql -v ON_ERROR_STOP=1 -X -q "$SUPABASE_DB_URL" "$@"; }

echo "==> checking the connection"
psql_ -tA -c "select 'connected as ' || current_user || ' to ' || current_database()"
if [ "$(psql_ -tA -c "select rolsuper from pg_roles where rolname = current_user")" = "t" ]; then
  echo "    (a superuser: fine, the preflight is simply harmless)"
fi

echo "==> roles"
psql_ < "$HERE/deploy/supabase/00_roles.sql" >/dev/null

echo "==> migrations"
psql_ -c "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())" >/dev/null
for f in "$HERE"/db/migrations/*.sql; do
  n="$(basename "$f")"
  if [ "$(psql_ -tA -c "select count(*) from schema_migrations where name = '$n'")" = "1" ]; then continue; fi
  psql_ < "$f" >/dev/null
  psql_ -c "insert into schema_migrations (name) values ('$n')" >/dev/null
  echo "    applied $n"
done

echo "==> logins"
# The two roles that serve traffic get passwords. Existing ones are left
# alone unless a password is passed in, so a re-run never locks the gateway out.
gen() { openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-40; }
set_login() { # role variable-name
  local role="$1" var="$2" have pw
  have="$(psql_ -tA -c "select rolcanlogin from pg_roles where rolname = '$role'")"
  pw="${!var:-}"
  if [ "$have" = "t" ] && [ -z "$pw" ]; then echo "    $role can already log in; password unchanged"; return; fi
  [ -n "$pw" ] || pw="$(gen)"
  # Letters and digits only, so the value can sit inside a SQL literal with
  # nothing to escape. It travels on standard input, never on a command line.
  if ! [[ "$pw" =~ ^[A-Za-z0-9]{20,}$ ]]; then echo "$var must be 20 or more letters and digits"; exit 1; fi
  printf "ALTER ROLE %s LOGIN PASSWORD '%s';" "$role" "$pw" | psql_ >/dev/null
  echo "    $role: new password (shown once; put it in the host's secrets now):"
  echo "      $pw"
}
set_login mdm_app APP_PASSWORD
set_login mdm_operator OPERATOR_PASSWORD

echo ""
echo "DONE. $(ls "$HERE"/db/migrations/*.sql | wc -l | tr -d ' ') migrations are in place."
