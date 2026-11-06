#!/usr/bin/env bash
# demo.sh — runs the whole platform on this machine so it can be looked at.
#
#   ./demo.sh          start it (or restart the app over the same database)
#   ./demo.sh stop     stop it and remove the containers, data included
#   ./demo.sh reset    the same as stop, then start again from nothing
#
# Needs Docker and nothing else: no Go toolchain, no local PostgreSQL.
#
# This is a DEMONSTRATION. The identity provider is local and asks for no
# password, cookies are sent without the Secure attribute because this serves
# plain HTTP, and the signing keys are fixed strings. cmd/gateway, the real
# entry point, refuses to start without the things this one supplies.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET="mdm-demo"
PG="mdm-demo-pg"
APP="mdm-demo-app"
PGIMAGE="postgres:17-alpine"
GOIMAGE="golang:1.23-alpine"
SUPERPASS="demo-local-only"
APPPASS="demo-app-local-only"
OPPASS="demo-operator-local-only"

# A developer machine often already has something on 8080. Pick the first
# free pair rather than failing with a port-in-use error ten steps later.
pick_ports() {
  for base in 8090 8100 8110 9080 9090; do
    if ! lsof -nP -iTCP:$base -sTCP:LISTEN >/dev/null 2>&1 &&
       ! lsof -nP -iTCP:$((base + 1)) -sTCP:LISTEN >/dev/null 2>&1 &&
       ! lsof -nP -iTCP:$((base + 2)) -sTCP:LISTEN >/dev/null 2>&1; then
      CONSOLE_PORT=$base
      IDP_PORT=$((base + 1))
      TLS_PORT=$((base + 2))
      return
    fi
  done
  echo "could not find three free ports"; exit 1
}
pick_ports

# stop halts both containers but keeps the database container, so what it
# recorded (an enterprise bound at the real Google) is still there at the
# next start. Only reset removes it. Before 2026-11-05 stop removed both,
# and one stop was enough to lose a real binding.
stop() {
  docker rm -f "$APP" >/dev/null 2>&1 || true
  docker stop "$PG" >/dev/null 2>&1 || true
}
wipe() {
  docker rm -f "$APP" "$PG" >/dev/null 2>&1 || true
}

case "${1:-up}" in
  stop)
    stop
    echo "Stopped. The database is kept for the next start (./demo.sh reset removes it)."
    exit 0 ;;
  reset)
    wipe ;;
  up) ;;
  *) echo "usage: ./demo.sh [stop|reset]"; exit 1 ;;
esac

# The app container is replaced on every start; the database is kept if it
# is already running, so what a real integration recorded (an Android
# enterprise bound at Google, say) survives a restart. ./demo.sh reset
# starts from nothing.
docker rm -f "$APP" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null 2>&1 || true

if docker ps --format '{{.Names}}' | grep -qx "$PG"; then
  echo "==> PostgreSQL is already running; keeping its data (./demo.sh reset starts clean)"
elif docker ps -a --format '{{.Names}}' | grep -qx "$PG"; then
  echo "==> PostgreSQL was stopped; starting it again with its data (./demo.sh reset starts clean)"
  docker start "$PG" >/dev/null
else
  docker rm -f "$PG" >/dev/null 2>&1 || true
  echo "==> starting PostgreSQL"
  docker run -d --name "$PG" --network "$NET" \
    -e POSTGRES_PASSWORD="$SUPERPASS" -e POSTGRES_DB=mdm "$PGIMAGE" >/dev/null
fi

echo "==> waiting for it to answer"
for i in $(seq 1 60); do
  docker exec "$PG" psql -U postgres -d mdm -tAc 'select 1' >/dev/null 2>&1 && break
  sleep 1
  if [ "$i" -eq 60 ]; then echo "database did not start"; docker logs "$PG" | tail -20; exit 1; fi
done

# Migrations are applied once each and written down, so a kept database
# takes only the new ones on the next start. A database that predates the
# ledger (tables, no ledger) is taken to be at the newest migration that
# existed when it was made; that is this machine's one such database, and
# any other is better served by ./demo.sh reset.
echo "==> applying migrations"
docker exec -i "$PG" psql -v ON_ERROR_STOP=1 -U postgres -d mdm \
  -c "CREATE TABLE IF NOT EXISTS demo_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())" >/dev/null
if [ "$(docker exec "$PG" psql -U postgres -d mdm -tAc "select count(*) from demo_migrations")" = "0" ] &&
   [ "$(docker exec "$PG" psql -U postgres -d mdm -tAc "select count(*) from pg_tables where tablename = 'tenants'")" = "1" ]; then
  echo "    (a database from before the migration ledger: recording every migration as applied)"
  for f in "$HERE"/db/migrations/*.sql; do
    docker exec "$PG" psql -U postgres -d mdm -tAc "insert into demo_migrations (name) values ('$(basename "$f")') on conflict do nothing" >/dev/null
  done
fi
for f in "$HERE"/db/migrations/*.sql; do
  n="$(basename "$f")"
  if [ "$(docker exec "$PG" psql -U postgres -d mdm -tAc "select count(*) from demo_migrations where name = '$n'")" = "1" ]; then
    continue
  fi
  docker exec -i "$PG" psql -v ON_ERROR_STOP=1 -U postgres -d mdm -f - < "$f" >/dev/null
  docker exec "$PG" psql -U postgres -d mdm -tAc "insert into demo_migrations (name) values ('$n')" >/dev/null
  echo "    applied $n"
done

docker exec -i "$PG" psql -v ON_ERROR_STOP=1 -U postgres -d mdm \
  -c "ALTER ROLE mdm_app LOGIN PASSWORD '${APPPASS}';" \
  -c "ALTER ROLE mdm_operator LOGIN PASSWORD '${OPPASS}';" \
  -c "GRANT CONNECT ON DATABASE mdm TO mdm_app, mdm_operator;" >/dev/null

# Android Enterprise against the real Google: export
# MDM_ANDROID_CREDENTIALS_FILE=/path/to/service-account.json before running
# this, and the key is mounted read-only into the container. Without it the
# demonstration uses its own fake of Google.
ANDROID_ARGS=()
if [ -n "${MDM_ANDROID_CREDENTIALS_FILE:-}" ]; then
  if [ ! -r "$MDM_ANDROID_CREDENTIALS_FILE" ]; then
    echo "MDM_ANDROID_CREDENTIALS_FILE is set but cannot be read: $MDM_ANDROID_CREDENTIALS_FILE"; exit 1
  fi
  ANDROID_ARGS=(-v "$MDM_ANDROID_CREDENTIALS_FILE":/etc/mdm/android-service-account.json:ro
                -e MDM_ANDROID_CREDENTIALS_FILE=/etc/mdm/android-service-account.json)
  echo "==> Android Enterprise: using the real Google with $MDM_ANDROID_CREDENTIALS_FILE"
  # Remember that this database's enterprise is a real one at Google.
  docker exec "$PG" psql -U postgres -d mdm -tAc \
    "create table if not exists demo_state (key text primary key, value text not null);
     insert into demo_state values ('android','real') on conflict (key) do update set value = 'real'" >/dev/null
else
  # A restart without the key would run the fake, and the seed clears the
  # fake's enterprises because the fake forgets them. That must never clear
  # one bound at the real Google (it happened once, 2026-11-05: a shell
  # without the variable restarted the demo and the binding was gone), so a
  # database last run against the real Google refuses to start the fake.
  if [ "$(docker exec "$PG" psql -U postgres -d mdm -tAc "select count(*) from pg_tables where tablename = 'demo_state'")" = "1" ] &&
     [ "$(docker exec "$PG" psql -U postgres -d mdm -tAc "select value from demo_state where key = 'android'")" = "real" ] &&
     [ "$(docker exec "$PG" psql -U postgres -d mdm -tAc "select count(*) from android_enterprises")" != "0" ]; then
    echo ""
    echo "This demo's Android enterprise is bound at the real Google (it was last started with"
    echo "MDM_ANDROID_CREDENTIALS_FILE). Starting without that variable would wipe the binding."
    echo "Either set it again:"
    echo "    MDM_ANDROID_CREDENTIALS_FILE=/etc/mdm/android-service-account.json ./demo.sh"
    echo "or wipe everything on purpose with ./demo.sh reset."
    docker rm -f "$APP" >/dev/null 2>&1 || true
    exit 1
  fi
fi

echo "==> building and starting the console"
docker run -d --name "$APP" --network "$NET" ${ANDROID_ARGS[@]+"${ANDROID_ARGS[@]}"} \
  -p "${CONSOLE_PORT}:${CONSOLE_PORT}" -p "${IDP_PORT}:${IDP_PORT}" -p "${TLS_PORT}:${TLS_PORT}" -p "8093:8093" \
  -v "$HERE":/src -v mdm-gomodcache:/go/pkg/mod -w /src \
  -e GOFLAGS=-mod=mod \
  -e MDM_CONSOLE_PORT="${CONSOLE_PORT}" -e MDM_IDP_PORT="${IDP_PORT}" -e MDM_CONSOLE_TLS_PORT="${TLS_PORT}" \
  -e MDM_ADMIN_DSN="postgres://postgres:${SUPERPASS}@${PG}:5432/mdm" \
  -e MDM_APP_DSN="postgres://mdm_app:${APPPASS}@${PG}:5432/mdm" \
  -e MDM_OPERATOR_DSN="postgres://mdm_operator:${OPPASS}@${PG}:5432/mdm" \
  "$GOIMAGE" sh -c "go run ./cmd/devserver" >/dev/null

echo "==> waiting for the console"
for i in $(seq 1 90); do
  if curl -fsS -o /dev/null "http://localhost:${CONSOLE_PORT}/signin" 2>/dev/null; then
    break
  fi
  sleep 1
  if [ "$i" -eq 90 ]; then
    echo "the console did not come up:"
    docker logs "$APP" 2>&1 | tail -30
    exit 1
  fi
done

docker logs "$APP" 2>&1 | sed -n '/────/,/────/p'
echo ""
echo "Open:  http://localhost:${CONSOLE_PORT}"
echo "Stop:  ./demo.sh stop"
