#!/bin/sh
# Moves the platform's secrets out of the process environment.
#
# A hosting platform hands secrets over as environment variables. The gateway
# would accept them that way, but warns, because an environment is readable by
# anything that can read /proc/<pid>/environ and shows up in crash dumps. So
# the three keys (and, if given, the Android service account) are written to a
# memory-backed directory, the variables are removed, and the gateway is
# started with MDM_KEY_SOURCE=files, which is the source it is built to
# prefer. The files are on tmpfs: a stopped machine leaves nothing on disk.
set -eu

D=/dev/shm/mdm-secrets
mkdir -p "$D"; chmod 700 "$D"

put() { # file-name  variable-name
  eval "v=\${$2:-}"
  if [ -z "$v" ]; then echo "entrypoint: $2 is not set" >&2; exit 1; fi
  ( umask 077; printf '%s' "$v" > "$D/$1" )
}

# Only the gateway needs the keys. tenantctl, run in the same image for a
# one-off job, needs the database login and nothing else.
if [ "${1:-gateway}" = "gateway" ]; then
  put claim_signing_key   MDM_CLAIM_SIGNING_KEY
  put session_signing_key MDM_SESSION_SIGNING_KEY
  put sealing_key         MDM_SEALING_KEY
  if [ -n "${MDM_SEALING_KEY_PREVIOUS:-}" ]; then put sealing_key_previous MDM_SEALING_KEY_PREVIOUS; fi
  export MDM_KEY_SOURCE=files MDM_KEY_DIR="$D"
  if [ -n "${MDM_ANDROID_CREDENTIALS_B64:-}" ]; then
    ( umask 077; printf '%s' "$MDM_ANDROID_CREDENTIALS_B64" | base64 -d > "$D/android-service-account.json" )
    export MDM_ANDROID_CREDENTIALS_FILE="$D/android-service-account.json"
  fi
fi

exec env -u MDM_CLAIM_SIGNING_KEY -u MDM_SESSION_SIGNING_KEY -u MDM_SEALING_KEY \
         -u MDM_SEALING_KEY_PREVIOUS -u MDM_ANDROID_CREDENTIALS_B64 \
     "$@"
