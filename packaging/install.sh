#!/usr/bin/env bash
# install.sh — install the device agent on this machine.
#
#   echo "$TOKEN" | sudo ./install.sh --server https://mdm.kalesi.example
#   sudo ./install.sh --server https://... --token-file /path/to/token
#
# The token is read from standard input or from a file, never from an
# argument. An enrolment token is a bearer credential and ps shows every
# process's arguments to every local user on this machine.

set -euo pipefail

SERVER=""
TOKEN_FILE=""
BINARY=""
DIR="/var/lib/mdm-agent"
LIBEXEC="/usr/local/libexec/mdm-agent"
EVERY="15m"
LABEL="com.kalesi.mdm-agent"

usage() {
  cat <<USAGE
Usage: sudo ./install.sh --server URL [options]

  --server URL        your organisation's console address (required)
  --token-file PATH   file holding the enrolment token (default: read stdin)
  --binary PATH       the agent binary to install (default: ./mdm-agent-<os>-<arch>)
  --dir PATH          where this device's identity is kept (default: $DIR)
  --every DURATION    how often to report (default: $EVERY)

The token is never taken as an argument. Pipe it in, or point at a file that
only root can read.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token-file) TOKEN_FILE="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --dir) DIR="$2"; shift 2 ;;
    --every) EVERY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1"; usage; exit 2 ;;
  esac
done

[ -n "$SERVER" ] || { echo "--server is required"; usage; exit 2; }

if [ "$(id -u)" -ne 0 ]; then
  echo "This must run as root: the agent locks and wipes, which is privileged,"
  echo "and its private key must be readable only by root."
  exit 1
fi

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac
case "$OS" in
  Darwin) GOOS=darwin ;;
  Linux)  GOOS=linux ;;
  *) echo "This script handles macOS and Linux. For Windows see packaging/windows."; exit 1 ;;
esac

[ -n "$BINARY" ] || BINARY="./mdm-agent-${GOOS}-${ARCH}"
[ -f "$BINARY" ] || { echo "no such binary: $BINARY"; exit 1; }

# Read the token BEFORE anything is installed, so a mistyped token does not
# leave a half-installed service behind.
if [ -n "$TOKEN_FILE" ]; then
  [ -f "$TOKEN_FILE" ] || { echo "no such file: $TOKEN_FILE"; exit 1; }
  TOKEN="$(cat "$TOKEN_FILE")"
else
  if [ -t 0 ]; then
    printf 'Enrolment token: '
  fi
  read -r TOKEN
fi
[ -n "$TOKEN" ] || { echo "no enrolment token given"; exit 1; }

echo "==> installing the agent"
install -d -m 0755 -o root "$(dirname "$LIBEXEC")"
install -m 0755 -o root "$BINARY" "$LIBEXEC"

# 0700 and root-owned. The directory holds the private key that IS this
# device's identity; anything wider and any local account can become this
# machine.
install -d -m 0700 -o root "$DIR"

echo "==> enrolling"
# The token goes in on standard input. It is never an argument, so it never
# appears in ps, in the shell history, or in a process list a monitoring
# agent happens to be collecting.
printf '%s\n' "$TOKEN" | "$LIBEXEC" -server "$SERVER" -dir "$DIR" enrol
unset TOKEN

echo "==> installing the service"
if [ "$GOOS" = "darwin" ]; then
  PLIST="/Library/LaunchDaemons/${LABEL}.plist"
  sed -e "s|https://mdm.kalesi.example|${SERVER}|" \
      -e "s|/var/lib/mdm-agent|${DIR}|" \
      -e "s|<string>15m</string>|<string>${EVERY}</string>|" \
      "$(dirname "$0")/macos/${LABEL}.plist" > "$PLIST"
  # launchd REFUSES a plist that is group or world writable, or one not
  # owned by root. Setting both is not tidiness; without them the load
  # below fails and the install looks as if it worked.
  chown root:wheel "$PLIST"
  chmod 644 "$PLIST"
  launchctl bootout system "$PLIST" 2>/dev/null || true
  launchctl bootstrap system "$PLIST"
  launchctl enable "system/${LABEL}"
else
  UNIT="/etc/systemd/system/mdm-agent.service"
  sed -e "s|https://mdm.kalesi.example|${SERVER}|" \
      -e "s|/var/lib/mdm-agent|${DIR}|" \
      -e "s|-every 15m|-every ${EVERY}|" \
      "$(dirname "$0")/linux/mdm-agent.service" > "$UNIT"
  chown root:root "$UNIT"
  chmod 644 "$UNIT"
  systemctl daemon-reload
  systemctl enable --now mdm-agent.service
fi

echo "==> checking the installation"
SERVICE_FILE="${PLIST:-${UNIT:-}}"
"$LIBEXEC" -server "$SERVER" -dir "$DIR" -service-file "$SERVICE_FILE" doctor

echo ""
echo "Installed. This device is enrolled and reporting every ${EVERY}."
echo ""
echo "  state      $DIR"
echo "  binary     $LIBEXEC"
echo "  service    $SERVICE_FILE"
echo ""
echo "Locking and wiping need a privileged helper this build does not ship."
echo "Until one is installed, those commands stay outstanding in the console"
echo "rather than being reported as done."
