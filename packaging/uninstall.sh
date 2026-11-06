#!/usr/bin/env bash
# uninstall.sh — take the agent off this machine.
#
# It is explicit about what it does NOT do, because an uninstaller that
# quietly leaves a device enrolled is how a fleet ends up with records of
# machines nobody can reach.

set -euo pipefail

DIR="/var/lib/mdm-agent"
LIBEXEC="/usr/local/libexec/mdm-agent"
LABEL="com.kalesi.mdm-agent"
KEEP_STATE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --keep-state) KEEP_STATE=1; shift ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "This must run as root."; exit 1; }

case "$(uname -s)" in
  Darwin)
    PLIST="/Library/LaunchDaemons/${LABEL}.plist"
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    ;;
  Linux)
    systemctl disable --now mdm-agent.service 2>/dev/null || true
    rm -f /etc/systemd/system/mdm-agent.service
    systemctl daemon-reload
    ;;
esac

rm -f "$LIBEXEC"

if [ "$KEEP_STATE" -eq 1 ]; then
  echo "Left $DIR in place, including this device's private key."
else
  rm -rf "$DIR"
fi

cat <<'NOTE'

Removed from this machine.

WHAT THIS DID NOT DO, and somebody has to:

  * The device is still enrolled. The console still lists it, and its
    certificate is still valid until it expires or an administrator revokes
    it. Revoking is a console action, deliberately: a machine that can
    uninstall its own agent must not be able to delete its own record.

  * Nothing was un-enforced. Any passcode policy, encryption or restriction
    that a helper applied is still applied. Removing the agent removes the
    reporting, not the configuration.

Ask an administrator to retire the device in the console.
NOTE
