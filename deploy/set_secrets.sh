#!/usr/bin/env bash
# Asks for the platform's secrets one at a time (typing is hidden), checks
# them, and sends them to Fly on standard input. Nothing secret is written to
# a command line, a file or your shell history. Names only are shown back.
#
#   bash "/full/path/to/deploy/set_secrets.sh"
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v fly >/dev/null || { echo "fly is not installed"; exit 1; }
[ -f fly.toml ] || { echo "fly.toml not found next to this script"; exit 1; }

secret() { local v; IFS= read -rsp "$1: " v; echo >&2; printf '%s' "$v"; }
plain()  { local v; IFS= read -rp  "$1 [$2]: " v; printf '%s' "${v:-$2}"; }
clean()  { # name value : a value that would break the NAME="value" format is refused
  case "$2" in ''|*[\"\\]*|*$'\n'*) echo "$1 is empty or contains a quote, backslash or newline" >&2; exit 1 ;; esac
}

echo "Everything you type for a password is hidden. Paste, then press Return."
echo
seal="$(secret 'MDM_SEALING_KEY (the line from your password manager, without "base64:")')"
clean sealing "$seal"
seal="${seal#base64:}"
bytes="$(printf '%s' "$seal" | openssl base64 -d -A 2>/dev/null | wc -c | tr -d ' ')"
[ "$bytes" = "32" ] || { echo "That is not a valid sealing key (it decodes to $bytes bytes, not 32). Nothing was set."; exit 1; }

host="$(plain 'Supabase Session pooler host' 'aws-0-<region>.pooler.supabase.com')"
case "$host" in *"<"*|*">"*|"") echo "Type the real host, from Supabase: Connect, Session pooler."; exit 1;; esac
case "$host" in db.*) echo "That is the DIRECT address (it starts db.). It cannot be reached from Fly or from Docker on a Mac. Use the Session pooler host: aws-...pooler.supabase.com. Nothing was set."; exit 1;; esac
case "$host" in *.pooler.supabase.com) ;; *) echo "Expected a host ending in .pooler.supabase.com (Supabase, Connect, Session pooler). Nothing was set."; exit 1;; esac
case "$host" in *:*|*/*|*@*) echo "Type only the host, with no port, slash or @. Nothing was set."; exit 1;; esac
ref="$(plain 'Supabase project reference' 'jpzotcxlylctfzywngvz')"
apppw="$(secret 'Password for mdm_app (the 40 characters the setup printed)')"; clean mdm_app "$apppw"
oppw="$(secret 'Password for mdm_operator (the other 40 characters)')"; clean mdm_operator "$oppw"
[ "$apppw" != "$oppw" ] || { echo "The two passwords are the same. They should be different. Nothing was set."; exit 1; }

smtp="$(plain 'Mail server (host:port)' 'smtp.resend.com:587')"
sectype="$(plain 'Mail security (starttls or tls)' 'starttls')"
case "$sectype" in starttls|tls) ;; *) echo "Mail security must be starttls or tls."; exit 1;; esac
smtpuser="$(plain 'Mail username' 'resend')"; clean smtpuser "$smtpuser"
from="$(plain 'Sending address' 'hello@vlumesec.com')"; clean from "$from"
smtppw="$(secret 'Mail password (for Resend, the API key)')"; clean smtp "$smtppw"

claim="base64:$(openssl rand -base64 32)"
sess="base64:$(openssl rand -base64 32)"

{
  printf 'MDM_SEALING_KEY="base64:%s"\n' "$seal"
  printf 'MDM_CLAIM_SIGNING_KEY="%s"\n' "$claim"
  printf 'MDM_SESSION_SIGNING_KEY="%s"\n' "$sess"
  printf 'MDM_APP_DSN="postgres://mdm_app.%s:%s@%s:5432/postgres?sslmode=require"\n' "$ref" "$apppw" "$host"
  printf 'MDM_OPERATOR_DSN="postgres://mdm_operator.%s:%s@%s:5432/postgres?sslmode=require"\n' "$ref" "$oppw" "$host"
  printf 'MDM_SMTP_SERVER="%s"\n' "$smtp"
  printf 'MDM_SMTP_FROM="%s"\n' "$from"
  printf 'MDM_SMTP_SECURITY="%s"\n' "$sectype"
  printf 'MDM_SMTP_USERNAME="%s"\n' "$smtpuser"
  printf 'MDM_SMTP_PASSWORD="%s"\n' "$smtppw"
} | fly secrets import

echo
echo "Sent. The names Fly now holds (never the values):"
fly secrets list
