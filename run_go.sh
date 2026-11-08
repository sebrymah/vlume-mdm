#!/usr/bin/env bash
# run_go.sh — runs the Go tests against a throwaway PostgreSQL, both in
# Docker. Nothing is installed on the host: no Go toolchain, no local
# PostgreSQL.
#
#   ./run_go.sh                  every test
#   ./run_go.sh --break-<name>   a negative control (see below)
#   GOTESTFLAGS=-v ./run_go.sh   with the test names
#
# db/run.sh proves PostgreSQL enforces isolation. These prove the Go code
# cannot be talked out of it, and the negative controls prove these tests
# would notice if it were.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET="mdm-net"
PG="mdm-pg-go"
PGIMAGE="postgres:17-alpine"
GOIMAGE="golang:1.23-alpine"
SUPERPASS="isolation-suite-local-only"
APPPASS="app-role-local-only"
OPPASS="operator-role-local-only"

MODE="${1:-normal}"
SRC="$HERE"
TMPSRC=""
OUT=""

# One cleanup, set once. The previous version set a fresh trap in each
# negative-control block and again for the output file, so each new trap
# replaced the one before it and the container was left running.
cleanup() {
  docker rm -f "$PG" >/dev/null 2>&1 || true
  [ -n "$TMPSRC" ] && rm -rf "$TMPSRC"
  [ -n "$OUT" ] && rm -f "$OUT"
  return 0
}
trap cleanup EXIT

# patch copies the tree aside and removes ONE check, so the same tests can be
# run against a build that is deliberately wrong. The copy means the real
# source is never touched.
#
# Every patched line must still COMPILE. A build failure would make the tests
# fail for the wrong reason and the control would pass without proving
# anything, which is why the guard at the bottom treats "build failed" as an
# invalid control rather than a success.
patch() {
  local file="$1" from="$2" to="$3"
  if ! grep -qF -- "$from" "$SRC/$file"; then
    echo "NEGATIVE CONTROL INVALID: nothing to patch in $file"
    echo "  looked for: $from"
    exit 1
  fi
  python3 - "$SRC/$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    s = f.read()
with open(path, "w") as f:
    f.write(s.replace(old, new, 1))
PY
}

if [ "$MODE" != "normal" ]; then
  TMPSRC="$(mktemp -d)"
  cp -R "$HERE/." "$TMPSRC/"
  SRC="$TMPSRC"
fi

case "$MODE" in
normal) ;;

--break-claim)
  # The data layer's tenant, not set on the transaction.
  echo "==> NEGATIVE CONTROL: WithTenant no longer sets the tenant"
  patch internal/data/data.go "'app.tenant_id'" "'app.tenant_id_never_read'"
  ;;

--break-host)
  # The gateway's central rule: a session or a device certificate must name
  # the same tenant as the hostname.
  echo "==> NEGATIVE CONTROL: tenant is no longer compared to hostname"
  patch internal/gateway/gateway.go \
    "if id.TenantID != host.ID {" "if id.TenantID != host.ID && false {"
  patch internal/gateway/gateway.go \
    "if certTenant != host.ID {" "if certTenant != host.ID && false {"
  ;;

--break-brand)
  # T4 and T12: every tenant rendered with one fixed brand.
  echo "==> NEGATIVE CONTROL: one brand is rendered for every tenant"
  patch internal/console/console.go "p.Brand = b" \
    'p.Brand = b; p.Brand = branding.Brand{ProductName: "Kalesi Device Care", Colour: "#0F6E66", MarkLetter: "K"}'
  ;;

--break-approval)
  # R6: a full wipe needs two people.
  echo "==> NEGATIVE CONTROL: a full wipe needs one approval"
  patch internal/command/command.go \
    "WipeFull:      {Reversible: false, Approvals: 2" \
    "WipeFull:      {Reversible: false, Approvals: 1"
  ;;

--break-csrf)
  # The console's cross-site protection.
  echo "==> NEGATIVE CONTROL: the form token is not checked"
  patch internal/gateway/gateway.go \
    "res.FromCookie && !g.csrfOK(r, res)" "res.FromCookie && !g.csrfOK(r, res) && false"
  patch internal/gateway/console_post.go \
    "res.FromCookie && !g.csrfOK(r, res)" "res.FromCookie && !g.csrfOK(r, res) && false"
  ;;

--break-rolemap)
  # The silent grant. Someone signs in, no group of theirs is mapped, and
  # instead of being refused they are quietly made an administrator. This is
  # the single worst thing this sprint could get wrong, so it gets a control.
  echo "==> NEGATIVE CONTROL: an unmapped person is given a role anyway"
  patch internal/identity/identity.go 'return "", ErrNoRole' "return authz.ITAdmin, nil"
  ;;

--break-audience)
  # The check people leave out of an OpenID Connect integration: an identity
  # token minted for another application at the same provider is accepted
  # here. go-oidc has a flag for exactly this, which makes it one line to
  # remove and therefore one line worth proving we would notice.
  echo "==> NEGATIVE CONTROL: the identity token's audience is not checked"
  patch internal/identity/oidc.go \
    "&oidc.Config{ClientID: cfg.ClientID}" \
    "&oidc.Config{ClientID: cfg.ClientID, SkipClientIDCheck: true}"
  ;;

--break-revocation)
  # An administrator ends every session for their tenant and nothing happens.
  echo "==> NEGATIVE CONTROL: tenant-wide session revocation is not applied"
  patch internal/gateway/gateway.go \
    "if sess.StartedAt.Before(host.SessionsInvalidBefore) {" \
    "if sess.StartedAt.Before(host.SessionsInvalidBefore) && false {"
  ;;

--break-certtrust)
  # THE GAP THIS SPRINT CLOSED. Stop checking that a device certificate is
  # one we issued, and the gateway is back to trusting anything of the right
  # shape, which is what it did for five sprints.
  echo "==> NEGATIVE CONTROL: a device certificate is trusted without being checked"
  patch internal/gateway/gateway.go \
    "if err := g.deviceCertTrusted(r.Context(), host, cert, deviceID); err != nil {" \
    "if err := g.deviceCertTrusted(r.Context(), host, cert, deviceID); err != nil && false {"
  ;;

--break-csrsubject)
  # The classic certificate authority mistake: sign the name you were asked
  # to sign. A device could then ask to be a different device, or to be in a
  # different tenant.
  echo "==> NEGATIVE CONTROL: the authority honours the subject it was asked for"
  patch internal/pki/pki.go \
    "Subject: pkix.Name{
			CommonName:         deviceID.String(),
			OrganizationalUnit: []string{tenantID.String()},
		}," \
    "Subject: csr.Subject,"
  ;;

--break-reenrol)
  # A machine enrolled a second time keeps its old certificate working, so a
  # stolen laptop's credential survives its replacement being enrolled.
  echo "==> NEGATIVE CONTROL: re-enrolment leaves the old certificate valid"
  patch internal/enrol/enrol.go \
    "WHERE device_id = \$1 AND revoked_at IS NULL\`, existing)" \
    "WHERE device_id = \$1 AND revoked_at IS NULL AND false\`, existing)"
  ;;

--break-merge)
  # The classic MDM failure: assigning a looser policy silently relaxes a
  # stricter one. Make the merge last-write-wins instead of strictest-wins.
  echo "==> NEGATIVE CONTROL: the last policy read wins instead of the strictest"
  patch internal/policy/policy.go \
    "out[kind] = stricter(held, want)" \
    "out[kind] = want; _ = held"
  ;;

--break-unknownrule)
  # A typo in a rule name becomes a policy that requires nothing, saves
  # happily, and displays as a policy. The lie surfaces during an incident.
  echo "==> NEGATIVE CONTROL: an unknown rule name is skipped rather than refused"
  patch internal/policy/policy.go \
    "		if !ok {
			return nil, fmt.Errorf(\"%w: %q. The rules this platform understands are: %s\",
				ErrUnknownRule, name, joinKinds())
		}" \
    "		if !ok {
			continue
		}"
  ;;

--break-silence)
  # Treat a field the device did not report as a pass. An agent with a bug,
  # or a device choosing not to answer, then reads as compliant.
  echo "==> NEGATIVE CONTROL: a device that did not answer counts as passing"
  patch internal/policy/policy.go \
    "	case got == nil:
		note(Finding{req.Kind, req.Says(), \"the device did not say\", req.From, true})
	case !*got:" \
    "	case got == nil:
		return
	case !*got:"
  ;;

--break-quarantine)
  # A cheerful report from a laptop that has just been wiped releases it from
  # quarantine. The database trigger is the backstop; this removes the Go
  # half and proves the tests notice.
  echo "==> NEGATIVE CONTROL: evaluation overwrites an administrative hold"
  patch internal/policy/store.go \
    "	case \"quarantined\", \"retired\":" \
    "	case \"a-state-no-device-is-in\":"
  ;;

--break-devicerole)
  # THE ESCALATION THIS SPRINT FOUND. Put it_admin back on device
  # certificates and one stolen laptop can lock any device in the tenant,
  # request a wipe of any device, rewrite the policy and mint enrolment
  # tokens. This is the most important control in the build.
  echo "==> NEGATIVE CONTROL: a device certificate is treated as an administrator"
  patch internal/gateway/gateway.go \
    "Role: authz.Device, Source: \"device_certificate\"" \
    "Role: authz.ITAdmin, Source: \"device_certificate\""
  ;;

--break-devicescope)
  # A device is handed the whole tenant's command queue: who is being wiped,
  # why, and on whose instruction.
  echo "==> NEGATIVE CONTROL: a device sees every device's instructions"
  patch internal/gateway/commands.go \
    "command.Filter{DeviceID: res.DeviceID, Limit: 50}" \
    "command.Filter{Limit: 50}"
  ;;

--break-ack)
  # The agent acknowledges work it could not carry out, so the console
  # reports a lock that never happened as done.
  echo "==> NEGATIVE CONTROL: the agent acknowledges work that failed"
  patch internal/agent/agent.go \
    "			a.log.Error(\"could not carry out\", \"command\", c.ID, \"type\", c.Type, \"err\", derr)
			continue
		}" \
    "			a.log.Error(\"could not carry out\", \"command\", c.ID, \"type\", c.Type, \"err\", derr)
		}"
  ;;

--break-mine)
  # Person-vs-person isolation inside one tenant. Unlike the tenant
  # boundary, this has ONE control: row-level security cannot help, because
  # an administrator legitimately reads every row in the tenant. So this is
  # the control, and this proves the tests hold it up.
  echo "==> NEGATIVE CONTROL: an employee is shown their colleagues' devices"
  patch internal/data/devices.go \
    "		   AND person_id IN (SELECT id FROM people WHERE \` + activePerson + \`)\`" \
    "		   AND true\`"
  ;;

--break-emailreuse)
  # A leaver's row still answers for their address. The next hire with
  # the same email signs in and finds the leaver's devices on their page.
  echo "==> NEGATIVE CONTROL: a reused address inherits a leaver's devices"
  patch internal/data/people.go \
    "const activePerson = \`left_at IS NULL" \
    "const activePerson = \`true"
  ;;

--break-leftmark)
  # Offboarding wipes the devices and forgets the person. Their subject
  # and address stay live, and the next assignment to that address lands
  # on someone who has gone.
  echo "==> NEGATIVE CONTROL: a leaver's devices go and the person stays"
  patch internal/gateway/offboard.go \
    "		if err := data.MarkLeft(ctx, tx, person.ID, by, reason, now); err != nil {" \
    "		if err := error(nil); err != nil {"
  ;;

--break-lostowner)
  # Anyone can report anyone's device lost, which puts a red flag on a
  # colleague's laptop and an administrator's attention on the wrong
  # machine.
  echo "==> NEGATIVE CONTROL: a person can report a colleague's device lost"
  # BOTH call sites. The first run of this control FAILED with only the
  # opening one patched: the re-read at the end also goes through MyDevice,
  # so the write landed and was then rolled back by the error from that
  # second read. That is the protection holding by accident rather than by
  # design, and a control that leaves it in place proves nothing.
  patch internal/data/devices.go \
    "	d, err := MyDevice(ctx, tx, id)" \
    "	d, err := GetDevice(ctx, tx, id)"
  patch internal/data/devices.go \
    "	return MyDevice(ctx, tx, id)" \
    "	return GetDevice(ctx, tx, id)"
  ;;

--break-ssrf)
  # A tenant administrator supplies the webhook address and this platform
  # then makes a request to it from inside its own network. Without the
  # dial-time check, pointing it at the cloud metadata service or at an
  # internal database is a tenant asking our server to fetch something they
  # cannot reach themselves.
  echo "==> NEGATIVE CONTROL: a webhook may be aimed inside the platform's network"
  patch internal/notify/webhook.go \
    "	if w.AllowPrivateAddresses {
		return nil
	}" \
    "	if true {
		return nil
	}"
  ;;

--break-refusal)
  # Put back the defect this sprint found: return the limiter's error out of
  # the transaction, rolling back the refusal record and its audit entry
  # that R1 requires. The unit test passed through this the whole time
  # because it held its own transaction open.
  echo "==> NEGATIVE CONTROL: the limiter's refusal is rolled back with the request"
  patch internal/gateway/commands.go \
    "				refusal = err" \
    "				return err"
  ;;

--break-dedupe)
  # One event queues a message every time the button is pressed.
  #
  # Patching away ON CONFLICT does NOT work as a control, and the first
  # attempt at this proved it: the unique index then raises, the enqueue
  # errors, and the count stays at one for entirely the wrong reason.
  # Giving every message its own key is the real failure mode, and the one
  # a careless edit would actually produce.
  echo "==> NEGATIVE CONTROL: the same event queues more than once"
  patch internal/notify/notify.go \
    'm.DedupeKey = string(m.Topic) + ":" + m.ObjectRef' \
    'm.DedupeKey = string(m.Topic) + ":" + m.ObjectRef + uuid.NewString()'
  ;;

--break-headers)
  # The control this channel exists around. An address field containing a
  # newline is not a malformed address, it is extra headers, and a Bcc
  # written that way is a silent copy of every notification to somebody
  # else, configured through a form by anyone who can reach the page.
  echo "==> NEGATIVE CONTROL: a line break may be written into a mail header"
  patch internal/notify/email.go \
    "func checkHeaderValue(v string) error {
	for _, r := range v {" \
    "func checkHeaderValue(v string) error {
	if v != \"\" {
		return nil
	}
	for _, r := range v {"
  ;;

--break-cleartext)
  # Hand a password to a server that offered no encryption. The mail still
  # arrives, which is what makes this failure silent.
  echo "==> NEGATIVE CONTROL: a password may be sent over an unencrypted connection"
  patch internal/notify/email.go \
    "		if !encrypted {
			return ErrCleartextAuth
		}" \
    "		if !encrypted && false {
			return ErrCleartextAuth
		}"
  ;;

--break-dnsproof)
  # THE CONTROL THIS SPRINT EXISTS AROUND. Accept any DKIM record rather
  # than the one carrying our own key, and a tenant can have this platform
  # sign mail as a domain already running DKIM for somebody else, which is
  # to say as a domain they do not control.
  echo "==> NEGATIVE CONTROL: a sending domain is verified without proving control"
  patch internal/notify/sending.go \
    "			if keyIn(r) == d.PublicKey {" \
    "			if keyIn(r) != \"\" || r == \"\" {"
  ;;

--break-alignment)
  # Sign as the tenant but send from the operator. The signature is valid
  # and DMARC fails anyway, which is the failure nobody notices until a
  # customer says the mail is not arriving.
  echo "==> NEGATIVE CONTROL: the sender does not align with the signed domain"
  patch internal/notify/email.go \
    "	if m.Sender != nil && m.Sender.From != \"\" {" \
    "	if false && m.Sender != nil && m.Sender.From != \"\" {"
  ;;

--break-tokenfile)
  # A token file anybody can read is a token anybody can use. The same rule
  # an SSH private key has, and packaging is when it bites: install scripts
  # write files with whatever umask the shell had.
  echo "==> NEGATIVE CONTROL: a world-readable enrolment token file is accepted"
  patch internal/agent/install.go \
    "	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return \"\", fmt.Errorf(" \
    "	if perm := info.Mode().Perm(); perm&0o077 != 0 && false {
		return \"\", fmt.Errorf("
  ;;

--break-doctor)
  # Stop noticing that the binary this agent runs from can be replaced by
  # another user. The agent runs as root, so that is a local privilege
  # escalation with a service unit pointing at it.
  echo "==> NEGATIVE CONTROL: a world-writable agent binary is not reported"
  patch internal/agent/install.go \
    "	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		add(Finding{path," \
    "	if perm := info.Mode().Perm(); perm&0o022 != 0 && false {
		add(Finding{path,"
  ;;

--break-renewrevoked)
  # THE ONE THAT MATTERS FOR RENEWAL. A renewal path that let a revoked
  # certificate get a fresh one would make revocation decorative: a stolen
  # laptop would renew its way back the next time it was switched on.
  #
  # BOTH checks are removed, and that is the point of removing both. The
  # gateway refuses a revoked certificate during resolution, and enrol.Renew
  # refuses it again. Patching one leaves the other catching it, and the
  # control would pass while proving nothing. That lesson came from
  # --break-lostowner, which did exactly that on its first run.
  echo "==> NEGATIVE CONTROL: a revoked certificate can renew itself back to life"
  patch internal/gateway/enrolment.go \
    "		if revokedAt != nil {
			return ErrCertRevoked
		}" \
    "		if revokedAt != nil && false {
			return ErrCertRevoked
		}"
  patch internal/enrol/enrol.go \
    "	if revokedAt != nil {
		return Renewed{}, ErrUnknownCertificate
	}" \
    "	if revokedAt != nil && false {
		return Renewed{}, ErrUnknownCertificate
	}"
  ;;

--break-renewwindow)
  # The window is also the rate limit: a certificate issued today is not
  # inside its own window, so a device that has just renewed cannot renew
  # again. Remove it and a device holding one valid certificate can mint an
  # unbounded number of them.
  echo "==> NEGATIVE CONTROL: any certificate may renew, at any point in its life"
  patch internal/enrol/enrol.go \
    "	if notAfter.Sub(now) > RenewalWindow {
		return Renewed{}, ErrNotDueForRenewal
	}" \
    "	if notAfter.Sub(now) > RenewalWindow && false {
		return Renewed{}, ErrNotDueForRenewal
	}"
  ;;

--break-operatorreach)
  # R13. Onboarding widened the operator's role to write the four rows a new
  # tenant needs. This gives it one more thing, a read of devices, and the
  # directory's probe test must notice: the operator can set a tenant up and
  # must not be able to look inside it.
  echo "==> NEGATIVE CONTROL: the operator's role can read devices"
  patch db/migrations/0014_onboarding.sql \
    "GRANT INSERT, UPDATE ON tenants TO mdm_operator;" \
    "GRANT INSERT, UPDATE ON tenants TO mdm_operator;
GRANT SELECT ON devices TO mdm_operator;"
  ;;

--break-signupreuse)
  # A sign-up link is spent on use. There are two guards, the read that
  # refuses a finished row and the UPDATE that matches only an open one, so
  # both go, and the test that finishes the same link twice must see two
  # tenants from one proof.
  echo "==> NEGATIVE CONTROL: a sign-up link can be used again"
  patch internal/directory/signup.go \
    "	if finished != nil {
		return Signup{}, ErrSignupFinished
	}" \
    "	if finished != nil && false {
		return Signup{}, ErrSignupFinished
	}"
  patch internal/directory/signup.go \
    "		 WHERE id = \$1 AND finished_at IS NULL AND expires_at > now()\`, s.ID, id)" \
    "		 WHERE id = \$1 AND expires_at > now()\`, s.ID, id)"
  ;;

--break-signupexpiry)
  # A link lasts a day. Remove the check on the read and an old link opens.
  echo "==> NEGATIVE CONTROL: a sign-up link never expires"
  patch internal/directory/signup.go \
    "	if !expires.After(time.Now()) {
		return Signup{}, ErrSignupExpired
	}" \
    "	if !expires.After(time.Now()) && false {
		return Signup{}, ErrSignupExpired
	}"
  ;;

--break-signupcap)
  # The per-domain and per-address caps are what bound how much mail a
  # stranger can make this platform send. Remove them and the sixth and the
  # eleventh requests go through.
  echo "==> NEGATIVE CONTROL: no cap on sign-ups per domain or address"
  patch internal/directory/signup.go \
    "	if byDomain >= MaxSignupsPerDomainPerDay || byIP >= MaxSignupsPerIPPerDay {" \
    "	if false && (byDomain >= MaxSignupsPerDomainPerDay || byIP >= MaxSignupsPerIPPerDay) {"
  ;;

--break-signupfreemail)
  # A tenant is a company. Let a free-mail address through and the proof
  # proves nothing about who is asking.
  echo "==> NEGATIVE CONTROL: any address may sign up"
  patch internal/directory/signup.go \
    "	if !strings.Contains(domain, \".\") || IsFreeMail(domain) {" \
    "	if !strings.Contains(domain, \".\") {"
  ;;

--break-proxytrust)
  # Believe X-Forwarded-For from anyone. A stranger then chooses their own
  # address and every per-address limit becomes a suggestion.
  echo "==> NEGATIVE CONTROL: X-Forwarded-For is believed from any peer"
  patch internal/gateway/proxy.go \
    "	if len(trusted) == 0 || !inAny(peer, trusted) {
		return peer
	}" \
    "	if false {
		return peer
	}"
  ;;

--break-brake)
  # Remove the brake and sixty devices failing at once are sixty devices
  # quarantined at once. Standing directive 1 in one line.
  echo "==> NEGATIVE CONTROL: automatic quarantine has no brake"
  patch internal/policy/store.go \
    "	if failing > brakeLimit(fleet) {" \
    "	if false && failing > brakeLimit(fleet) {"
  ;;

--break-optin)
  # Quarantine whether or not a policy asked. Every tenant with a policy
  # becomes a tenant with enforcement they never switched on.
  echo "==> NEGATIVE CONTROL: quarantine without a policy asking for it"
  patch internal/policy/store.go \
    "	if !ask || verdict.State != NotCompliant || newState != NotCompliant {" \
    "	_ = ask
	if verdict.State != NotCompliant || newState != NotCompliant {"
  ;;

--break-releasepath)
  # The release function forgets the one setting the trigger looks for.
  # The trigger must refuse it: a writer that bypasses the named path is
  # refused by the database, which is what the path is for.
  echo "==> NEGATIVE CONTROL: release without telling the database a person asked"
  patch internal/data/devices.go \
    "	if _, err := tx.Exec(ctx, \`SET LOCAL app.release = 'yes'\`); err != nil {" \
    "	if _, err := tx.Exec(ctx, \`SELECT 1\`); err != nil {"
  ;;

--break-tokenrevoked)
  # Revocation is the whole reason the row exists. Ignore it and a token
  # the Super Admin revoked yesterday still opens the feed today.
  echo "==> NEGATIVE CONTROL: a revoked integration token still works"
  patch internal/data/network.go \
    "		 WHERE token_hash = \$1 AND revoked_at IS NULL\`, hash).Scan(" \
    "		 WHERE token_hash = \$1\`, hash).Scan("
  ;;

--break-networkrole)
  # Give the network role the device list. The matrix transcription test
  # and the feed test both have to notice.
  echo "==> NEGATIVE CONTROL: a network token may list devices"
  patch internal/authz/authz.go \
    "	Network: {
		ManageAccess: false,
		ViewDevices:  false," \
    "	Network: {
		ManageAccess: false,
		ViewDevices:  true,"
  ;;

--break-feeddeny)
  # The feed says allow for a quarantined device. F9's network half
  # becomes a feed that never denies anything.
  echo "==> NEGATIVE CONTROL: the access feed allows a quarantined device"
  patch internal/data/network.go \
    "	case \"quarantined\":
		v.Access, v.Reason, v.Since = \"deny\", reason, since" \
    "	case \"quarantined\":
		v.Access, v.Reason, v.Since = \"allow\", reason, since"
  ;;

--break-feedunknown)
  # Let a device that has never reported onto the network. Not knowing
  # becomes a pass at the door.
  echo "==> NEGATIVE CONTROL: the access feed allows a device that has not reported"
  patch internal/data/network.go \
    "	case \"state_unknown\", \"awaiting_first_boot\":
		v.Access, v.Reason = \"deny\", \"has not reported clean\"" \
    "	case \"state_unknown\", \"awaiting_first_boot\":
		v.Access, v.Reason = \"allow\", \"has not reported clean\""
  patch internal/data/network.go \
    "	if v.Access == \"allow\" && maxAge > 0 &&" \
    "	if false && maxAge > 0 &&"
  ;;

--break-scopedbrake)
  # Measure the brake over the whole fleet only. Five of five tablets
  # failing is 2.4% of two hundred laptops, and they are all quarantined.
  echo "==> NEGATIVE CONTROL: the brake ignores a policy's own scope"
  patch internal/policy/store.go \
    "		if p.Scope == (Scope{}) {
			continue
		}" \
    "		if true {
			continue
		}"
  ;;

--break-androidstate)
  # The callback stops checking that the sign-up it is finishing is the one
  # THIS person started. A token arriving on a callback nobody here began
  # binds somebody else's enterprise to this tenant.
  echo "==> NEGATIVE CONTROL: the Android callback binds without a sign-up in progress"
  patch internal/gateway/android.go \
    "	ck, err := r.Cookie(androidBindCookie)
	if err != nil || token == \"\" {" \
    "	ck, err := r.Cookie(androidBindCookie)
	if err != nil {
		ck = &http.Cookie{Value: g.bindState(res.Subject, r.URL.Query().Get(\"signup\"))}
		err = nil
	}
	if err != nil || token == \"\" {"
  ;;

--break-androidwipe)
  # A selective wipe goes to Google as a full wipe. The person's own
  # photos go with the work profile.
  echo "==> NEGATIVE CONTROL: a selective wipe of an Android device is a full wipe"
  patch internal/android/push.go \
    "		return p.Provider.Wipe(ctx, name, true)" \
    "		return p.Provider.Wipe(ctx, name, false)"
  ;;

--break-androidjudged)
  # Rules Google cannot enforce are dropped silently instead of named.
  # The policy enforces less than it says and nobody is told.
  echo "==> NEGATIVE CONTROL: undeliverable Android rules vanish silently"
  patch internal/android/translate.go \
    "			undelivered = append(undelivered, string(kind))" \
    "			_ = kind"
  ;;

--break-lostbrand)
  # The lock screen of a lost phone names the platform instead of the
  # tenant. The operator-brand rule, broken on the one surface a stranger
  # sees.
  echo "==> NEGATIVE CONTROL: a lost Android phone shows the operator's name"
  patch internal/android/push.go \
    "	org := b.ProductName
	if b.IsPlaceholder() {" \
    "	org := \"MDM Platform Operator\"
	if false {"
  ;;

--break-lostcontact)
  # The lock screen keeps the tenant's name and drops who to call. A found
  # phone says whose it is and gives no way to return it.
  echo "==> NEGATIVE CONTROL: a lost phone's lock screen gives no way to reach the owner"
  patch internal/android/push.go \
    "	return LostModeInput{Message: msg, Organisation: org, Email: b.LostEmail, Phone: b.LostPhone}" \
    "	return LostModeInput{Message: msg, Organisation: org}"
  ;;

--break-reportbrand)
  # The PDF's band names the platform instead of the tenant. T12 on paper.
  echo "==> NEGATIVE CONTROL: the compliance PDF carries the operator's name"
  patch internal/report/pdf.go \
    "		fontBand, marginX, pageH-bandH+15, esc(b.ProductName))" \
    "		fontBand, marginX, pageH-bandH+15, esc(\"MDM Platform Operator\"))"
  ;;

--break-reportaudit)
  # An export of tenant data that leaves no record of who took it.
  echo "==> NEGATIVE CONTROL: making a report is not audited"
  patch internal/gateway/reports.go \
    "	if err := data.AppendAudit(ctx, tx, \"report.generated\", \"compliance.\"+format+\" devices:\"+itoa(rep.Total)); err != nil {" \
    "	if err := error(nil); err != nil {"
  ;;

--break-rollbackinplace)
  # Rollback switches the old row back on instead of writing a new
  # version. A verdict reached against v2 can no longer be explained once
  # v2 has been edited underneath it.
  echo "==> NEGATIVE CONTROL: rollback reactivates the old version in place"
  patch internal/policy/store.go \
    "	in := SaveInput{Name: name, Body: body, CreatedBy: by}" \
    "	if _, err := tx.Exec(ctx, \`UPDATE policies SET active = false WHERE name = \$1 AND active\`, name); err != nil {
		return Policy{}, err
	}
	if _, err := tx.Exec(ctx, \`UPDATE policies SET active = true WHERE name = \$1 AND version = \$2\`, name, version); err != nil {
		return Policy{}, err
	}
	var pp Policy
	pp.Name, pp.Version, pp.Active = name, version, true
	return pp, nil
	in := SaveInput{Name: name, Body: body, CreatedBy: by}"
  ;;

--break-devicecap)
  # Both halves of the cap go: the invitation check and the trigger. A
  # starter tenant with fifty devices paid for enrols its five hundredth.
  echo "==> NEGATIVE CONTROL: the plan's device cap is not enforced"
  patch internal/enrol/enrol.go \
    "	if have >= cap {
		return fmt.Errorf(\"%w: %d of %d devices are in use. Retire a device, or ask for a larger plan\", ErrDeviceCap, have, cap)" \
    "	if false && have >= cap {
		return fmt.Errorf(\"%w: %d of %d devices are in use. Retire a device, or ask for a larger plan\", ErrDeviceCap, have, cap)"
  patch db/migrations/0021_plans_metering.sql \
    "  IF have >= cap THEN" \
    "  IF false THEN"
  ;;

--break-featureflag)
  # Every feature is on for every plan. A starter tenant binds Android
  # Enterprise it has not paid for.
  echo "==> NEGATIVE CONTROL: feature flags always answer yes"
  patch internal/directory/plans.go \
    "func (t Tenant) Feature(name string) bool {
	if v, ok := t.Features[name]; ok {" \
    "func (t Tenant) Feature(name string) bool {
	if true {
		return true
	}
	if v, ok := t.Features[name]; ok {"
  ;;

--break-rolloutall)
  # Every device is in every stage. A 10% trial of a stricter passcode is
  # a 100% rollout nobody asked for.
  echo "==> NEGATIVE CONTROL: a staged policy applies to every device"
  patch internal/policy/store.go \
    "	if !p.Rolling() {
		return true
	}
	if p.RolloutTag != \"\" {" \
    "	if !p.Rolling() || true {
		return true
	}
	if p.RolloutTag != \"\" {"
  ;;

--break-rolloutshuffle)
  # The stage is decided afresh on every report instead of from the
  # device's id. A device flips between versions from one report to the
  # next, and nobody can say which rules it was held to.
  echo "==> NEGATIVE CONTROL: a device's stage changes between reports"
  patch internal/policy/store.go \
    "	h := fnv.New32a()
	h.Write(id[:])
	return int(h.Sum32() % 100)" \
    "	h := fnv.New32a()
	h.Write(id[:])
	h.Write([]byte(time.Now().String()))
	return int(h.Sum32() % 100)"
  ;;

--break-siemcursor)
  # The cursor moves before the SIEM has taken the event. A collector
  # that was down for an hour has an hour-shaped hole it will never know
  # about.
  echo "==> NEGATIVE CONTROL: the SIEM cursor moves past events that were not delivered"
  patch internal/siem/siem.go \
    "		if err := svc.DeliverNow(ctx, target, m); err != nil {
			res.Err = err" \
    "		if err := svc.DeliverNow(ctx, target, m); err != nil {
			_, _ = tx.Exec(ctx, \`UPDATE siem_cursors SET last_audit_id = \$1\`, e.ID)
			res.Err = err"
  ;;

--break-siembrand)
  # Every line a tenant's analysts see names the platform's operator.
  echo "==> NEGATIVE CONTROL: the CEF vendor field is the operator"
  patch internal/siem/siem.go \
    "	if b.IsPlaceholder() {
		return \"Device Management\"
	}
	return b.ProductName" \
    "	return \"MDM Platform Operator\""
  ;;

--break-offboardretire)
  # The wipe is acknowledged and nothing follows. A device marked for
  # offboarding keeps its certificate and its slot for ever.
  echo "==> NEGATIVE CONTROL: a completed wipe does not retire an offboarding device"
  patch internal/command/command.go \
    "	if p.OnWiped == nil || (c.Type != WipeSelective && c.Type != WipeFull) {" \
    "	if true {"
  ;;

--break-tokenscope)
  # Every integration token resolves to the network role, HR's included.
  # The HR system cannot say anyone has left; and a token minted for HR
  # reads the access feed it was never meant to see.
  echo "==> NEGATIVE CONTROL: a token's scope is ignored"
  patch internal/gateway/network.go \
    "	if tok.Scope == \"hr\" {
		role = authz.HRFeed
	}" \
    "	if false {
		role = authz.HRFeed
	}"
  ;;

--break-offboardscope)
  # The offboarding permission covers every wipe type. An HR feed that
  # may say "left" can now erase a device to factory state.
  echo "==> NEGATIVE CONTROL: the offboarding permission covers full wipes"
  patch internal/command/command.go \
    "	if in.Offboarding && in.Type == WipeSelective && authz.Can(role, authz.OffboardEmployee) {" \
    "	if in.Offboarding && authz.Can(role, authz.OffboardEmployee) {"
  ;;

--break-offboardactive)
  # An active tenant can be offboarded in one command. The two deliberate
  # steps become one accident.
  echo "==> NEGATIVE CONTROL: an active tenant can be offboarded without suspension"
  patch db/migrations/0025_offboard_tenant.sql \
    "  IF st NOT IN ('suspended','exporting') THEN" \
    "  IF false THEN"
  patch internal/directory/offboard.go \
    "	if status != \"suspended\" && status != \"exporting\" {" \
    "	if false {"
  ;;

--break-offboardresidue)
  # The deletion skips the audit log and the verification does not notice.
  echo "==> NEGATIVE CONTROL: offboarding leaves the audit log and reports success"
  patch db/migrations/0025_offboard_tenant.sql \
    "    EXECUTE format('DELETE FROM %I WHERE tenant_id = \$1', tbl) USING t;" \
    "    IF tbl <> 'audit_events' THEN EXECUTE format('DELETE FROM %I WHERE tenant_id = \$1', tbl) USING t; END IF;"
  patch internal/directory/offboard.go \
    "	if out.Residue > 0 {" \
    "	if false {"
  ;;

--break-exportsecret)
  # The export carries the sealed client secret and every token hash.
  echo "==> NEGATIVE CONTROL: the export includes sealed secrets"
  patch internal/gateway/export.go \
    "				if redacted(k) {" \
    "				if false && redacted(k) {"
  ;;

--break-rotatereseal)
  # Rotation makes a new version and re-seals nothing. The new key seals
  # no value; the old one, now retired, still seals them all.
  echo "==> NEGATIVE CONTROL: rotation does not re-seal the tenant's values"
  patch internal/gateway/keys.go \
    "	if err := reseal(\"tenant_identity\", \"tenant_id\", \"client_secret_sealed\", &out.Identity); err != nil {" \
    "	if err := error(nil); err != nil {"
  ;;

--break-keyscope)
  # The keyring seals under the master key for everyone. One key again,
  # and a tenant's rotation changes nothing it holds.
  echo "==> NEGATIVE CONTROL: every tenant's values are sealed under the one master key"
  patch internal/secrets/keyring.go \
    "	version, key, err := k.current(ctx, tx)
	if err != nil {
		return nil, err
	}
	return SealWith(key, version, plain)" \
    "	return k.master.Seal(plain)"
  ;;

--break-wake)
  # A pushed command wakes nobody. The held poll only notices at its
  # fallback tick, so a lock takes seconds longer than it should, and the
  # test that times it sees the difference.
  echo "==> NEGATIVE CONTROL: a pushed command does not wake the device's poll"
  patch internal/gateway/gateway.go \
    "		g.pipe.OnPushed = g.waiters.wake" \
    "		g.pipe.OnPushed = func(uuid.UUID) {}"
  ;;

--break-revealaudit)
  # A recovery key is revealed and nothing is written down.
  echo "==> NEGATIVE CONTROL: revealing a recovery key leaves no audit record"
  patch internal/data/escrow.go \
    "	return sealed, kind, AppendAudit(ctx, tx, \"recovery_key.revealed\"," \
    "	return sealed, kind, func(...any) error { return nil }("
  ;;

--break-revealrole)
  # Anyone who can see devices can see their recovery keys.
  echo "==> NEGATIVE CONTROL: the help desk can reveal recovery keys"
  patch internal/gateway/gateway.go \
    "	mux.Handle(\"POST /api/devices/{id}/recovery-key/reveal\", g.guard(authz.RetrieveKey, g.apiRevealKey))" \
    "	mux.Handle(\"POST /api/devices/{id}/recovery-key/reveal\", g.guard(authz.ViewDevices, g.apiRevealKey))"
  ;;

--break-logosniff)
  # The upload trusts whatever bytes arrive. An HTML file named logo.png
  # is served on every page as image/png and in the band of the PDF.
  echo "==> NEGATIVE CONTROL: a brand image is not checked to be an image"
  patch internal/branding/branding.go \
    "	typ := ImageType(b)
	if typ == \"\" {" \
    "	typ := ImageType(b)
	if typ == \"\" {
		typ = \"image/png\"
	}
	if false {"
  ;;

--break-hostpolicy)
  # Any hostname pointed at this platform gets a certificate on our
  # account. A stranger spends the issuance budget; a tenant that has
  # left keeps getting renewals.
  echo "==> NEGATIVE CONTROL: certificates are issued for any hostname"
  patch internal/directory/tls.go \
    "	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf(\"%w: %q\", ErrHostNotOurs, h)
	}" \
    "	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}"
  ;;

--break-ticketssrf)
  # The ticketing client dials anywhere. A tenant's "Jira" at
  # https://10.0.0.5 is a request from inside this platform to its own
  # internals, with a tenant-chosen body.
  echo "==> NEGATIVE CONTROL: the ticketing channel reaches inside the platform's network"
  patch internal/notify/ticketing.go \
    "	if t.AllowPrivateAddresses {
		return nil
	}" \
    "	if true {
		return nil
	}"
  ;;

--break-partnerscope)
  # The partner's list is every tenant. One reseller sees, meters and
  # suspends another's customers.
  echo "==> NEGATIVE CONTROL: a partner's tenant list is not scoped to the partner"
  patch internal/directory/partners.go \
    "		 WHERE t.partner_id = \$1
		 GROUP BY t.id ORDER BY t.created_at\`, partner.ID)" \
    "		 WHERE t.partner_id = \$1 OR true
		 GROUP BY t.id ORDER BY t.created_at\`, partner.ID)"
  ;;

--break-region)
  # A deployment serves any tenant that resolves to it. A tenant whose
  # data was promised to one region is served from another.
  echo "==> NEGATIVE CONTROL: the region check is off"
  patch internal/gateway/gateway.go \
    "	if g.region != \"\" && host.Region != \"\" && host.Region != g.region {" \
    "	if false {"
  ;;

--break-projectid)
  # The client stops naming the project on the sign-up call. Google refuses
  # ("Missing identifier. Provide the project id."), and so must the fake,
  # or a test passes against a Google that does not exist.
  echo "==> NEGATIVE CONTROL: the sign-up call names no project"
  patch internal/android/amapi.go \
    "	q := url.Values{\"projectId\": {a.project}, \"callbackUrl\": {callbackURL}}" \
    "	q := url.Values{\"callbackUrl\": {callbackURL}}"
  ;;

--break-callbackbase)
  # The console ignores the https callback it was given and sends Google
  # its own plain-http address. Google refuses; on a laptop nobody can
  # bind at all.
  echo "==> NEGATIVE CONTROL: the Android callback base is ignored"
  patch internal/gateway/android.go \
    "	if g.androidCallback != \"\" {" \
    "	if false {"
  ;;

--break-fakehttps)
  # The fake of Google accepts a callback Google would refuse. Tests pass
  # against a Google that does not exist.
  echo "==> NEGATIVE CONTROL: the fake accepts a plain-http callback"
  patch internal/android/fake.go \
    "		if !strings.HasPrefix(q.Get(\"callbackUrl\"), \"https://\") {" \
    "		if false {"
  ;;

--break-seats)
  # The seat count is never checked: a plan with three administrator seats
  # has as many administrators as the identity provider sends.
  echo "==> NEGATIVE CONTROL: administrator seats are not enforced"
  patch internal/gateway/seats.go \
    "	if used >= seats {" \
    "	if false {"
  ;;

--break-seatlapse)
  # A seat never lapses: whoever once signed in holds it for ever, so a
  # tenant whose administrators have moved on runs out of seats for good.
  echo "==> NEGATIVE CONTROL: seats never lapse"
  patch internal/gateway/seats.go \
    "		 WHERE subject = \$1 AND last_seen_at > now() - \$5::interval" \
    "		 WHERE subject = \$1 AND (\$5::interval IS NOT NULL)"
  ;;

--break-invitelink)
  # The invitation carries a link to this console instead of Google's. The
  # phone talks to Google; a link here is a link to nothing it can use.
  echo "==> NEGATIVE CONTROL: the invitation links to the console, not Google"
  patch internal/android/android.go \
    "	return \"https://enterprise.google.com/android/enroll?et=\" + url.QueryEscape(tokenValue)" \
    "	return \"https://console.kalesi.example/android/enroll?et=\" + url.QueryEscape(tokenValue)"
  ;;

--break-inviteaddress)
  # The address is not checked before Google is asked. A bad address costs
  # a token at Google, and a line break in it is on its way to a header.
  echo "==> NEGATIVE CONTROL: the invitation address is not checked first"
  patch internal/gateway/android.go \
    "		addrs, err := notify.ParseRecipients(strings.TrimSpace(r.FormValue(\"assigned_to\")))" \
    "		addrs, err := []string{strings.TrimSpace(r.FormValue(\"assigned_to\"))}, error(nil)"
  ;;

--break-expiryfield)
  # The client reads a field Google does not send, and the fake does not
  # notice because it sends what the client reads. The first real token's
  # invitation said it expired in the year 1.
  echo "==> NEGATIVE CONTROL: the token expiry is read from a field Google does not send"
  patch internal/android/amapi.go \
    "		ExpirationTime string \`json:\"expirationTimestamp\"\`" \
    "		ExpirationTime string \`json:\"expirationTime\"\`"
  patch internal/android/amapi.go \
    "	if err != nil && in.Lifetime > 0 {
		exp = time.Now().UTC().Add(in.Lifetime)
	}" \
    "	_ = err"
  ;;

--break-sharedwake)
  # The wake stays inside the instance that received the lock. A phone
  # held open on another instance waits for the fallback tick instead.
  echo "==> NEGATIVE CONTROL: the wake does not cross instances"
  patch internal/gateway/wake.go \
    "	if err := tx.Notify(ctx, wakeChannel, id.String()); err != nil {" \
    "	if err := error(nil); err != nil {"
  ;;

--break-resealhalt)
  # A tenant key the rotation cannot open is skipped instead of halting
  # the run. The database is left half under one master, half under the
  # other, with nothing to say which.
  echo "==> NEGATIVE CONTROL: a master-key rotation skips what it cannot open"
  patch internal/directory/keys.go \
    "			return ResealReport{}, fmt.Errorf(\"directory: tenant %s key version %d: %w; nothing was changed\", b.TenantID, b.Version, err)" \
    "			continue"
  ;;

--break-previousmaster)
  # The keyring forgets the master being rotated out: between the deploy
  # and the re-seal, every tenant key stops opening.
  echo "==> NEGATIVE CONTROL: the keyring ignores the previous master"
  patch internal/secrets/keyring.go \
    "	for _, m := range k.previous {" \
    "	for _, m := range k.previous[:0] {"
  ;;

--break-sharedrate)
  # The rate limit is counted in memory, per instance. A tenant behind two
  # gateways gets twice its plan.
  echo "==> NEGATIVE CONTROL: the rate limit is per instance"
  patch internal/gateway/gateway.go \
    "	if l.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)" \
    "	if false {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)"
  ;;

--break-importcounts)
  # The import does not check that what landed is what was sent. A bundle
  # missing a table's worth of rows is committed as if whole.
  echo "==> NEGATIVE CONTROL: the import skips the in-vs-out check"
  patch internal/directory/importer.go \
    "		if got != want {" \
    "		if false && got != want {"
  ;;

--break-importtenant)
  # The database stops checking that an imported row is the tenant's. A
  # bundle can write into another tenant.
  echo "==> NEGATIVE CONTROL: imported rows are not checked for their tenant"
  patch db/migrations/0035_tenant_import.sql \
    "  IF (r->>'tenant_id')::uuid IS DISTINCT FROM t THEN" \
    "  IF false THEN"
  ;;

--break-agentverify)
  # The agent trusts the connection and skips the signature. Anything that
  # can answer on the device's channel can lock or wipe it.
  echo "==> NEGATIVE CONTROL: the agent does not verify command signatures"
  patch internal/agent/agent.go \
    "		if !a.verified(ctx, c) {" \
    "		if false {"
  ;;

--break-sealedsigning)
  # The private signing key is stored in the clear.
  echo "==> NEGATIVE CONTROL: the signing key is stored unsealed"
  patch internal/command/storedkeys.go \
    "	sealed, err := s.Sealer.Seal(ctx, tx, der)" \
    "	sealed, err := der, error(nil)"
  ;;

--break-emailescape)
  # The HTML half of an email shows the message body as markup. A device
  # name or a reason typed by anyone becomes script in every inbox.
  echo "==> NEGATIVE CONTROL: the email body is not escaped in the HTML half"
  patch internal/notify/email.go \
    "		out.WriteString(\`<p style=\"margin:0 0 12px\">\` + linkify(html.EscapeString(para)) + \`</p>\`)" \
    "		out.WriteString(\`<p style=\"margin:0 0 12px\">\` + linkify(para) + \`</p>\`)"
  ;;

--break-emailbrand)
  # The stamp leaves the brand off: every email goes out in a default
  # colour with no legal footer, whatever the tenant set.
  echo "==> NEGATIVE CONTROL: the stamp leaves the brand off the email"
  patch internal/notify/notify.go \
    "		m.Colour, m.Footer = b.Colour, b.LegalFooter" \
    "		_ = b"
  ;;

--break-templates)
  # The Android template goes: a tenant with phones starts from a blank
  # form, which is a tenant who ships no policy to its phones.
  echo "==> NEGATIVE CONTROL: no template addresses Android"
  patch internal/policy/store.go \
    "			Scope: Scope{OSFamily: \"android\"}," \
    "			Scope: Scope{},"
  ;;

--break-persignout)
  # One person's sign-out is never checked. "Sign this laptop out" does
  # nothing until the session's own clock runs out.
  echo "==> NEGATIVE CONTROL: a person's sign-out stamp is ignored"
  patch internal/gateway/gateway.go \
    "		if sess.StartedAt.Before(g.subjectInvalidBefore(r.Context(), host, sess.Subject)) {" \
    "		if false {"
  ;;

--break-coalesce)
  # The line is set so high that nothing ever coalesces: a fleet failing
  # at once is a hundred messages in the channel.
  echo "==> NEGATIVE CONTROL: notifications never coalesce"
  patch internal/notify/notify.go \
    "const DefaultCoalesceAbove = 3" \
    "const DefaultCoalesceAbove = 1000"
  ;;

--break-rplogout)
  # Sign-out clears our cookie and stops. The person is still signed in at
  # the provider; the next person at a shared machine is them.
  echo "==> NEGATIVE CONTROL: sign-out does not end the provider's session"
  patch internal/gateway/signin.go \
    "	if host, ok := g.resolveHostQuietly(r); ok && g.oidc != nil {" \
    "	if host, ok := g.resolveHostQuietly(r); false && ok && g.oidc != nil {"
  ;;

--break-saml)
  # An assertion that answers no request of ours, or somebody else's, is
  # accepted. That is an identity-provider-initiated sign-in, which is a
  # replay with a better name: a captured assertion signs its holder in
  # from any browser for as long as its validity window lasts.
  echo "==> NEGATIVE CONTROL: SAML takes an assertion for any request"
  patch internal/identity/saml.go \
    "		AllowIDPInitiated: false," \
    "		AllowIDPInitiated: true,"
  ;;

--break-samlhost)
  # The SAML callback no longer insists the flow and the hostname name the
  # same tenant: a sign-in begun on one tenant's hostname finishes on
  # another's.
  echo "==> NEGATIVE CONTROL: SAML callback ignores which tenant the flow was for"
  patch internal/gateway/saml.go \
    "	if flow.TenantID != host.ID {" \
    "	if false && flow.TenantID != host.ID {"
  ;;

--break-remediate)
  # Every failed finding is marked for the device to act on, whether or
  # not the policy asked. A tenant that only wanted to observe finds its
  # fleet's firewalls, encryption and password policies changed.
  echo "==> NEGATIVE CONTROL: findings are marked for remediation whatever the policy said"
  patch internal/policy/policy.go \
    "		Fix:     req.Fix && !unknown," \
    "		Fix:     !unknown,"
  ;;

--break-nativebounds)
  # The number the server sends is used as it came. Nothing else from
  # the server reaches a command line, but a password length of a
  # million or a lock timeout of zero is a setting nobody asked for.
  echo "==> NEGATIVE CONTROL: the native enforcer takes any number from the server"
  patch internal/agent/native.go \
    "		if f.Num < 1 || f.Num > MaxPasscodeLength {" \
    "		if false {"
  ;;

--break-vaulthttp)
  # A vault address over plain http is accepted for any host. The three
  # platform keys cross the network in the clear on every start.
  echo "==> NEGATIVE CONTROL: platform keys may be fetched from a vault over plain http"
  patch internal/platformkeys/vault.go \
    "	if u.Scheme != \"https\" && !loopback(u.Hostname()) {" \
    "	if false {"
  ;;

--break-keydescribe)
  # The start-up line prints the key bytes along with the fingerprint.
  # Every log shipper downstream of the gateway now holds the keys.
  echo "==> NEGATIVE CONTROL: the start-up line prints the platform keys"
  patch internal/platformkeys/platformkeys.go \
    "	return fmt.Sprintf(\"%s %d bytes, fingerprint %s\", name, len(v), fingerprint(v))" \
    "	return fmt.Sprintf(\"%s %d bytes, fingerprint %s %s\", name, len(v), fingerprint(v), v)"
  ;;

--break-keyfilemode)
  # A key file any user on the host can read is read. The sealing master
  # is one 'cat' away for anybody with a shell.
  echo "==> NEGATIVE CONTROL: a world-readable key file is accepted"
  patch internal/platformkeys/platformkeys.go \
    "	if perm := info.Mode().Perm(); perm&0o077 != 0 {" \
    "	if perm := info.Mode().Perm(); false {"
  ;;

--break-freemailsuffix)
  # Only the exact domain is checked against the free-mail list. Every
  # provider's subdomain, and every disposable service's per-user
  # hostname, signs up as a company.
  echo "==> NEGATIVE CONTROL: a subdomain of a free-mail provider is a work address"
  patch internal/directory/freemail.go \
    "	for i := 0; i < len(labels)-1; i++ {" \
    "	for i := 0; i < 1 && len(labels) > 1; i++ {"
  ;;

--break-macnormalise)
  # The address is matched as written. A NAC that writes aabb.ccdd.eeff
  # asks about a device the feed has as aa:bb:cc:dd:ee:ff and is told
  # unknown, and the network's unmanaged-device policy applies instead.
  echo "==> NEGATIVE CONTROL: a MAC address is matched only as written"
  patch internal/data/macs.go \
    "	s = strings.NewReplacer(\":\", \"\", \"-\", \"\", \".\", \"\", \" \", \"\").Replace(s)" \
    "	s = strings.ReplaceAll(s, \":\", \"\")"
  ;;

--break-macmove)
  # An address stays with the device that reported it first. The dock
  # moved from a quarantined laptop keeps the clean laptop off the
  # network, and the reverse lets a quarantined one on.
  echo "==> NEGATIVE CONTROL: a MAC address never moves between devices"
  patch internal/data/macs.go \
    "			   SET device_id = excluded.device_id," \
    "			   SET device_id = device_macs.device_id,"
  ;;

--break-isecompliance)
  # Every registered device is compliant as far as ISE is told. The
  # door's answer and ISE's answer part company.
  echo "==> NEGATIVE CONTROL: ISE is told every registered device is compliant"
  patch internal/gateway/ise.go \
    "				Compliance:     iseCompliance{Status: v.Access == \"allow\", FailureReason: v.Reason}," \
    "				Compliance:     iseCompliance{Status: true, FailureReason: v.Reason},"
  ;;

--break-historychange)
  # A history row on every report. A fleet reporting every quarter of
  # an hour writes ninety-six rows a day per device, and the history
  # stops saying when anything changed.
  echo "==> NEGATIVE CONTROL: the verdict history grows on every report"
  patch internal/data/history.go \
    "	if previous == current {" \
    "	if false {"
  ;;

--break-trendcount)
  # The snapshot counts something other than the dashboard does. The
  # trend and the board disagree, and nobody knows which to believe.
  echo "==> NEGATIVE CONTROL: the trend is not the dashboard's count"
  patch internal/data/history.go \
    "		Compliant: c.Compliant, NotCompliant: c.NotCompliant," \
    "		Compliant: c.Total, NotCompliant: c.NotCompliant,"
  ;;

--break-personsql)
  # The database's half of person isolation is switched off: the
  # restrictive policy on devices passes everything. The Go predicate is
  # all that is left, and a raw query from an employee's transaction
  # reads the whole tenant.
  echo "==> NEGATIVE CONTROL: the database no longer holds an employee to their own devices"
  patch db/migrations/0042_person_isolation.sql \
    "  USING (app.claim_role() <> 'employee' OR person_id = app.current_person())" \
    "  USING (true)"
  ;;

--break-slosig)
  # A logout request from the provider is taken without its signature.
  # Anyone who can get a browser to our logout endpoint can sign that
  # browser out by naming a subject.
  echo "==> NEGATIVE CONTROL: a provider's logout request is accepted unsigned"
  patch internal/identity/saml_logout.go \
    "	if _, err := vc.Validate(root); err != nil {" \
    "	if _, err := vc.Validate(root); false && err != nil {"
  ;;

--break-rotategrace)
  # A rotation forgets the key before it. Every session open at the
  # moment the keys turn over ends at its next request, which is a
  # fleet-wide sign-out at every rotation, so nobody rotates.
  echo "==> NEGATIVE CONTROL: a key rotation ends every open session"
  patch internal/session/session.go \
    "	if !hmac.Equal(sig, mac(cur, []byte(signed))) && (prev == nil || !hmac.Equal(sig, mac(prev, []byte(signed)))) {" \
    "	if !hmac.Equal(sig, mac(cur, []byte(signed))) && (prev == nil || true) {"
  ;;

--break-keysdiffer)
  # One key doing three jobs is accepted, at start and at every re-read.
  echo "==> NEGATIVE CONTROL: the same key may do all three jobs"
  patch internal/platformkeys/platformkeys.go \
    "	if string(k.Claim) == string(k.Session) || string(k.Claim) == string(k.Sealing) ||" \
    "	if false ||"
  ;;

--break-bucketssrf)
  # The export-to-bucket sender dials whatever the endpoint's name
  # resolves to. "my bucket" becomes the metadata service, and a tenant's
  # Super Admin can have the whole export posted inside this platform's
  # own network.
  echo "==> NEGATIVE CONTROL: the export is sent to any address the endpoint resolves to"
  patch internal/gateway/bucket.go \
    "					if !g.allowPrivateBuckets && !notify.PublicIP(ip.IP) {" \
    "					if false && !notify.PublicIP(ip.IP) {"
  ;;

--break-lockout)
  # Wrong passwords are counted and never lock. Anybody can guess at
  # an account for as long as they have patience.
  echo "==> NEGATIVE CONTROL: five wrong passwords do not lock an account"
  patch internal/data/local.go \
    "	LockAfter = 5" \
    "	LockAfter = 500000"
  ;;

--break-totpreplay)
  # A second-factor code is good more than once. A code somebody watched
  # being typed signs them in too.
  echo "==> NEGATIVE CONTROL: a second-factor code can be used twice"
  patch internal/data/local.go \
    "AND totp_last_step < \$2" \
    "AND totp_last_step <= \$2"
  ;;

--break-lastadmin)
  # The last Super Admin can be disabled or demoted. The tenant has
  # nobody who can invite anyone, and nobody who can fix it.
  echo "==> NEGATIVE CONTROL: the last Super Admin can be removed"
  patch internal/data/local.go \
    "	if targetIsOne && others == 0 {" \
    "	if false && targetIsOne && others == 0 {"
  ;;

--break-enumeration)
  # An address with no account is told so. Anyone can learn who has an
  # account here, and the list is where phishing starts.
  echo "==> NEGATIVE CONTROL: an unknown address gets a different answer"
  patch internal/gateway/local_signin.go \
    "		localauth.VerifyAbsent(password)" \
    "		g.localRender(w, r, host, http.StatusNotFound, console.LocalView{Mode: \"signin\", Title: \"No such account\", Said: \"No account has that email address.\", Email: email}); return"
  ;;

--break-localtoken)
  # An invitation or reset link works more than once. A link left in an
  # inbox is a standing way in.
  echo "==> NEGATIVE CONTROL: a spent link can be used again"
  patch internal/data/local.go \
    "		 WHERE token_hash = \$1 AND purpose = \$2 AND used_at IS NULL AND expires_at > \$3" \
    "		 WHERE token_hash = \$1 AND purpose = \$2 AND expires_at > \$3"
  # The link is checked twice, once when the page opens and again when the
  # password is saved. Both must go, or the first still turns a spent link away.
  patch internal/data/local.go \
    "t.token_hash = \$1 AND t.purpose = \$2 AND t.used_at IS NULL AND t.expires_at > \$3" \
    "t.token_hash = \$1 AND t.purpose = \$2 AND t.expires_at > \$3"
  ;;

--break-mfarequired)
  # An administrator signs in on a password alone, whatever the policy.
  echo "==> NEGATIVE CONTROL: administrators are not held to the second factor"
  patch internal/data/local.go \
    '	case "super_admin", "it_admin", "security_manager":' \
    '	case "no_such_role":'
  ;;

--break-reserved)
  # A customer takes the short name app or www, the operator's own hosts.
  echo "==> NEGATIVE CONTROL: reserved short names are allowed"
  patch internal/directory/onboard.go \
    "	if reservedSlugs[s] {" \
    "	if false && reservedSlugs[s] {"
  ;;

--break-qrpayload)
  # The QR code holds the bare token instead of Google's link, so a camera
  # reads a string of letters and nothing opens.
  echo "==> NEGATIVE CONTROL: the QR code carries the bare token"
  patch internal/gateway/android.go \
    "	text, kind := android.EnrolLink(tok.Value), \"link\"" \
    "	text, kind := tok.Value, \"link\""
  ;;

--break-qrowner)
  # A company phone is shown the link QR code. It scans, and leads nowhere:
  # a welcome screen has no browser to open it in.
  echo "==> NEGATIVE CONTROL: a company phone gets the personal-phone QR code"
  patch internal/gateway/android.go \
    "	if ownership != \"personal\" {
		text, kind = tok.QRCode, \"provision\"" \
    "	if false {
		text, kind = tok.QRCode, \"provision\""
  ;;

--break-selfwho)
  # The code is made for whatever address the form names, not the address of
  # the person signed in. Anybody could then enrol a phone as anybody.
  echo "==> NEGATIVE CONTROL: the code is for the address typed, not the signed-in person"
  patch internal/gateway/selfenrol.go \
    "	email := strings.ToLower(strings.TrimSpace(res.Email))" \
    "	email := strings.ToLower(strings.TrimSpace(r.FormValue(\"assigned_to\")))"
  ;;

--break-selfoff)
  # The administrator's setting is ignored: a code is made while it is off.
  echo "==> NEGATIVE CONTROL: self-enrolment works while it is switched off"
  patch internal/gateway/selfenrol.go \
    "			if mode == android.SelfOff {" \
    "			if false {"
  ;;

--break-selfcap)
  # No limit on how many codes one person can make Google issue.
  echo "==> NEGATIVE CONTROL: no limit on codes per person"
  patch internal/gateway/selfenrol.go \
    "			if n >= android.SelfLimit {" \
    "			if n >= 1<<30 {"
  ;;

--break-selfowner)
  # A person in personal-only mode can still ask for a company phone.
  echo "==> NEGATIVE CONTROL: a person may ask for a company phone in personal mode"
  patch internal/gateway/selfenrol.go \
    "			if mode == android.SelfAny && wanted == \"company\" {" \
    "			if wanted == \"company\" {"
  ;;

--break-selfleaver)
  # Somebody the platform has been told has left can still enrol a phone.
  echo "==> NEGATIVE CONTROL: a leaver can enrol a phone"
  patch internal/gateway/selfenrol.go \
    "			if left {" \
    "			if left && false {"
  ;;

--break-unverifiedemail)
  # An address the provider marks unverified is used as the person's address.
  # Whoever can edit their own profile at the provider could then become
  # somebody else here.
  echo "==> NEGATIVE CONTROL: an unverified email is believed"
  patch internal/identity/identity.go \
    "	if !present {" \
    "	if true || !present {"
  ;;

--break-joincode)
  # The code is not checked: the link alone gives the way in.
  echo "==> NEGATIVE CONTROL: a join link needs no code"
  patch internal/gateway/join.go \
    "	if !android.VerifyJoinCode(r.PostFormValue(\"code\"), codeHash) {" \
    "	if false && !android.VerifyJoinCode(r.PostFormValue(\"code\"), codeHash) {"
  ;;

--break-joinlock)
  # Any number of wrong codes: the link is never paused, so a code can be guessed.
  echo "==> NEGATIVE CONTROL: wrong codes never pause a link"
  patch internal/android/join.go \
    "	if count >= JoinMaxWrong {" \
    "	if count >= 1<<30 {"
  ;;

--break-joincap)
  # The device limit is not enforced, in the state check or in the statement
  # that counts the use.
  echo "==> NEGATIVE CONTROL: a join link has no device limit"
  patch internal/android/join.go \
    "	case j.Uses >= j.MaxUses:" \
    "	case false:"
  patch internal/android/join.go \
    "		 WHERE id = \$1 AND status = 'active' AND expires_at > \$2 AND uses < max_uses" \
    "		 WHERE id = \$1 AND status = 'active' AND expires_at > \$2"
  ;;

--break-joinexpiry)
  # A link outlives its time.
  echo "==> NEGATIVE CONTROL: a join link never runs out of time"
  patch internal/android/join.go \
    "	case !now.Before(j.ExpiresAt):" \
    "	case false:"
  patch internal/android/join.go \
    "		 WHERE id = \$1 AND status = 'active' AND expires_at > \$2 AND uses < max_uses" \
    "		 WHERE id = \$1 AND status = 'active' AND uses < max_uses"
  ;;

--break-joincancel)
  # A cancelled link keeps working.
  echo "==> NEGATIVE CONTROL: a cancelled join link still works"
  patch internal/android/join.go \
    "	case j.Status == \"cancelled\":" \
    "	case false:"
  patch internal/android/join.go \
    "		 WHERE id = \$1 AND status = 'active' AND expires_at > \$2 AND uses < max_uses" \
    "		 WHERE id = \$1 AND expires_at > \$2 AND uses < max_uses"
  ;;

--break-joinrace)
  # The link is not locked while a guess is judged, so a burst of
  # simultaneous guesses are all tried before any is counted.
  echo "==> NEGATIVE CONTROL: guesses at a join link are not taken one at a time"
  patch internal/android/join.go \
    "code_hash FROM join_links WHERE id = \$1 FOR UPDATE" \
    "code_hash FROM join_links WHERE id = \$1"
  ;;

--break-joinreset)
  # A success wipes the wrong-guess count, so somebody guessing gets a fresh
  # ten tries every time another person gets in.
  echo "==> NEGATIVE CONTROL: a success resets the wrong-guess count"
  patch internal/android/join.go \
    "		UPDATE join_links SET uses = uses + 1" \
    "		UPDATE join_links SET uses = uses + 1, failed_count = 0, failed_since = NULL"
  ;;

--break-configsystem)
  # A policy may carry another system's settings.
  echo "==> NEGATIVE CONTROL: a policy for one system may carry another system's settings"
  patch internal/policy/config.go \
    "	if scope.OSFamily != sys {" \
    "	if false && scope.OSFamily != sys {"
  ;;

--break-configowner)
  # A setting that cannot reach a kind of phone is accepted on a policy for that kind.
  echo "==> NEGATIVE CONTROL: a company-only setting is accepted on a personal policy"
  patch internal/policy/config.go \
    "		if s.For == \"company\" && scope.Ownership == \"personal\" {" \
    "		if false && s.For == \"company\" && scope.Ownership == \"personal\" {"
  ;;

--break-configfilter)
  # A work profile is sent company-only settings and a company phone work-profile ones.
  echo "==> NEGATIVE CONTROL: settings are not filtered by kind of phone"
  patch internal/android/store.go \
    "s.For != \"all\" && s.For != ownership {" \
    "s.For != \"all\" && s.For != ownership && false {"
  ;;

--break-configstrict)
  # The longer passcode loses: the looser value wins a merge.
  echo "==> NEGATIVE CONTROL: the lower of two minimums wins"
  patch internal/catalog/catalog.go \
    "		if b.(int) > a.(int) {" \
    "		if b.(int) < a.(int) {"
  ;;

--break-configrules)
  # The rules a policy judges by are not part of what a phone is given.
  echo "==> NEGATIVE CONTROL: a rule stricter than a setting is not delivered"
  patch internal/android/translate.go \
    "	merged := catalog.Merge(fromRules, cfg)" \
    "	merged := catalog.Merge(cfg)"
  ;;

--break-configunknown)
  # An unknown setting is skipped instead of refused.
  echo "==> NEGATIVE CONTROL: an unknown setting is silently ignored"
  patch internal/catalog/catalog.go \
    "			return nil, fmt.Errorf(\"%w: %q\", ErrUnknown, key)" \
    "			continue"
  ;;

--break-libraryonce)
  # A ready-made policy can be added twice.
  echo "==> NEGATIVE CONTROL: a ready-made policy is added again"
  patch internal/gateway/console_post.go \
    "				if p.Name == t.Title {" \
    "				if false && p.Name == t.Title {"
  ;;

--break-personalpolicy)
  # A work-profile phone is enrolled onto the company policy.
  echo "==> NEGATIVE CONTROL: a personal phone is given the company policy"
  patch internal/android/store.go \
    "	if ownership == \"personal\" {
" \
    "	if false {
"
  ;;

--break-localprotocol)
  # A password signs in at a tenant that has an identity provider, which
  # is a way round the provider's own controls, offboarding above all.
  echo "==> NEGATIVE CONTROL: a password signs in at an identity-provider tenant"
  patch internal/gateway/local_signin.go \
    "	if errors.Is(err, directory.ErrNoIdentityConfig) || (err == nil && !cfg.IsLocal()) {" \
    "	if errors.Is(err, directory.ErrNoIdentityConfig) {"
  ;;

--break-sessionsend)
  # Disabling an account, changing its role or resetting its password
  # leaves the sessions it already has. The person is gone and still in.
  echo "==> NEGATIVE CONTROL: ending an account's sessions does nothing"
  patch internal/gateway/local_signin.go \
    "SET sessions_invalid_before = GREATEST(tenant_admins.sessions_invalid_before, \$2)" \
    "SET sessions_invalid_before = tenant_admins.sessions_invalid_before"
  ;;

--break-googlewords)
  # Google's refusal is shown as the raw JSON envelope. The administrator
  # who has to switch an API on gets a wall of braces instead of a sentence.
  echo "==> NEGATIVE CONTROL: Google's refusal is dumped as JSON"
  patch internal/android/amapi.go \
    "	if json.Unmarshal([]byte(e.Body), &g) == nil && g.Error.Message != \"\" {" \
    "	if false && json.Unmarshal([]byte(e.Body), &g) == nil && g.Error.Message != \"\" {"
  ;;

*)
  echo "unknown mode: $MODE"
  echo "use one of: --break-claim --break-host --break-brand --break-approval"
  echo "            --break-csrf --break-rolemap --break-audience --break-revocation"
  echo "            --break-certtrust --break-csrsubject --break-reenrol"
  echo "            --break-merge --break-unknownrule --break-silence --break-quarantine"
  echo "            --break-devicerole --break-devicescope --break-ack"
  echo "            --break-mine --break-lostowner"
  echo "            --break-ssrf --break-refusal --break-dedupe"
  echo "            --break-headers --break-cleartext"
  echo "            --break-dnsproof --break-alignment"
  echo "            --break-tokenfile --break-doctor"
  echo "            --break-renewrevoked --break-renewwindow"
  echo "            --break-operatorreach --break-signupreuse --break-signupexpiry"
  echo "            --break-signupcap --break-signupfreemail --break-proxytrust"
  echo "            --break-brake --break-optin --break-releasepath --break-scopedbrake"
  echo "            --break-androidstate --break-androidwipe --break-androidjudged --break-lostbrand --break-lostcontact"
  echo "            --break-reportbrand --break-reportaudit --break-rollbackinplace"
  echo "            --break-devicecap --break-featureflag --break-rolloutall --break-rolloutshuffle"
  echo "            --break-siemcursor --break-siembrand --break-offboardretire --break-tokenscope --break-offboardscope"
  echo "            --break-offboardactive --break-offboardresidue --break-exportsecret"
  echo "            --break-rotatereseal --break-keyscope --break-wake --break-revealaudit --break-revealrole --break-logosniff --break-hostpolicy --break-ticketssrf --break-partnerscope --break-region"
  echo "            --break-googlewords --break-projectid --break-callbackbase --break-fakehttps"
  echo "            --break-seats --break-seatlapse --break-invitelink --break-inviteaddress --break-expiryfield --break-sharedwake"
  echo "            --break-resealhalt --break-previousmaster --break-sharedrate"
  echo "            --break-importcounts --break-importtenant --break-agentverify --break-sealedsigning"
  echo "            --break-emailescape --break-emailbrand --break-templates --break-persignout --break-coalesce --break-rplogout"
  echo "            --break-saml --break-samlhost --break-remediate --break-nativebounds"
  echo "            --break-vaulthttp --break-keydescribe --break-keyfilemode --break-freemailsuffix"
  echo "            --break-macnormalise --break-macmove --break-isecompliance --break-emailreuse --break-leftmark"
  echo "            --break-historychange --break-trendcount --break-personsql --break-slosig --break-rotategrace --break-keysdiffer --break-bucketssrf"
  echo "            --break-lockout --break-totpreplay --break-lastadmin --break-enumeration --break-localtoken --break-mfarequired --break-localprotocol --break-sessionsend --break-reserved --break-qrpayload --break-qrowner --break-selfwho --break-selfoff --break-selfcap --break-selfowner --break-selfleaver --break-unverifiedemail --break-joincode --break-joinlock --break-joincap --break-joinexpiry --break-joincancel --break-joinrace --break-joinreset --break-configsystem --break-configowner --break-configfilter --break-configstrict --break-configrules --break-configunknown --break-libraryonce --break-personalpolicy"
  echo "            --break-tokenrevoked --break-networkrole --break-feeddeny --break-feedunknown"
  exit 2
  ;;
esac

# Refuse to start if another run already holds the database.
#
# This is here because it has been got wrong twice: a negative-control sweep
# running in the background while the suite ran in the foreground, both using
# this container name. Each tore the other's database down mid-seed, and the
# result was a page of foreign-key violations in unrelated tests that looked
# exactly like a product defect. It cost more time than every real bug in the
# sprint put together.
#
# Removing the container unconditionally, as this used to, is precisely what
# made it possible.
if docker ps --format '{{.Names}}' | grep -qx "$PG"; then
  echo "REFUSING TO START: $PG is already running."
  echo ""
  echo "Another run of this script has the database. Two runs share one"
  echo "container name, so starting now would tear that one down mid-test and"
  echo "produce failures in both that look like real defects."
  echo ""
  echo "Wait for it to finish, or stop it with:  docker rm -f $PG"
  exit 1
fi

docker network create "$NET" >/dev/null 2>&1 || true

echo "==> starting $PGIMAGE as $PG"
docker rm -f "$PG" >/dev/null 2>&1 || true
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_PASSWORD="$SUPERPASS" \
  -e POSTGRES_DB=mdm \
  "$PGIMAGE" >/dev/null

# Waiting on a real query rather than pg_isready: the image answers
# pg_isready during its own bootstrap, before the database exists.
echo "==> waiting for the database to exist and answer"
READY=0
for i in $(seq 1 60); do
  if docker exec "$PG" psql -U postgres -d mdm -tAc 'select 1' >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  echo "database did not become available in 60 seconds"
  docker logs "$PG" 2>&1 | tail -20
  exit 1
fi

echo "==> applying migrations"
for f in "$SRC"/db/migrations/*.sql; do
  echo "    $(basename "$f")"
  docker exec -i "$PG" psql -v ON_ERROR_STOP=1 -U postgres -d mdm -f - < "$f" >/dev/null
done

# Deployment configuration, not schema: the application connects as mdm_app.
# In production this credential comes from the vault, never from a script.
echo "==> granting the application and directory roles a login"
docker exec -i "$PG" psql -v ON_ERROR_STOP=1 -U postgres -d mdm \
  -c "ALTER ROLE mdm_app LOGIN PASSWORD '${APPPASS}';" \
  -c "ALTER ROLE mdm_operator LOGIN PASSWORD '${OPPASS}';" \
  -c "GRANT CONNECT ON DATABASE mdm TO mdm_app, mdm_operator;" >/dev/null

OUT="$(mktemp)"

echo "==> running the Go tests"
set +e
docker run --rm --network "$NET" \
  -v "$SRC":/src \
  -v mdm-gomodcache:/go/pkg/mod \
  -w /src \
  -e MDM_TEST_DSN="postgres://mdm_app:${APPPASS}@${PG}:5432/mdm" \
  -e MDM_TEST_ADMIN_DSN="postgres://postgres:${SUPERPASS}@${PG}:5432/mdm" \
  -e MDM_TEST_OPERATOR_DSN="postgres://mdm_operator:${OPPASS}@${PG}:5432/mdm" \
  -e GOFLAGS=-mod=mod \
  -e GOTESTFLAGS="${GOTESTFLAGS:-}" \
  "$GOIMAGE" sh -c "go mod tidy >/dev/null 2>&1 && go test ./... -count=1 -p 1 ${GOTESTFLAGS:-} 2>&1" | tee "$OUT"
RESULT=${PIPESTATUS[0]}
set -e

echo ""
if [ "$MODE" != "normal" ]; then
  if grep -q "build failed" "$OUT"; then
    echo "NEGATIVE CONTROL INVALID: the patched copy did not compile."
    echo "A build failure says nothing about whether the tests catch the behaviour."
    exit 1
  fi
  if [ $RESULT -eq 0 ]; then
    echo "NEGATIVE CONTROL FAILED: the tests passed with the check removed."
    echo "They are not testing what they claim to test."
    exit 1
  fi
  echo "NEGATIVE CONTROL PASSED: the tests caught the removed check."
  exit 0
fi

if [ $RESULT -ne 0 ]; then
  echo "GO TESTS FAILED. This fails the build."
  exit 1
fi
echo "GO TESTS PASSED."
