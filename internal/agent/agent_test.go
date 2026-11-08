package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/enrol"
	"platform/internal/gateway"
	"platform/internal/policy"
	"platform/internal/secrets"
	"platform/internal/tenantclaim"
)

// These are the only tests in the build that run the WHOLE stack: a real
// agent, over real TLS, presenting a real client certificate, against the
// real gateway and a real PostgreSQL.
//
// Everything before this sprint tested the device path by setting r.TLS on a
// synthetic request. That proved the handler logic and proved nothing about
// whether a certificate this platform issues is one a Go TLS client can
// actually present and a Go TLS server can actually read. It can, and this
// is where that is established.

var (
	tenantA = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	testKey = []byte("agent-suite-signing-key-32-bytes!!!!")
	sealKey = []byte("agent-suite-sealing-key-32-bytes")
)

type rig struct {
	server  *httptest.Server
	pipe    *command.Pipeline
	store   *data.Store
	signer  *tenantclaim.Signer
	pool    *x509.CertPool
	bodies  *bodyRecorder
	enrol   *enrol.Service
	devices func(t *testing.T) []deviceRow
}

type deviceRow struct {
	ID    uuid.UUID
	Name  string
	State string
}

// bodyRecorder keeps every request body the agent sent, so a test can assert
// what was NOT in them. It WRAPS the agent's own transport rather than
// replacing it, so the device certificate is still presented and what is
// being observed is the real traffic.
type bodyRecorder struct {
	mu   sync.Mutex
	sent [][]byte
	base http.RoundTripper
}

func (b *bodyRecorder) wrap(rt http.RoundTripper) http.RoundTripper {
	b.mu.Lock()
	b.base = rt
	b.mu.Unlock()
	return b
}

func (b *bodyRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		b.mu.Lock()
		b.sent = append(b.sent, raw)
		b.mu.Unlock()
	}
	b.mu.Lock()
	base := b.base
	b.mu.Unlock()
	return base.RoundTrip(r)
}

func (b *bodyRecorder) all() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var sb strings.Builder
	for _, s := range b.sent {
		sb.Write(s)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()

	appDSN := os.Getenv("MDM_TEST_DSN")
	opDSN := os.Getenv("MDM_TEST_OPERATOR_DSN")
	adminDSN := os.Getenv("MDM_TEST_ADMIN_DSN")
	if appDSN == "" || opDSN == "" || adminDSN == "" {
		t.Skip("database environment not set")
	}

	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	for _, s := range []string{
		`DELETE FROM offboarding_log`,
		`DELETE FROM tenant_keys`,
		`DELETE FROM siem_cursors`,
		`DELETE FROM usage_snapshots`,
		`DELETE FROM signups`,
		`DELETE FROM integration_tokens`,
		`DELETE FROM android_enrollment_tokens`,
		`DELETE FROM join_links`,
		`DELETE FROM android_enterprises`,
		`DELETE FROM sending_domains`,
		`DELETE FROM notifications`,
		`DELETE FROM notification_targets`,
		`DELETE FROM device_apps`,
		`DELETE FROM device_recovery_keys`,
		`DELETE FROM device_compliance`,
		`DELETE FROM device_certificates`,
		`DELETE FROM enrolments`,
		`DELETE FROM tenant_ca`,
		`DELETE FROM command_signing_keys`,
		`DELETE FROM command_approvals`,
		`DELETE FROM commands`,
		`DELETE FROM audit_events`,
		`DELETE FROM devices`,
		`DELETE FROM local_tokens`,
		`DELETE FROM local_accounts`,
		`DELETE FROM tenant_enrolment`,
		`DELETE FROM people`,
		`DELETE FROM compliance_snapshots`,
		`DELETE FROM policies`,
		`DELETE FROM tenant_branding`,
		`DELETE FROM tenant_domains`,
		`DELETE FROM tenant_role_map`,
		`DELETE FROM tenant_identity`,
		`DELETE FROM tenants WHERE id = '11111111-1111-1111-1111-111111111111'`,
		`DELETE FROM partners`,
		`INSERT INTO tenants (id, name, slug, plan, status, api_rate_per_min) VALUES
		   ('11111111-1111-1111-1111-111111111111','Kalesi Foods','kalesi','growth','active',6000)`,
		// The agent dials the test server directly, so the hostname that
		// decides the tenant is the loopback address.
		`INSERT INTO tenant_domains (host, tenant_id, verified_at)
		   VALUES ('127.0.0.1','11111111-1111-1111-1111-111111111111', now())`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %.50s: %v", s, err)
		}
	}

	signer, err := tenantclaim.NewSigner(testKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store, err := data.Open(ctx, appDSN, signer, 8)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(store.Close)
	dir, err := directory.Open(ctx, opDSN)
	if err != nil {
		t.Fatalf("directory: %v", err)
	}
	t.Cleanup(dir.Close)
	master, err := secrets.NewAESSealer(sealKey)
	sealer := secrets.NewKeyring(master)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	enrolment := enrol.New(sealer)

	pipe := command.New(&command.StoredKeys{Sealer: sealer, Bits: 1024},
		command.AppleNotConfigured(), command.DefaultLimiter())
	g := gateway.New(gateway.Config{
		Directory: dir, Store: store, Signer: signer,
		Pipeline: pipe,
		Sealer:   sealer, Enrol: enrolment, CSRFKey: testKey,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	srv := httptest.NewUnstartedServer(g.Handler())
	// RequestClientCert rather than RequireAndVerify: the gateway verifies
	// the certificate itself, against what it issued, which is a stronger
	// check than chain validation and also the only one that can answer
	// revocation. See internal/gateway/enrolment.go.
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	return &rig{
		server: srv, pipe: pipe, store: store, signer: signer, pool: pool,
		bodies: &bodyRecorder{}, enrol: enrolment,
		devices: func(t *testing.T) []deviceRow {
			t.Helper()
			c, err := pgx.Connect(ctx, adminDSN)
			if err != nil {
				t.Fatalf("admin connect: %v", err)
			}
			defer c.Close(ctx)
			rows, err := c.Query(ctx, `SELECT id, name, state FROM devices ORDER BY name`)
			if err != nil {
				t.Fatalf("devices: %v", err)
			}
			defer rows.Close()
			var out []deviceRow
			for rows.Next() {
				var d deviceRow
				if err := rows.Scan(&d.ID, &d.Name, &d.State); err != nil {
					t.Fatalf("scan: %v", err)
				}
				out = append(out, d)
			}
			return out
		},
	}
}

// claim mints an administrator-shaped claim so a test can do the things an
// administrator would: write a policy, create an enrolment, ask for a lock.
func (r *rig) admin(t *testing.T, fn func(ctx context.Context, tx *data.Tx) error) {
	t.Helper()
	tok, err := r.signer.Mint(tenantclaim.Claim{
		TenantID: tenantA, Subject: "o.martins", Role: "it_admin",
		RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := r.store.WithTenant(context.Background(), tok, fn); err != nil {
		t.Fatalf("admin work: %v", err)
	}
}

func (r *rig) invite(t *testing.T, label string) string {
	t.Helper()
	var token string
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		_, tk, err := r.enrol.Create(ctx, tx, enrol.CreateInput{
			Label: label, Ownership: "company", OSFamily: "macos",
		})
		token = tk
		return err
	})
	return token
}

func (r *rig) newAgent(t *testing.T, probe Probe, enforcer Enforcer) *Agent {
	t.Helper()
	a, err := New(Config{
		ServerURL: r.server.URL,
		Dir:       t.TempDir(),
		Probe:     probe,
		Enforcer:  enforcer,
		RootCAs:   r.pool,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Wrap:      r.bodies.wrap,
	})
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	return a
}

func macProbe() FixedProbe {
	return FixedProbe{
		SerialNumber: "C02XK4YTQ6NV", Family: "macos", Host: "kemi-mbp",
		Report: policy.Report{OSVersion: "15.2"},
	}
}

// ------------------------------------------------------------- the whole arc

// One agent, from a machine that has never been seen, to a machine that has
// enrolled, been judged, been told to lock, locked, and said so.
func TestAnAgentEnrolsReportsAndObeys(t *testing.T) {
	r := newRig(t)

	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		_, err := policy.Save(ctx, tx, policy.SaveInput{
			Name:      "Baseline",
			Body:      []byte(`{"disk_encryption_required": true, "os_version_min": "15.0"}`),
			CreatedBy: "o.martins",
		})
		return err
	})
	token := r.invite(t, "Kemi's laptop")

	enforcer := &RecordingEnforcer{}
	a := r.newAgent(t, macProbe(), enforcer)
	ctx := context.Background()

	// ---- enrol
	if a.Enrolled() {
		t.Fatal("a fresh agent thinks it is enrolled")
	}
	if err := a.Enrol(ctx, token); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if !a.Enrolled() {
		t.Fatal("the agent did not record its identity")
	}

	devices := r.devices(t)
	if len(devices) != 1 || devices[0].ID != a.DeviceID() {
		t.Fatalf("the device did not appear: %+v", devices)
	}

	// ---- report
	// The probe says the OS version and nothing about disk encryption, so
	// the honest answer is that we do not know, never that it passed.
	v, err := a.Report(ctx)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if v.State != policy.Unknown {
		t.Fatalf("a device that said nothing about encryption is %q", v.State)
	}
	if len(v.Findings) != 1 || !v.Findings[0].Unknown {
		t.Fatalf("got %+v", v.Findings)
	}
	if v.Findings[0].From != "Baseline v1" {
		t.Fatalf("the finding does not name its policy: %+v", v.Findings[0])
	}

	// A probe that can read the setting turns the same device green.
	yes := true
	full := macProbe()
	full.Report.DiskEncryption = &yes
	a2 := r.newAgent(t, full, enforcer)
	copyIdentity(t, a, a2)
	v, err = a2.Report(ctx)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if v.State != policy.Compliant {
		t.Fatalf("got %q with %+v", v.State, v.Findings)
	}

	// ---- obey
	var commandID uuid.UUID
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		pipe := r.pipe
		c, err := pipe.Request(ctx, tx, command.RequestInput{
			DeviceID: a.DeviceID(), Type: command.Lock,
			Reason: "reported lost at the airport",
		})
		if err != nil {
			return err
		}
		c, err = pipe.Dispatch(ctx, tx, c.ID)
		commandID = c.ID
		return err
	})

	done, err := a2.Sync(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if done != 1 {
		t.Fatalf("the agent carried out %d instructions, want 1", done)
	}
	if len(enforcer.Done) != 1 || enforcer.Done[0] != "lock" {
		t.Fatalf("the enforcer was asked for %v", enforcer.Done)
	}

	// The server agrees it is done, which is the only state the console
	// reports as done.
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		c, err := command.Load(ctx, tx, commandID)
		if err != nil {
			return err
		}
		if c.State != command.Acknowledged {
			t.Fatalf("the command is %s, want acknowledged", c.State)
		}
		return nil
	})

	// And nothing is left outstanding.
	done, err = a2.Sync(ctx)
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if done != 0 {
		t.Fatalf("the agent carried out %d instructions a second time", done)
	}
}

// copyIdentity hands a second agent the first one's credentials, which is
// how a test swaps the probe without re-enrolling.
func copyIdentity(t *testing.T, from, to *Agent) {
	t.Helper()
	for _, f := range []string{"key.pem", "cert.pem", "ca.pem", "device.json"} {
		b, err := os.ReadFile(from.path(f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		mode := os.FileMode(0o644)
		if f == "key.pem" || f == "device.json" {
			mode = 0o600
		}
		if err := os.WriteFile(to.path(f), b, mode); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	if err := to.loadState(); err != nil {
		t.Fatalf("load state: %v", err)
	}
}

// ---------------------------------------------------------- the key stays

// The headline claim of this package, asserted rather than documented.
func TestThePrivateKeyNeverLeavesTheDevice(t *testing.T) {
	r := newRig(t)
	token := r.invite(t, "Kemi's laptop")
	a := r.newAgent(t, macProbe(), &RecordingEnforcer{})
	ctx := context.Background()

	if err := a.Enrol(ctx, token); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if _, err := a.Report(ctx); err != nil {
		t.Fatalf("report: %v", err)
	}
	if _, err := a.Sync(ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}

	sent := r.bodies.all()
	for _, forbidden := range []string{"PRIVATE KEY", "EC PRIVATE", "BEGIN RSA"} {
		if strings.Contains(sent, forbidden) {
			t.Fatalf("%q appeared in a request body", forbidden)
		}
	}
	// What DID go out is a certificate signing request, which is the public
	// half and a signature over it.
	if !strings.Contains(sent, "CERTIFICATE REQUEST") {
		t.Fatal("no certificate signing request was sent")
	}

	// And on disk it is owner-only: anything wider and any local account on
	// this machine can become this device.
	info, err := os.Stat(a.path("key.pem"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the key is mode %o, want 600", perm)
	}
}

// ---------------------------------------------------------------- refusals

func TestEnrollingTwiceIsRefusedRatherThanDuplicating(t *testing.T) {
	r := newRig(t)
	a := r.newAgent(t, macProbe(), &RecordingEnforcer{})
	ctx := context.Background()

	if err := a.Enrol(ctx, r.invite(t, "a laptop")); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := a.Enrol(ctx, r.invite(t, "a laptop")); err == nil {
		t.Fatal("a second enrolment was allowed")
	}
	if n := len(r.devices(t)); n != 1 {
		t.Fatalf("%d devices exist", n)
	}
}

func TestABadTokenIsReportedInTheServersOwnWords(t *testing.T) {
	r := newRig(t)
	a := r.newAgent(t, macProbe(), &RecordingEnforcer{})

	err := a.Enrol(context.Background(), "not-a-real-token")
	if err == nil {
		t.Fatal("a made-up token enrolled a device")
	}
	if !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("unhelpful error: %v", err)
	}
	// Nothing was written, so a retry with a good token works cleanly.
	if a.Enrolled() {
		t.Fatal("a failed enrolment left the agent half enrolled")
	}
	if _, err := os.Stat(a.path("key.pem")); err == nil {
		t.Fatal("a failed enrolment left a private key on disk")
	}
}

func TestAnUnenrolledAgentDoesNotPretend(t *testing.T) {
	r := newRig(t)
	a := r.newAgent(t, macProbe(), &RecordingEnforcer{})
	ctx := context.Background()

	if _, err := a.Report(ctx); err != ErrNotEnrolled {
		t.Fatalf("report gave %v", err)
	}
	if _, err := a.Sync(ctx); err != ErrNotEnrolled {
		t.Fatalf("sync gave %v", err)
	}
}

// An instruction the agent cannot carry out must stay outstanding. The
// console only reports acknowledged work as done, so acknowledging something
// that did not happen would be a lie told to the person who asked for it.
func TestAnInstructionThatFailsLocallyIsNotAcknowledged(t *testing.T) {
	r := newRig(t)
	token := r.invite(t, "a laptop")

	enforcer := &RecordingEnforcer{Fail: map[string]error{
		"lock": ErrRefused,
	}}
	a := r.newAgent(t, macProbe(), enforcer)
	ctx := context.Background()
	if err := a.Enrol(ctx, token); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	var commandID uuid.UUID
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		pipe := r.pipe
		c, err := pipe.Request(ctx, tx, command.RequestInput{
			DeviceID: a.DeviceID(), Type: command.Lock, Reason: "a drill",
		})
		if err != nil {
			return err
		}
		c, err = pipe.Dispatch(ctx, tx, c.ID)
		commandID = c.ID
		return err
	})

	done, err := a.Sync(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if done != 0 {
		t.Fatalf("the agent acknowledged %d instructions it could not carry out", done)
	}
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		c, err := command.Load(ctx, tx, commandID)
		if err != nil {
			return err
		}
		if c.State == command.Acknowledged {
			t.Fatal("work that failed on the device is recorded as done")
		}
		return nil
	})
}

// The agent that ships with no local enforcement says what is missing rather
// than failing vaguely, and leaves the command outstanding.
func TestTheDefaultEnforcerNamesWhatIsMissing(t *testing.T) {
	err := NotConfigured{}.Do(context.Background(), "wipe_full")
	if err == nil {
		t.Fatal("the stand-in enforcer claimed to have wiped a machine")
	}
	for _, want := range []string{"wipe_full", "vendor certificate", "privileged"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the message does not mention %q: %v", want, err)
		}
	}
}

func TestAHelperIsOnlyEverRunForAKindAnOperatorConfigured(t *testing.T) {
	e := ScriptEnforcer{Scripts: map[string]string{"lock": "/bin/true"}}
	if err := e.Do(context.Background(), "wipe_full"); err == nil {
		t.Fatal("an unconfigured instruction kind ran something")
	}
	if err := e.Do(context.Background(), "lock"); err != nil {
		t.Fatalf("a configured helper did not run: %v", err)
	}
}

// ------------------------------------------------------- what it may reach

// The agent holds a device certificate, so everything the gateway refuses a
// device it refuses this agent. This is the same assertion as the gateway's
// device-role test, made through the real client over real TLS, because a
// privilege boundary that only holds for synthetic requests is not one.
func TestTheAgentsCertificateIsNotAnAdministratorsCredential(t *testing.T) {
	r := newRig(t)
	a := r.newAgent(t, macProbe(), &RecordingEnforcer{})
	ctx := context.Background()
	if err := a.Enrol(ctx, r.invite(t, "a laptop")); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	for _, path := range []string{"/api/devices", "/api/audit", "/api/policies",
		"/api/enrolments", "/api/commands"} {
		raw, status, err := a.call(ctx, "GET", path, nil)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if status != http.StatusForbidden {
			t.Fatalf("the agent reached %s: got %d (%s)", path, status, raw)
		}
	}

	// Its own routes still work.
	_, status, err := a.call(ctx, "GET", "/api/my/commands", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("the agent could not read its own queue: %d %v", status, err)
	}
}

// Re-enrolment after a rebuild: the same hardware serial, a new key, and the
// old certificate stops working.
func TestARebuiltMachineComesBackAsItself(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	first := r.newAgent(t, macProbe(), &RecordingEnforcer{})
	if err := first.Enrol(ctx, r.invite(t, "Kemi's laptop")); err != nil {
		t.Fatalf("first enrol: %v", err)
	}
	original := first.DeviceID()

	// A fresh install: new state directory, new key, same machine.
	second := r.newAgent(t, macProbe(), &RecordingEnforcer{})
	if err := second.Enrol(ctx, r.invite(t, "Kemi's laptop, rebuilt")); err != nil {
		t.Fatalf("second enrol: %v", err)
	}
	if second.DeviceID() != original {
		t.Fatalf("the rebuilt machine came back as a new device: %s then %s",
			original, second.DeviceID())
	}
	if n := len(r.devices(t)); n != 1 {
		t.Fatalf("%d device rows for one machine", n)
	}

	// The credential from before the rebuild is dead.
	if _, err := first.Report(ctx); err == nil {
		t.Fatal("the pre-rebuild certificate still worked")
	}
	if _, err := second.Report(ctx); err != nil {
		t.Fatalf("the rebuilt machine cannot report: %v", err)
	}
}

// A device with no serial number cannot enrol, because a made-up one would
// make every rebuild look like a new machine and quietly double the fleet.
func TestAMachineWithNoSerialWillNotEnrol(t *testing.T) {
	r := newRig(t)
	probe := macProbe()
	probe.SerialNumber = ""
	a := r.newAgent(t, probe, &RecordingEnforcer{})

	err := a.Enrol(context.Background(), r.invite(t, "a laptop"))
	if err == nil {
		t.Fatal("a device with no serial enrolled")
	}
	if !strings.Contains(err.Error(), "serial") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// The probe leaves unsaid what it cannot read, which the server reads as
// state_unknown. This is the property that stops a half-supported platform
// reporting a fleet of green rows.
func TestABareProbeSaysNothingItCannotRead(t *testing.T) {
	rep, err := HostProbe{}.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	for name, got := range map[string]any{
		"passcode set":        rep.PasscodeSet,
		"passcode length":     rep.PasscodeLength,
		"disk encryption":     rep.DiskEncryption,
		"screen lock timeout": rep.ScreenLockTimeout,
		"firewall":            rep.Firewall,
		"jailbroken":          rep.Jailbroken,
	} {
		if !isNil(got) {
			t.Fatalf("the bare probe claimed to know the %s", name)
		}
	}
}

func isNil(v any) bool {
	switch t := v.(type) {
	case *bool:
		return t == nil
	case *int:
		return t == nil
	default:
		return v == nil
	}
}

func TestOverridesFillInWhatTheProbeCannotRead(t *testing.T) {
	yes := true
	p := HostProbe{Overrides: policy.Report{DiskEncryption: &yes, OSVersion: "15.2"}}
	rep, err := p.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if rep.DiskEncryption == nil || !*rep.DiskEncryption {
		t.Fatal("the override was not applied")
	}
	if rep.OSVersion != "15.2" {
		t.Fatalf("os version is %q", rep.OSVersion)
	}
	// What was not overridden stays unsaid.
	if rep.Firewall != nil {
		t.Fatal("an override invented a firewall reading")
	}
}

func TestTheAgentRefusesToStartWithoutWhatItNeeds(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no server": {Dir: t.TempDir(), Probe: macProbe()},
		"no dir":    {ServerURL: "https://x", Probe: macProbe()},
		"no probe":  {ServerURL: "https://x", Dir: t.TempDir()},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("%s: started anyway", name)
		}
	}
}

// F12 from the agent's side: Run keeps a poll open, so a lock requested
// while the agent is idle is carried out in seconds, not at the next cycle.
func TestAListeningAgentCarriesOutALockInSeconds(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	enf := &RecordingEnforcer{}
	a := r.newAgent(t, macProbe(), enf)
	if err := a.Enrol(ctx, r.invite(t, "a listening laptop")); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	// A cycle every hour: anything that lands sooner came through the listener.
	go func() { _ = a.Run(ctx, time.Hour) }()
	time.Sleep(500 * time.Millisecond) // the listener has opened its poll

	var commandID uuid.UUID
	asked := time.Now()
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		c, err := r.pipe.Request(ctx, tx, command.RequestInput{
			DeviceID: a.DeviceID(), Type: command.Lock, Reason: "lost in the car park",
		})
		if err != nil {
			return err
		}
		c, err = r.pipe.Dispatch(ctx, tx, c.ID)
		commandID = c.ID
		return err
	})
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var state string
		r.admin(t, func(ctx context.Context, tx *data.Tx) error {
			return tx.QueryRow(ctx, `SELECT state FROM commands WHERE id = $1`, commandID).Scan(&state)
		})
		if state == "acknowledged" {
			if took := time.Since(asked); took > 3*time.Second {
				t.Fatalf("acknowledged after %s: the listener did not get it promptly", took)
			}
			if n := len(enf.Done); n != 1 || enf.Done[0] != "lock" {
				t.Fatalf("the enforcer ran %v", enf.Done)
			}
			cancel()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the lock was never acknowledged while the agent was listening")
}

// The connection is not the authority; the signature is. An instruction
// whose signature does not fit the tenant's published keys is not carried
// out and not acknowledged, whatever the server said.
func TestAnInstructionWhoseSignatureDoesNotVerifyIsRefused(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	enf := &RecordingEnforcer{}
	a := r.newAgent(t, macProbe(), enf)
	if err := a.Enrol(ctx, r.invite(t, "a careful laptop")); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	var commandID uuid.UUID
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		c, err := r.pipe.Request(ctx, tx, command.RequestInput{DeviceID: a.DeviceID(), Type: command.Lock, Reason: "a test"})
		if err != nil {
			return err
		}
		c, err = r.pipe.Dispatch(ctx, tx, c.ID)
		commandID = c.ID
		return err
	})
	// Forged on the way: a valid-looking signature from nobody's key.
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE commands SET signature = $2 WHERE id = $1`, commandID,
			"AAAA"+strings.Repeat("Qg==", 1))
		return err
	})
	done, err := a.Sync(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if done != 0 || len(enf.Done) != 0 {
		t.Fatalf("a forged instruction was carried out: done=%d ran=%v", done, enf.Done)
	}
	var state string
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM commands WHERE id = $1`, commandID).Scan(&state)
	})
	if state == "acknowledged" {
		t.Fatal("a forged instruction was acknowledged")
	}
}

// ------------------------------------------------------- putting it right

// A policy that asks for remediation gets it: the device reports the
// firewall off, the server marks the finding, the agent's native enforcer
// switches the firewall on with the platform's own tool, and the device
// reports again in the same cycle, green. A policy that does not ask gets
// a report and nothing else.
func TestAPolicyThatAsksGetsTheDeviceToPutItselfRight(t *testing.T) {
	r := newRig(t)
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		_, err := policy.Save(ctx, tx, policy.SaveInput{
			Name:      "Laptops",
			Body:      []byte(`{"firewall_required": true, "os_version_min": "15.0", "remediate": true}`),
			CreatedBy: "o.martins",
		})
		return err
	})
	token := r.invite(t, "Kemi's laptop")

	// A Mac, as its own tools describe it, with the firewall off. The
	// runner is the fake from native_test.go with one live edge: when
	// socketfilterfw is told to switch on, the next read says on.
	mac := aMac()
	mac.out["/usr/sbin/ioreg -l"] = `    | |   "IOPlatformSerialNumber" = "C02XK4YTQ6NV"` + "\n"
	mac.out["/usr/bin/sw_vers -productVersion"] = "15.2\n"
	mac.out[socketfilterfw+" --getglobalstate"] = "Firewall is disabled. (State = 0)\n"
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := mac.run(ctx, name, args...)
		if name == socketfilterfw && len(args) == 2 && args[0] == "--setglobalstate" && args[1] == "on" {
			mac.out[socketfilterfw+" --getglobalstate"] = "Firewall is enabled. (State = 1)\n"
			return "Firewall is enabled. (State = 1)\n", nil
		}
		return out, err
	}
	probe := HostProbe{OS: "darwin", Run: run}
	a := r.newAgent(t, probe, Native{OS: "darwin", Run: run, Dir: t.TempDir()})
	ctx := context.Background()
	if err := a.Enrol(ctx, token); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	if err := a.RunOnce(ctx); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if !mac.called(socketfilterfw + " --setglobalstate on") {
		t.Fatalf("the firewall was not switched on: %v", mac.calls)
	}
	devices := r.devices(t)
	if len(devices) != 1 || devices[0].State != policy.Compliant {
		t.Fatalf("after the cycle the device is %+v, want compliant in the same cycle", devices)
	}

	// Now the policy stops asking. The firewall goes off again (a person
	// switched it off); the device reports red and is left alone.
	r.admin(t, func(ctx context.Context, tx *data.Tx) error {
		_, err := policy.Save(ctx, tx, policy.SaveInput{
			Name:      "Laptops",
			Body:      []byte(`{"firewall_required": true, "os_version_min": "15.0"}`),
			CreatedBy: "o.martins",
		})
		return err
	})
	mac.out[socketfilterfw+" --getglobalstate"] = "Firewall is disabled. (State = 0)\n"
	mac.calls = nil
	if err := a.RunOnce(ctx); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if mac.called(socketfilterfw + " --setglobalstate") {
		t.Fatalf("a policy that did not ask had the device's settings changed: %v", mac.calls)
	}
	devices = r.devices(t)
	if len(devices) != 1 || devices[0].State != policy.NotCompliant {
		t.Fatalf("device is %+v, want not_compliant and untouched", devices)
	}
	// The verdict the device was handed says so too: the finding is
	// there, unmarked.
	v, err := a.Report(ctx)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	for _, f := range v.Findings {
		if f.Fix {
			t.Fatalf("a finding was marked for the device to act on without the policy asking: %+v", f)
		}
	}
}
