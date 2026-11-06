package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/android"
	"platform/internal/authz"
	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/enrol"
	"platform/internal/notify"
	"platform/internal/notify/smtptest"
	"platform/internal/secrets"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

// Requirement T13, now at the HTTP layer. The SQL suite proves PostgreSQL
// enforces isolation and the data-layer tests prove the Go code cannot be
// talked out of it. These prove the same thing through the front door, which
// is where an attacker actually stands.

var (
	tenantA = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	hostA   = "mdm.kalesi.example"
	hostB   = "devices.arbor.example"
	testKey = []byte("isolation-suite-signing-key-32-bytes!!")
	sealKey = []byte("gateway-suite-sealing-key-32-byt")
)

type staticIDP map[string]Identity

func (s staticIDP) Verify(_ context.Context, bearer string) (Identity, error) {
	id, ok := s[bearer]
	if !ok {
		return Identity{}, ErrNoIdentity
	}
	return id, nil
}

var idp = staticIDP{
	"a-super":    {Subject: "f.okonkwo", TenantID: tenantA, Role: authz.SuperAdmin},
	"a-itadmin":  {Subject: "o.martins", TenantID: tenantA, Role: authz.ITAdmin},
	"a-helpdesk": {Subject: "p.eneh", TenantID: tenantA, Role: authz.Helpdesk},
	"a-auditor":  {Subject: "r.chukwu", TenantID: tenantA, Role: authz.Auditor},
	"a-employee": {Subject: "t.eze", TenantID: tenantA, Role: authz.Employee},
	"a-secmgr":   {Subject: "d.adeyinka", TenantID: tenantA, Role: authz.SecurityManager},
	"b-itadmin":  {Subject: "j.okafor", TenantID: tenantB, Role: authz.ITAdmin},
}

type fixture struct {
	h        http.Handler
	g        *Gateway
	pipe     *command.Pipeline
	sessions *session.Signer
	enrol    *enrol.Service
	sealer   secrets.Sealer
	notify   *notify.Service
	webhook  *notify.Webhook
	mail     *smtptest.Server
	dns      *fakeDNS
	notifier *notify.Worker
	devices  map[uuid.UUID][]uuid.UUID // tenant -> device ids
	// emailChannel is the same channel the notifier holds, kept so the
	// sign-up tests can send through the fixture's SMTP server.
	emailChannel notify.Email
	// google is the fake Android Management API the gateway talks to.
	google *android.FakeGoogle
}

// cookie mints a real signed session for one of the identities above.
//
// The tests used to put a bare bearer name in the cookie, which worked while
// a cookie and a header were verified the same way. They are not any more: a
// cookie must be a session this gateway minted, because a browser credential
// that falls back to some other verifier is a second trust path through the
// front door. So the tests now hold the same thing a browser holds.
func (f fixture) cookie(t *testing.T, name string) string {
	t.Helper()
	id, ok := idp[name]
	if !ok {
		t.Fatalf("no test identity named %q", name)
	}
	tok, _, err := f.sessions.Start(session.Session{
		TenantID: id.TenantID, Subject: id.Subject, Role: string(id.Role),
	})
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	return tok
}

// okPush stands in for a working provider so the tests can reach the states
// beyond "queued" that the real Apple adapter will unlock.
type okPush struct{}

func (okPush) Name() string                                   { return "test" }
func (okPush) Push(context.Context, command.PushTarget) error { return nil }

func seed(t *testing.T) map[uuid.UUID][]uuid.UUID {
	t.Helper()
	ctx := context.Background()
	adminDSN := os.Getenv("MDM_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("MDM_TEST_ADMIN_DSN not set")
	}
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	for _, s := range []string{
		`DELETE FROM offboarding_log`,
		`DELETE FROM tenant_keys`,
		`DELETE FROM tenant_admins`,
		`DELETE FROM command_signing_keys`,
		`DELETE FROM api_rate`,
		`DELETE FROM siem_cursors`,
		`DELETE FROM usage_snapshots`,
		`DELETE FROM signups`,
		`DELETE FROM integration_tokens`,
		`DELETE FROM android_enrollment_tokens`,
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
		`DELETE FROM command_approvals`,
		`DELETE FROM commands`,
		`DELETE FROM audit_events`,
		`DELETE FROM devices`,
		`DELETE FROM people`,
		`DELETE FROM compliance_snapshots`,
		`DELETE FROM policies`,
		`DELETE FROM tenant_branding`,
		`DELETE FROM tenant_domains`,
		`DELETE FROM tenant_role_map`,
		`DELETE FROM tenant_identity`,
		`DELETE FROM tenants WHERE id IN ('11111111-1111-1111-1111-111111111111',
		                                   '22222222-2222-2222-2222-222222222222')`,
		`DELETE FROM partners`,
		`INSERT INTO tenants (id, name, slug, plan, status, api_rate_per_min, device_cap, admin_seats) VALUES
		   ('11111111-1111-1111-1111-111111111111','Kalesi Foods','kalesi','growth','active',600,500,10),
		   ('22222222-2222-2222-2222-222222222222','Arbor Health','arbor','scale','active',2400,2000,50)`,
		`INSERT INTO tenant_domains (host, tenant_id, verified_at) VALUES
		   ('mdm.kalesi.example','11111111-1111-1111-1111-111111111111', now()),
		   ('devices.arbor.example','22222222-2222-2222-2222-222222222222', now())`,
		`INSERT INTO tenant_branding (tenant_id, product_name, legal_footer, brand_colour, mark_letter) VALUES
		   ('11111111-1111-1111-1111-111111111111','Kalesi Device Care','Kalesi Foods Ltd · RC 1184420 · Lagos','#0F6E66','K')`,
		`INSERT INTO devices (tenant_id, name, serial, os_family) VALUES
		   ('11111111-1111-1111-1111-111111111111','HQ-MBP-001','C02XK4YTQ6NV','macos'),
		   ('11111111-1111-1111-1111-111111111111','HQ-WIN-004','SN-00000004','windows'),
		   ('22222222-2222-2222-2222-222222222222','HQ-MBP-001','C02XK4YTQ6NV','macos'),
		   ('22222222-2222-2222-2222-222222222222','HQ-WIN-004','SN-00000004','windows'),
		   ('22222222-2222-2222-2222-222222222222','HQ-IPH-009','SN-00000009','ios')`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %.40s: %v", s, err)
		}
	}

	out := map[uuid.UUID][]uuid.UUID{}
	rows, err := conn.Query(ctx, `SELECT tenant_id, id FROM devices ORDER BY tenant_id, name`)
	if err != nil {
		t.Fatalf("read ids: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tid, did uuid.UUID
		if err := rows.Scan(&tid, &did); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[tid] = append(out[tid], did)
	}
	return out
}

func newFixture(t *testing.T) fixture { return newFixtureWith(t, okPush{}) }

func newFixtureWith(t *testing.T, push command.PushProvider) fixture {
	t.Helper()
	ctx := context.Background()
	devices := seed(t)

	appDSN := os.Getenv("MDM_TEST_DSN")
	opDSN := os.Getenv("MDM_TEST_OPERATOR_DSN")
	if appDSN == "" || opDSN == "" {
		t.Skip("MDM_TEST_DSN or MDM_TEST_OPERATOR_DSN not set")
	}

	signer, err := tenantclaim.NewSigner(testKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store, err := data.Open(ctx, appDSN, signer, 4)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(store.Close)

	dir, err := directory.Open(ctx, opDSN)
	if err != nil {
		t.Fatalf("directory: %v", err)
	}
	t.Cleanup(dir.Close)

	sessions, err := session.NewSigner(testKey)
	if err != nil {
		t.Fatalf("session signer: %v", err)
	}

	master, err := secrets.NewAESSealer(sealKey)
	sealer := secrets.NewKeyring(master)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	enrolment := enrol.New(sealer)

	// A webhook channel that may reach 127.0.0.1, because the test's own
	// endpoint is there. Production leaves this off and the dial-time
	// check refuses anything inside the platform's network.
	webhook := notify.NewWebhook(slog.New(slog.NewTextHandler(io.Discard, nil)))
	webhook.AllowPrivateAddresses = true
	// A real SMTP server, so the email channel can be exercised through
	// the whole stack rather than stubbed at the edge.
	mailServer, err := smtptest.New()
	if err != nil {
		t.Fatalf("smtptest: %v", err)
	}
	t.Cleanup(mailServer.Close)
	email := notify.Email{
		Server: mailServer.Addr(), From: "notifications@kalesi.example",
		Security: "starttls", RootCAs: mailServer.RootCAs(), Helo: "test",
	}
	syslogCh := notify.NewSyslog()
	syslogCh.AllowPrivateAddresses = true
	jira := notify.NewTicketing("jira", slog.New(slog.NewTextHandler(io.Discard, nil)))
	jira.AllowPrivateAddresses = true
	snow := notify.NewTicketing("servicenow", slog.New(slog.NewTextHandler(io.Discard, nil)))
	snow.AllowPrivateAddresses = true
	notifier := notify.New(sealer, webhook, email, syslogCh, jira, snow,
		notify.NewLog(slog.New(slog.NewTextHandler(io.Discard, nil))))
	// A resolver the test answers, so a sending domain can be proven
	// without touching the internet. Production leaves it nil and uses the
	// host's own resolver.
	dns := &fakeDNS{records: map[string][]string{}}
	notifier.LookupTXT = dns.lookup

	// Google, faked: the same seven calls over HTTP, recording what it
	// was asked so a test can read the request shapes back.
	google := android.NewFakeGoogle()
	t.Cleanup(google.Close)
	androidAPI := google.Client()

	pipe := command.New(&command.StoredKeys{Sealer: sealer, Bits: 1024}, command.ByOS{
		Routes:   map[string]command.PushProvider{"android": android.Push{Provider: androidAPI}},
		Fallback: push,
	}, command.DefaultLimiter())
	g := New(Config{
		Directory: dir, Store: store, Signer: signer, Identity: idp,
		Pipeline: pipe, CSRFKey: testKey, Sessions: sessions,
		Sealer: sealer, Enrol: enrolment, Notify: notifier, Android: androidAPI, Mail: email,
		// The test server speaks plain HTTP, so a Secure cookie would never
		// come back. Production leaves this false and main.go warns loudly
		// when it is on.
		InsecureCookies: true,
		// The export-to-bucket test's bucket is an httptest server on
		// loopback, which the dial guard refuses in a deployment.
		AllowPrivateBuckets: true,
	})
	worker := notify.NewWorker(notifier, store, signer,
		func(ctx context.Context) ([]uuid.UUID, error) { return dir.ActiveTenantIDs(ctx) },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	return fixture{h: g.Handler(), g: g, pipe: pipe, sessions: sessions,
		enrol: enrolment, sealer: sealer, notify: notifier, webhook: webhook,
		mail: mailServer, dns: dns, notifier: worker, devices: devices, emailChannel: email,
		google: google}
}

// form builds a POST carrying body values. Bearer callers need no form token:
// cross-site protection is only for credentials a browser attaches by itself.
func form(t *testing.T, host, path, bearer string, vals url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "http://"+host+path, strings.NewReader(vals.Encode()))
	r.Host = host
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func req(t *testing.T, method, host, path, bearer string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.Host = host
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

// deviceCert builds a certificate of the right SHAPE: tenant in the
// organisational unit, device in the common name, both arriving from the TLS
// handshake where no header can set them.
//
// It is NOT trusted. Until the enrolment sprint it would have been, which was
// the gap: shape is not provenance. Anyone can make one of these. The gateway
// now matches the exact bytes against what it issued, so a test that wants a
// working device certificate uses trustedCert below, and the fact that this
// one is refused is itself a test.
func deviceCert(t *testing.T, tenant, device uuid.UUID) *tls.ConnectionState {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         device.String(),
			OrganizationalUnit: []string{tenant.String()},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

// trustedCert makes one AND records it as issued, which is what enrolment
// does for real. A test that wants to exercise the device path rather than
// the trust check uses this.
func trustedCert(t *testing.T, tenant, device uuid.UUID) *tls.ConnectionState {
	t.Helper()
	state := deviceCert(t, tenant, device)
	registerCert(t, tenant, device, state.PeerCertificates[0].Raw, nil)
	return state
}

// certUntil registers a certificate with a chosen expiry, so a test can put
// a device anywhere in its certificate's life: freshly issued, inside the
// renewal window, or past the end.
//
// The expiry that matters is the one in the device_certificates row rather
// than the one inside the X.509 structure, because the gateway matches a
// presented certificate by fingerprint against what it recorded. That is
// the same reason revocation works at all.
func certUntil(t *testing.T, tenant, device uuid.UUID, notAfter time.Time) *tls.ConnectionState {
	t.Helper()
	state := deviceCert(t, tenant, device)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if _, err := conn.Exec(ctx, `
		INSERT INTO device_certificates
		  (tenant_id, device_id, serial, fingerprint, not_before, not_after)
		VALUES ($1, $2, $3, $4, now() - interval '300 days', $5)`,
		tenant, device, hex.EncodeToString(sum[:8]), sum[:], notAfter); err != nil {
		t.Fatalf("register certificate: %v", err)
	}
	return state
}

// registerCert writes the device_certificates row. revokedReason non-nil
// records it as revoked, for the tests that check revocation bites.
func registerCert(t *testing.T, tenant, device uuid.UUID, der []byte, revokedReason *string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	sum := sha256.Sum256(der)
	var revokedAt any
	if revokedReason != nil {
		revokedAt = time.Now().UTC()
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO device_certificates
		  (tenant_id, device_id, serial, fingerprint, not_before, not_after,
		   revoked_at, revoked_reason)
		VALUES ($1, $2, $3, $4, now() - interval '1 hour', now() + interval '1 hour',
		        $5, $6)`,
		tenant, device, hex.EncodeToString(sum[:8]), sum[:], revokedAt, revokedReason); err != nil {
		t.Fatalf("register certificate: %v", err)
	}
}

func do(t *testing.T, f fixture, r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	var body map[string]any
	b, _ := io.ReadAll(rec.Body)
	_ = json.Unmarshal(b, &body)
	return rec, body
}

// ---------------------------------------------------------------- isolation

func TestEachTenantSeesOnlyItsOwnDevices(t *testing.T) {
	f := newFixture(t)

	rec, body := do(t, f, req(t, "GET", hostA, "/api/devices", "a-itadmin"))
	if rec.Code != 200 {
		t.Fatalf("tenant A: got %d", rec.Code)
	}
	if n := len(body["devices"].([]any)); n != 2 {
		t.Fatalf("tenant A saw %d devices, want 2", n)
	}

	rec, body = do(t, f, req(t, "GET", hostB, "/api/devices", "b-itadmin"))
	if rec.Code != 200 {
		t.Fatalf("tenant B: got %d", rec.Code)
	}
	if n := len(body["devices"].([]any)); n != 3 {
		t.Fatalf("tenant B saw %d devices, want 3", n)
	}
}

// The attack this gateway exists to refuse: a perfectly valid session for one
// tenant, pointed at another tenant's hostname.
func TestValidSessionAgainstAnotherTenantsHostIsRefused(t *testing.T) {
	f := newFixture(t)

	rec, body := do(t, f, req(t, "GET", hostB, "/api/devices", "a-super"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	if body["error"] == "" {
		t.Fatal("no reason given")
	}
	// A Super Admin of A must not be a Super Admin of B by changing the URL.
}

// Not forbidden. Not found. A forbidden answer would confirm the device
// exists, which is itself a cross-tenant leak.
func TestAnotherTenantsDeviceIsNotFoundRatherThanForbidden(t *testing.T) {
	f := newFixture(t)
	bDevice := f.devices[tenantB][0]

	rec, _ := do(t, f, req(t, "GET", hostA, "/api/devices/"+bDevice.String(), "a-super"))
	if rec.Code == http.StatusForbidden {
		t.Fatal("answered 403, which confirms the device exists in another tenant")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}

	// The same identifier, from its own tenant, is found. Without this the
	// test above would pass on a handler that 404s everything.
	rec, _ = do(t, f, req(t, "GET", hostB, "/api/devices/"+bDevice.String(), "b-itadmin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant B cannot read its own device: got %d", rec.Code)
	}
}

func TestLockOnAnotherTenantsDeviceIsNotFound(t *testing.T) {
	f := newFixture(t)
	bDevice := f.devices[tenantB][0]

	rec, _ := do(t, f, form(t, hostA, "/api/devices/"+bDevice.String()+"/lock", "a-super",
		url.Values{"reason": {"reported stolen"}}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

// ---------------------------------------------------------------- identity

// A device certificate resolves its own tenant, which is what lets the data
// layer scope everything behind it.
//
// This used to assert that the device could then list the tenant's devices.
// It cannot any more, and should never have been able to: see
// device_role_test.go. What it proves now is that the certificate resolves
// and the device reaches its own work, which is the whole of what resolving
// is for.
func TestDeviceCertificateResolvesItsOwnTenant(t *testing.T) {
	f := newFixture(t)
	aDevice := f.devices[tenantA][0]
	cert := trustedCert(t, tenantA, aDevice)

	r := req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = cert
	if rec, body := do(t, f, r); rec.Code != 200 {
		t.Fatalf("got %d, want 200: %v", rec.Code, body)
	}

	// Writing lands in its own tenant: the report is stored under Kalesi,
	// so Kalesi can read it back and Arbor cannot.
	r = jsonReq(t, "POST", hostA, "/api/devices/"+aDevice.String()+"/report", "",
		map[string]any{"passcode_set": true})
	r.TLS = cert
	if rec, body := do(t, f, r); rec.Code != 200 {
		t.Fatalf("report: %d %v", rec.Code, body)
	}
	_, body := do(t, f, req(t, "GET", hostA,
		"/api/devices/"+aDevice.String()+"/compliance", "a-itadmin"))
	if body["state"] == nil || body["state"] == "awaiting_first_boot" {
		t.Fatalf("the report did not land in the device's own tenant: %v", body)
	}
}

func TestDeviceCertificateAgainstAnotherTenantsHostIsRefused(t *testing.T) {
	f := newFixture(t)
	aDevice := f.devices[tenantA][0]

	r := req(t, "GET", hostB, "/api/devices", "")
	r.TLS = trustedCert(t, tenantA, aDevice)
	rec, _ := do(t, f, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

func TestUnknownHostAndMissingCredentials(t *testing.T) {
	f := newFixture(t)

	rec, _ := do(t, f, req(t, "GET", "mdm.someoneelse.example", "/api/devices", "a-super"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: got %d, want 404", rec.Code)
	}

	rec, _ = do(t, f, req(t, "GET", hostA, "/api/devices", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: got %d, want 401", rec.Code)
	}

	rec, _ = do(t, f, req(t, "GET", hostA, "/api/devices", "not-a-session"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad session: got %d, want 401", rec.Code)
	}
}

// ---------------------------------------------------------------- roles

func TestRoleMatrixIsEnforcedAtTheEdge(t *testing.T) {
	f := newFixture(t)
	aDevice := f.devices[tenantA][0]

	cases := []struct {
		name, bearer, method, path string
		want                       int
	}{
		{"helpdesk may see devices", "a-helpdesk", "GET", "/api/devices", 200},
		{"helpdesk may not see the audit log", "a-helpdesk", "GET", "/api/audit", 403},
		{"helpdesk may not lock", "a-helpdesk", "POST", "/api/devices/" + aDevice.String() + "/lock", 403},
		{"auditor may see the audit log", "a-auditor", "GET", "/api/audit", 200},
		{"auditor may not lock", "a-auditor", "POST", "/api/devices/" + aDevice.String() + "/lock", 403},
		{"employee may not list every device", "a-employee", "GET", "/api/devices", 403},
		{"it admin may lock", "a-itadmin", "POST", "/api/devices/" + aDevice.String() + "/lock", 202},
		{"it admin may not approve", "a-itadmin", "POST", "/api/commands/" + aDevice.String() + "/approve", 403},
		{"security manager may not lock", "a-secmgr", "POST", "/api/devices/" + aDevice.String() + "/lock", 403},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r *http.Request
			if c.method == "POST" {
				r = form(t, hostA, c.path, c.bearer, url.Values{"reason": {"stolen"}})
			} else {
				r = req(t, c.method, hostA, c.path, c.bearer)
			}
			rec, _ := do(t, f, r)
			if rec.Code != c.want {
				t.Fatalf("got %d, want %d", rec.Code, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------- plan limits

func TestSuspendedTenantIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx,
		`UPDATE tenants SET status='suspended' WHERE id=$1`, tenantA); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	rec, _ := do(t, f, req(t, "GET", hostA, "/api/devices", "a-super"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 for a suspended tenant", rec.Code)
	}
}

func TestRateLimitComesFromThePlan(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx,
		`UPDATE tenants SET api_rate_per_min=2 WHERE id=$1`, tenantA); err != nil {
		t.Fatalf("set rate: %v", err)
	}

	for i := 1; i <= 2; i++ {
		rec, _ := do(t, f, req(t, "GET", hostA, "/api/devices", "a-super"))
		if rec.Code != 200 {
			t.Fatalf("request %d: got %d, want 200", i, rec.Code)
		}
	}
	rec, _ := do(t, f, req(t, "GET", hostA, "/api/devices", "a-super"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: got %d, want 429", rec.Code)
	}

	// Tenant B is on its own bucket and is unaffected.
	rec, _ = do(t, f, req(t, "GET", hostB, "/api/devices", "b-itadmin"))
	if rec.Code != 200 {
		t.Fatalf("tenant B affected by tenant A's limit: got %d", rec.Code)
	}
}

// fakeDNS answers the TXT lookups a sending domain is proven by. Publishing
// a record is a test calling publish; a tenant who has not published yet is
// simply a name that is not in the map.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]string
}

func (d *fakeDNS) lookup(_ context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	got, ok := d.records[strings.TrimSuffix(name, ".")]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return got, nil
}

func (d *fakeDNS) publish(name string, values ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = values
}
