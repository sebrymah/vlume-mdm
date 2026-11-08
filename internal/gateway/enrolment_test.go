package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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

	"platform/internal/data"
	"platform/internal/tenantclaim"
)

// ------------------------------------------------------------- the helpers

// newCSR is what a device agent produces on first boot: a key it keeps and a
// request to have the public half certified.
func newCSR(t *testing.T, askedName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: askedName}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func jsonReq(t *testing.T, method, host, path, bearer string, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(string(b)))
	r.Host = host
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

// makeEnrolment creates one through the real API and returns the token, which
// is the only moment it is ever visible.
func makeEnrolment(t *testing.T, f fixture, host, bearer, label string) (uuid.UUID, string) {
	t.Helper()
	rec, body := do(t, f, jsonReq(t, "POST", host, "/api/enrolments", bearer, map[string]any{
		"label": label, "ownership": "company", "os_family": "macos",
	}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create enrolment: got %d, %v", rec.Code, body)
	}
	token, _ := body["token"].(string)
	if token == "" {
		t.Fatal("no token came back")
	}
	e, _ := body["enrolment"].(map[string]any)
	id, err := uuid.Parse(e["id"].(string))
	if err != nil {
		t.Fatalf("enrolment id: %v", err)
	}
	return id, token
}

type enrolResult struct {
	code        int
	deviceID    uuid.UUID
	certificate []byte
	authority   []byte
	reenrolled  bool
	body        map[string]any
}

func redeem(t *testing.T, f fixture, host, token, serial, name string) enrolResult {
	t.Helper()
	rec, body := do(t, f, jsonReq(t, "POST", host, "/api/enrol", "", map[string]any{
		"token": token, "csr": string(newCSR(t, "device-asked-for-this")),
		"serial": serial, "name": name,
	}))
	out := enrolResult{code: rec.Code, body: body}
	if rec.Code == http.StatusCreated {
		out.deviceID = uuid.MustParse(body["device_id"].(string))
		out.certificate = []byte(body["certificate"].(string))
		out.authority = []byte(body["authority"].(string))
		out.reenrolled, _ = body["reenrolled"].(bool)
	}
	return out
}

// asTLS turns the PEM a device was just given into what it would present on
// its next request.
func asTLS(t *testing.T, certPEM []byte) *tls.ConnectionState {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("the certificate that came back is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

// ------------------------------------------- the gap this sprint closes

// Since the gateway was written, a client certificate of the right SHAPE was
// trusted as the device it named. Nothing issued those certificates and
// nothing checked that we had. This is that gap, stated as a test: anyone can
// make a certificate saying whatever they like, and it must not work.
func TestACertificateWeDidNotIssueIsRefused(t *testing.T) {
	f := newFixture(t)
	aDevice := f.devices[tenantA][0]

	r := req(t, "GET", hostA, "/api/devices", "")
	r.TLS = deviceCert(t, tenantA, aDevice) // right shape, never issued
	rec, _ := do(t, f, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a self-made device certificate was accepted: got %d", rec.Code)
	}
}

func TestARevokedCertificateIsRefused(t *testing.T) {
	f := newFixture(t)
	aDevice := f.devices[tenantA][0]

	state := deviceCert(t, tenantA, aDevice)
	reason := "the laptop was reported stolen"
	registerCert(t, tenantA, aDevice, state.PeerCertificates[0].Raw, &reason)

	r := req(t, "GET", hostA, "/api/devices", "")
	r.TLS = state
	rec, _ := do(t, f, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a revoked certificate still worked: got %d", rec.Code)
	}
}

// A certificate issued to one tenant, presented on its own hostname, but
// recorded under another tenant. Row-level security makes it invisible, so
// the answer is the same as for one that was never issued.
func TestACertificateIssuedToAnotherTenantIsRefused(t *testing.T) {
	f := newFixture(t)
	bDevice := f.devices[tenantB][0]

	state := deviceCert(t, tenantA, bDevice)
	registerCert(t, tenantB, bDevice, state.PeerCertificates[0].Raw, nil)

	r := req(t, "GET", hostA, "/api/devices", "")
	r.TLS = state
	rec, _ := do(t, f, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a certificate recorded under another tenant worked: got %d", rec.Code)
	}
}

// --------------------------------------------------------- the whole path

func TestADeviceEnrolsAndThenUsesItsCertificate(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "Kemi's laptop")

	got := redeem(t, f, hostA, token, "C02-NEW-00001", "Kemi's MacBook")
	if got.code != http.StatusCreated {
		t.Fatalf("enrolment failed: %d %v", got.code, got.body)
	}

	// The certificate verifies against the authority the same response
	// handed over, which is what the device needs to trust its own chain.
	block, _ := pem.Decode(got.authority)
	if block == nil {
		t.Fatal("no authority came back")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	leaf := asTLS(t, got.certificate).PeerCertificates[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("the issued certificate does not verify against its authority: %v", err)
	}

	// The subject is what the gateway reads, written by us rather than by
	// the device that asked.
	if leaf.Subject.CommonName != got.deviceID.String() {
		t.Fatalf("certificate names %q, device is %s", leaf.Subject.CommonName, got.deviceID)
	}

	// And now the real point: the device can use it. The probe is the
	// device's own queue rather than the fleet listing, because since the
	// agent sprint a device certificate may not enumerate the fleet.
	r := req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = asTLS(t, got.certificate)
	rec, body := do(t, f, r)
	if rec.Code != 200 {
		t.Fatalf("the newly enrolled device could not call in: %d %v", rec.Code, body)
	}
	if _, ok := body["commands"]; !ok {
		t.Fatalf("no queue came back: %v", body)
	}
	// It can report on itself, which is the other half of its whole job.
	r = jsonReq(t, "POST", hostA, "/api/devices/"+got.deviceID.String()+"/report", "",
		map[string]any{"passcode_set": true})
	r.TLS = asTLS(t, got.certificate)
	if rec, body := do(t, f, r); rec.Code != 200 {
		t.Fatalf("the newly enrolled device could not report: %d %v", rec.Code, body)
	}
}

func TestTheDeviceAppearsWithTheOwnershipTheInvitationSet(t *testing.T) {
	f := newFixture(t)
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", "a-itadmin",
		map[string]any{"label": "Ade's own phone", "ownership": "personal", "os_family": "ios"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %v", rec.Code, body)
	}
	token := body["token"].(string)

	got := redeem(t, f, hostA, token, "SN-PERSONAL-1", "")
	if got.code != http.StatusCreated {
		t.Fatalf("redeem: %d %v", got.code, got.body)
	}

	rec, body = do(t, f, req(t, "GET", hostA,
		"/api/devices/"+got.deviceID.String(), "a-itadmin"))
	if rec.Code != 200 {
		t.Fatalf("read back: %d", rec.Code)
	}
	if body["ownership"] != "personal" {
		t.Fatalf("ownership is %v, want personal", body["ownership"])
	}
	if body["os_family"] != "ios" {
		t.Fatalf("os family is %v, want ios", body["os_family"])
	}
	// The label stands in for a name until the device reports its own.
	if body["name"] != "Ade's own phone" {
		t.Fatalf("name is %v", body["name"])
	}
}

// ------------------------------------------------------------ the refusals

func TestATokenWorksOnceAndOnlyOnce(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "a laptop")

	if got := redeem(t, f, hostA, token, "SN-ONCE-1", ""); got.code != http.StatusCreated {
		t.Fatalf("first redemption failed: %d %v", got.code, got.body)
	}
	if got := redeem(t, f, hostA, token, "SN-ONCE-2", ""); got.code != http.StatusForbidden {
		t.Fatalf("a spent token worked again: got %d", got.code)
	}
}

// Two devices arriving with the same token at the same moment. Exactly one
// may win, or a tenant acquires a machine it did not invite.
func TestTwoDevicesRacingForOneTokenGiveOneDevice(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "contested laptop")

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []int
	)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			got := redeem(t, f, hostA, token, "SN-RACE-"+string(rune('A'+n)), "")
			mu.Lock()
			results = append(results, got.code)
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	for _, c := range results {
		if c == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d of 2 racing redemptions succeeded, want exactly 1: %v", created, results)
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	id, token := makeEnrolment(t, f, hostA, "a-itadmin", "a slow laptop")

	// Reach in and age it, rather than waiting a week. Both ends move: the
	// schema refuses an enrolment that expires before it was made, which it
	// caught the first time this test was written.
	exec(t, `UPDATE enrolments
	            SET created_at = now() - interval '2 hours',
	                expires_at = now() - interval '1 hour'
	          WHERE id = $1`, id)

	if got := redeem(t, f, hostA, token, "SN-LATE-1", ""); got.code != http.StatusForbidden {
		t.Fatalf("an expired token worked: got %d", got.code)
	}
}

func TestAWithdrawnEnrolmentIsRefused(t *testing.T) {
	f := newFixture(t)
	id, token := makeEnrolment(t, f, hostA, "a-itadmin", "a cancelled laptop")

	rec, _ := do(t, f, jsonReq(t, "POST", hostA,
		"/api/enrolments/"+id.String()+"/revoke", "a-itadmin",
		map[string]any{"reason": "the order was cancelled"}))
	if rec.Code != 200 {
		t.Fatalf("revoke: got %d", rec.Code)
	}
	if got := redeem(t, f, hostA, token, "SN-GONE-1", ""); got.code != http.StatusForbidden {
		t.Fatalf("a withdrawn token worked: got %d", got.code)
	}
	// And it cannot be withdrawn into existence again.
	rec, _ = do(t, f, jsonReq(t, "POST", hostA,
		"/api/enrolments/"+id.String()+"/revoke", "a-itadmin",
		map[string]any{"reason": "again"}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("revoking twice got %d, want 409", rec.Code)
	}
}

// A token is a credential, not a routing instruction. Presented to another
// tenant's hostname it is looked up inside that tenant's row-level security,
// where it does not exist.
func TestATokenFromOneTenantIsUselessOnAnothersHostname(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "a Kalesi laptop")

	if got := redeem(t, f, hostB, token, "SN-CROSS-1", ""); got.code != http.StatusForbidden {
		t.Fatalf("a Kalesi token enrolled a device at Arbor: got %d %v", got.code, got.body)
	}
	// And it still works where it belongs, so the refusal above was the
	// tenant boundary rather than the token having been spent.
	if got := redeem(t, f, hostA, token, "SN-CROSS-2", ""); got.code != http.StatusCreated {
		t.Fatalf("the token no longer works at home: %d %v", got.code, got.body)
	}
}

func TestARequestWithNoCertificateRequestIsRefused(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "a laptop")

	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/enrol", "", map[string]any{
		"token": token, "serial": "SN-NOCSR-1",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestADeviceThatReportsNoSerialIsRefused(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "a laptop")

	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/enrol", "", map[string]any{
		"token": token, "csr": string(newCSR(t, "x")), "serial": "  ",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

// ------------------------------------------------------- re-enrolment

// A machine wiped and rebuilt comes back on the same hardware serial. It
// keeps its row and its history, and every certificate it used to hold stops
// working, because two live certificates for one machine means a stolen
// laptop's credential survives the replacement being enrolled.
func TestReEnrolmentKeepsTheDeviceAndRetiresTheOldCertificate(t *testing.T) {
	f := newFixture(t)

	_, first := makeEnrolment(t, f, hostA, "a-itadmin", "Kemi's laptop")
	one := redeem(t, f, hostA, first, "C02-SAME-0001", "Kemi's MacBook")
	if one.code != http.StatusCreated {
		t.Fatalf("first enrolment: %d %v", one.code, one.body)
	}
	if one.reenrolled {
		t.Fatal("a first enrolment reported itself as a re-enrolment")
	}

	_, second := makeEnrolment(t, f, hostA, "a-itadmin", "Kemi's laptop, rebuilt")
	two := redeem(t, f, hostA, second, "C02-SAME-0001", "Kemi's MacBook")
	if two.code != http.StatusCreated {
		t.Fatalf("second enrolment: %d %v", two.code, two.body)
	}
	if !two.reenrolled {
		t.Fatal("the same serial did not register as a re-enrolment")
	}
	if two.deviceID != one.deviceID {
		t.Fatalf("the rebuilt machine got a new device row: %s then %s",
			one.deviceID, two.deviceID)
	}

	// The old credential is dead.
	r := req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = asTLS(t, one.certificate)
	if rec, _ := do(t, f, r); rec.Code != http.StatusForbidden {
		t.Fatalf("the certificate from before the rebuild still worked: %d", rec.Code)
	}
	// The new one is not.
	r = req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = asTLS(t, two.certificate)
	if rec, _ := do(t, f, r); rec.Code != 200 {
		t.Fatalf("the certificate from the rebuild does not work: %d", rec.Code)
	}
}

// ---------------------------------------------------------------- the rest

// Helpdesk may see which devices are on their way in, and may not admit one.
// That is the whole reason device.enrol is its own action rather than a
// reuse of something that happened to have the right roles today.
func TestOnlyTheRolesInTheMatrixMayAdmitADevice(t *testing.T) {
	f := newFixture(t)

	for _, bearer := range []string{"a-helpdesk", "a-auditor", "a-secmgr", "a-employee"} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", bearer,
			map[string]any{"label": "x", "ownership": "company", "os_family": "macos"}))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s created an enrolment: got %d", bearer, rec.Code)
		}
	}
	for _, bearer := range []string{"a-super", "a-itadmin"} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", bearer,
			map[string]any{"label": "x", "ownership": "company", "os_family": "macos"}))
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s could not create an enrolment: got %d", bearer, rec.Code)
		}
	}
	// Helpdesk can still read the list.
	rec, _ := do(t, f, req(t, "GET", hostA, "/api/enrolments", "a-helpdesk"))
	if rec.Code != 200 {
		t.Fatalf("helpdesk could not list enrolments: got %d", rec.Code)
	}
}

// The token is a bearer credential, so it is stored the way a password is:
// not at all, only its hash.
func TestTheTokenIsNeverStored(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "a laptop")

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	var n int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM enrolments
		 WHERE encode(token_hash, 'escape') LIKE '%' || $1 || '%'`, token).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 0 {
		t.Fatal("the token is recoverable from the enrolments table")
	}
	// The audit log is the other place a credential must not end up, since
	// it is the one table nobody may delete from.
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE object_ref LIKE '%' || $1 || '%'`,
		token).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 0 {
		t.Fatal("the token was written to the audit log")
	}
}

// An enrolment is a thing that happened to a tenant, and so is the issuing
// of a credential. Both belong in the tenant's own audit log.
func TestEnrolmentIsAudited(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "an audited laptop")
	if got := redeem(t, f, hostA, token, "SN-AUDIT-1", ""); got.code != http.StatusCreated {
		t.Fatalf("redeem: %d %v", got.code, got.body)
	}

	_, body := do(t, f, req(t, "GET", hostA, "/api/audit", "a-auditor"))
	events, _ := json.Marshal(body["events"])
	for _, want := range []string{
		"enrolment.create", "authority.create", "enrolment.complete", "certificate.issue",
	} {
		if !strings.Contains(string(events), want) {
			t.Fatalf("%s is not in the audit log: %s", want, events)
		}
	}
}

// The authority is made once and reused. A second one would invalidate every
// certificate the first had issued.
func TestTheTenantAuthorityIsMadeOnceAndReused(t *testing.T) {
	f := newFixture(t)

	for i := 0; i < 3; i++ {
		_, token := makeEnrolment(t, f, hostA, "a-itadmin", "laptop")
		got := redeem(t, f, hostA, token, "SN-CA-"+string(rune('A'+i)), "")
		if got.code != http.StatusCreated {
			t.Fatalf("enrolment %d: %d %v", i, got.code, got.body)
		}
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM tenant_ca WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Fatalf("%d authorities for one tenant", n)
	}
	// And the key is not sitting there in the clear.
	var sealed []byte
	if err := conn.QueryRow(ctx,
		`SELECT private_key_sealed FROM tenant_ca WHERE tenant_id = $1`, tenantA).Scan(&sealed); err != nil {
		t.Fatalf("query: %v", err)
	}
	if strings.Contains(string(sealed), "PRIVATE KEY") {
		t.Fatal("the authority's private key is stored in the clear")
	}
}

func TestAnEnrolmentCannotBeAskedToLastForever(t *testing.T) {
	f := newFixture(t)
	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", "a-itadmin",
		map[string]any{"label": "x", "ownership": "company", "os_family": "macos",
			"days": 3650}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a ten-year enrolment was accepted: got %d", rec.Code)
	}
}

func TestIncompleteEnrolmentDetailsAreRefused(t *testing.T) {
	f := newFixture(t)
	for name, in := range map[string]map[string]any{
		"no label":      {"ownership": "company", "os_family": "macos"},
		"blank label":   {"label": "   ", "ownership": "company", "os_family": "macos"},
		"no ownership":  {"label": "x", "os_family": "macos"},
		"bad ownership": {"label": "x", "ownership": "leased", "os_family": "macos"},
		"bad os":        {"label": "x", "ownership": "company", "os_family": "beos"},
	} {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", "a-itadmin", in))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", name, rec.Code)
		}
	}
}

// The console shows the link once, on the page that answers the form, rather
// than redirecting. A redirect would have to carry the token in a URL.
func TestTheConsoleShowsTheLinkOnceAndDoesNotRedirect(t *testing.T) {
	f := newFixture(t)

	sess, err := f.sessions.Verify(f.cookie(t, "a-itadmin"))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	cookie := f.cookie(t, "a-itadmin")
	r := httptest.NewRequest("POST", "http://"+hostA+"/enrolments",
		strings.NewReader("label=Kemi%27s+laptop&ownership=company&os_family=macos&csrf="+
			f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)

	if rec.Code == http.StatusSeeOther || rec.Code == http.StatusFound {
		t.Fatalf("the console redirected, which would put the token in a URL: %s",
			rec.Header().Get("Location"))
	}
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/enrol?t=") {
		t.Fatalf("the page does not show the link: %s", body)
	}
	if !strings.Contains(body, "shown\n  once") && !strings.Contains(body, "shown") {
		t.Fatal("the page does not say the link is shown once")
	}
}

func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec: %v", err)
	}
}

// The unauthenticated routes do not pass through entry, so they do not get
// entry's rate limit. That was fine while the only one was a sign-in
// redirect. It stopped being fine when one of them began parsing a
// certificate signing request and verifying a signature for anyone who
// asked, so the limit moved into the one helper they all share.
func TestTheUnauthenticatedRoutesAreRateLimited(t *testing.T) {
	f := newFixture(t)
	exec(t, `UPDATE tenants SET api_rate_per_min = 5 WHERE id = $1`, tenantA)

	limited := 0
	for i := 0; i < 30; i++ {
		rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/enrol", "", map[string]any{
			"token": "not-a-real-token", "csr": "not-a-real-csr", "serial": "x",
		}))
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("enrolment accepted 30 requests against a 5 per minute plan")
	}

	// The sign-in routes share the helper, so they share the limit.
	r := httptest.NewRequest("GET", "http://"+hostA+"/signin", nil)
	r.Host = hostA
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("sign-in was not limited: got %d", rec.Code)
	}
}

// execErr runs a statement and hands back whatever the database said, for
// the tests that assert a constraint or a trigger refuses something.
func execErr(t *testing.T, sql string, args ...any) error {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql, args...)
	return err
}

// lostAt reads the reported-lost timestamp straight from the row, for the
// tests that care that it does not move.
func lostAt(t *testing.T, device uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	var at *string
	if err := conn.QueryRow(ctx,
		`SELECT reported_lost_at::text FROM devices WHERE id = $1`, device).Scan(&at); err != nil {
		t.Fatalf("read: %v", err)
	}
	if at == nil {
		t.Fatal("the device is not reported lost")
	}
	return *at
}

// sweep runs the expiring-certificate check the way a deployment does on a
// timer, under an administrator's claim.
func sweep(t *testing.T, f fixture) int {
	t.Helper()
	tok, err := f.g.signer.Mint(tenantclaim.Claim{
		TenantID: tenantA, Subject: "system:sweeper", Role: "platform_operator",
		RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	var n int
	if err := f.g.store.WithTenant(context.Background(), tok,
		func(ctx context.Context, tx *data.Tx) error {
			var serr error
			n, serr = f.g.SweepExpiring(ctx, tx)
			return serr
		}); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	return n
}

// queryRow reads one value straight from the database, for assertions about
// rows no API exposes.
func queryRow(t *testing.T, sql string, into any, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if err := conn.QueryRow(ctx, sql, args...).Scan(into); err != nil {
		t.Fatalf("query: %v", err)
	}
}

// The link an operator is shown starts https, not http. Behind a load
// balancer that ends TLS the process never sees TLS, and the link used to say
// http:// because of it: a token that anyone following the link as written
// would have sent unprotected. Only a developer's own machine is http.
func TestTheEnrolmentLinkIsHTTPSExceptOnADevelopersOwnMachine(t *testing.T) {
	for host, want := range map[string]string{
		"babbangona.mdm.vlumesec.com": "https",
		"mdm.kalesi.example:8443":     "https",
		"localhost:8100":              "http",
		"127.0.0.1:8100":              "http",
		"kalesi.localhost":            "http",
	} {
		r := httptest.NewRequest("GET", "http://"+host+"/", nil)
		r.Host = host
		if got := publicScheme(r); got != want {
			t.Errorf("%s: scheme %q, want %q", host, got, want)
		}
	}
}

// The Enrolments page is for computers that run the agent. Asking it for an
// Android phone sends the person to the Android page and makes nothing: a
// token made here is a link that does nothing on a phone.
func TestAnAndroidPhoneIsSentToTheAndroidPageNotGivenAnAgentToken(t *testing.T) {
	f := newFixture(t)
	before := adminCount(t, `SELECT count(*) FROM enrolments`)
	rec := postForm(t, f, "a-itadmin", "/enrolments", url.Values{
		"label": {"Kemi's phone"}, "ownership": {"personal"}, "os_family": {"android"}})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/android") ||
		!strings.Contains(said(rec), "Android page") {
		t.Fatalf("an Android request on the Enrolments page: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if adminCount(t, `SELECT count(*) FROM enrolments`) != before {
		t.Fatal("an agent token was made for an Android phone")
	}
}

// A computer is given the command to run, with the token on standard input
// and never on the command line, and told in words why there is no QR code.
func TestTheLinkPageGivesTheCommandAndExplainsWhyThereIsNoQRCode(t *testing.T) {
	f := newFixture(t)
	rec := postForm(t, f, "a-itadmin", "/enrolments", url.Values{
		"label": {"Kemi's laptop"}, "ownership": {"company"}, "os_family": {"macos"}})
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("%d", rec.Code)
	}
	for _, want := range []string{"agent -server https://" + hostA + " -dir /var/lib/mdm enrol", "echo &#39;", "not a web page", "no QR code"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not contain %q", want)
		}
	}
	if strings.Contains(body, "-token ") {
		t.Error("the command puts the token on the command line")
	}
}
