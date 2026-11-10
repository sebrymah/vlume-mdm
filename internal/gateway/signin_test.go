package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"platform/internal/identity"
	"platform/internal/identity/idptest"
	"platform/internal/secrets"
	"platform/internal/session"
)

// A whole sign-in, end to end: the browser arrives with nothing, is sent to
// the tenant's own identity provider, comes back with a code, and leaves
// holding a session that opens the console.
//
// The provider is real OpenID Connect (see internal/identity/idptest), the
// database is real PostgreSQL, and the browser is a real HTTP client with a
// real cookie jar. What is simulated is DNS: the client sends every request
// for a tenant hostname to the test server, which is the one thing a test
// cannot have for free.

type browser struct {
	client *http.Client
	t      *testing.T
}

// newBrowser wires a client that behaves like one. It keeps cookies per
// hostname, follows redirects, and resolves the example hostnames to the
// gateway under test while leaving the provider's own address alone.
func newBrowser(t *testing.T, gatewayAddr string) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &browser{t: t, client: &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// The identity provider is genuinely listening on 127.0.0.1.
				// Everything else is a tenant hostname that only exists in
				// the directory, and belongs at the gateway.
				if strings.HasPrefix(addr, "127.0.0.1:") {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", gatewayAddr)
			},
		},
	}}
}

func (b *browser) get(url string) (*http.Response, string) {
	b.t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		b.t.Fatalf("request: %v", err)
	}
	// Go's client sends no Accept header. A browser always does, and the
	// gateway uses it to decide between a sign-in page and a 401 an API
	// client can read, so a test browser that omits it is testing the
	// wrong branch.
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	// All of it, not one read: a single Read returns whatever the first
	// network chunk held, so a page whose head grew would be cut off before
	// its content and the tests would fail for a reason a browser never sees.
	all, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(all)
}

// stopAtRedirect runs one request without following anything, for the tests
// that care about where the gateway points rather than what is there.
func (b *browser) once(method, url string) *http.Response {
	b.t.Helper()
	b.client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { b.client.CheckRedirect = nil }()

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		b.t.Fatalf("request: %v", err)
	}
	req.Header.Set("Accept", "text/html")
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, url, err)
	}
	resp.Body.Close()
	return resp
}

func (b *browser) sessionCookie(host string) string {
	b.t.Helper()
	u, _ := url.Parse("http://" + host + "/")
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	return ""
}

type signInFixture struct {
	fixture
	idp     *idptest.Server
	server  *httptest.Server
	browser *browser
}

// newSignInFixture builds the fixture above plus a tenant that has actually
// been through setup: an identity provider, a sealed client secret, and a
// mapping from its groups to roles here.
func newSignInFixture(t *testing.T) *signInFixture {
	t.Helper()
	f := newFixture(t)

	idpServer, err := idptest.New("kalesi-console")
	if err != nil {
		t.Fatalf("idptest: %v", err)
	}
	t.Cleanup(idpServer.Close)

	sealer, err := secrets.NewAESSealer(sealKey)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	sealed, err := sealer.Seal([]byte("the-client-secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Rebuild the gateway with the sign-in parts wired in. newFixture gives
	// us a working store, directory and pipeline; this adds what a sign-in
	// needs on top.
	g := New(Config{
		Directory: f.g.dir, Store: f.g.store, Signer: f.g.signer, Identity: idp,
		Pipeline: f.pipe, CSRFKey: testKey, Sessions: f.sessions,
		OIDC: identity.NewOIDC(), Sealer: secrets.NewKeyring(sealer), Enrol: f.enrol,
		InsecureCookies: true,
	})
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)

	seedIdentity(t, idpServer.Issuer(), sealed)

	return &signInFixture{
		fixture: fixture{h: g.Handler(), g: g, pipe: f.pipe,
			sessions: f.sessions, enrol: f.enrol, sealer: secrets.NewKeyring(sealer),
			devices: f.devices},
		idp:     idpServer,
		server:  srv,
		browser: newBrowser(t, srv.Listener.Addr().String()),
	}
}

// seedIdentity is the setup wizard, done in SQL. Tenant A has finished it.
// Tenant B deliberately has not, which is a state a real deployment is in
// every time a new customer signs up.
func seedIdentity(t *testing.T, issuer string, sealed []byte) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_identity
		  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim)
		VALUES ($1, $2, 'kalesi-console', $3,
		        'http://mdm.kalesi.example/signin/callback', 'groups')`,
		tenantA, issuer, sealed); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_role_map (tenant_id, claim_value, role) VALUES
		  ($1,'MDM-Owners','super_admin'),
		  ($1,'IT-Operations','it_admin'),
		  ($1,'Security-Team','security_manager'),
		  ($1,'All-Staff','employee')`, tenantA); err != nil {
		t.Fatalf("seed role map: %v", err)
	}
}

var okonkwo = idptest.Person{
	Subject: "9f2c1a40-0000-4000-8000-000000000001",
	Email:   "o.martins@kalesi.example",
	Name:    "O. Martins",
	Groups:  []string{"All-Staff", "IT-Operations"},
}

// ---------------------------------------------------------------- the path

func TestAPersonSignsInAndReachesTheConsole(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)

	resp, body := f.browser.get("http://mdm.kalesi.example/signin")
	if resp.StatusCode != 200 {
		t.Fatalf("sign-in ended at %d: %s", resp.StatusCode, body)
	}
	// The chain ends on the dashboard, in the tenant's own branding.
	if !strings.Contains(body, "Dashboard") {
		t.Fatalf("did not land on the console: %s", body)
	}
	if !strings.Contains(body, "Kalesi Device Care") {
		t.Fatal("the console rendered without the tenant's brand")
	}
	// The role came from the group, not from a default. IT-Operations maps
	// to it_admin, which outranks the All-Staff mapping to employee.
	if !strings.Contains(body, "it_admin") {
		t.Fatalf("wrong role on the page: %s", body)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") == "" {
		t.Fatal("no session cookie was set")
	}
}

// The highest mapped group wins, and it has to win every time rather than
// most of the time.
func TestTheHighestMappedGroupDecidesTheRole(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(idptest.Person{
		Subject: "9f2c1a40-0000-4000-8000-000000000009",
		Email:   "f.okonkwo@kalesi.example",
		Groups:  []string{"All-Staff", "IT-Operations", "MDM-Owners", "Security-Team"},
	})
	_, body := f.browser.get("http://mdm.kalesi.example/signin")
	if !strings.Contains(body, "super_admin") {
		t.Fatalf("did not get the highest role: %s", body)
	}
}

// The first-day support call. Someone signs in perfectly well and still
// cannot get in, and the page has to say why and whose job it is to fix.
func TestSomeoneWithNoMappedGroupIsToldWhatIsWrong(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(idptest.Person{
		Subject: "9f2c1a40-0000-4000-8000-000000000002",
		Email:   "t.eze@kalesi.example",
		Groups:  []string{"Canteen", "Lagos-Office"},
	})

	resp, body := f.browser.get("http://mdm.kalesi.example/signin")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(body, "none of your groups is mapped") {
		t.Fatalf("the page did not explain the problem: %s", body)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatal("a session was issued to someone with no role")
	}
	// T12: a tenant-facing surface, including this one, names no operator.
	if strings.Contains(body, "platform") && strings.Contains(body, "operator") {
		t.Fatalf("the error page leaked operator language: %s", body)
	}
}

// A tenant partway through onboarding. Not an error, and the difference
// matters: an error page tells them to call support, this tells them which
// step they have not done.
func TestATenantWithNoIdentityProviderIsToldToFinishSetup(t *testing.T) {
	f := newSignInFixture(t)
	resp, body := f.browser.get("http://devices.arbor.example/signin")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("got %d, want 409", resp.StatusCode)
	}
	if !strings.Contains(body, "identity provider") {
		t.Fatalf("the page did not name the missing step: %s", body)
	}
}

// ------------------------------------------------------------- the refusals

// The gateway's central rule, now applied to a session that was minted here
// and is completely valid: it belongs to one tenant's hostname and nowhere
// else.
func TestASessionFromOneTenantDoesNotWorkOnAnother(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	f.browser.get("http://mdm.kalesi.example/signin")

	token := f.browser.sessionCookie("mdm.kalesi.example")
	if token == "" {
		t.Fatal("no session to carry across")
	}

	r := httptest.NewRequest("GET", "http://"+hostB+"/api/devices", nil)
	r.Host = hostB
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a Kalesi session worked on Arbor's hostname: got %d", rec.Code)
	}
}

// Tenant-wide revocation. An administrator ends every session at once, and
// an open browser stops working on its next request rather than whenever its
// token happens to expire.
//
// The checks below use raw requests rather than the test browser on purpose.
// A browser that is refused is sent to sign in, and this provider signs
// people in without asking, so following the redirects would quietly produce
// a brand new valid session and a green test. That is correct behaviour and
// the wrong thing to assert here.
func TestRevokingATenantsSessionsEndsThemAtOnce(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	f.browser.get("http://mdm.kalesi.example/signin")

	token := f.browser.sessionCookie("mdm.kalesi.example")
	if token == "" {
		t.Fatal("not signed in")
	}
	call := func() int {
		r := httptest.NewRequest("GET", "http://"+hostA+"/api/devices", nil)
		r.Host = hostA
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, r)
		return rec.Code
	}

	if got := call(); got != 200 {
		t.Fatalf("the session did not work before revocation: %d", got)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx,
		`UPDATE tenants SET sessions_invalid_before = now() WHERE id = $1`, tenantA); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if got := call(); got != http.StatusUnauthorized {
		t.Fatalf("a revoked session still worked: got %d", got)
	}

	// And renewal cannot bring it back. Renewal moves IssuedAt, which is
	// what decides whether a token is re-minted, but never StartedAt, which
	// is what revocation is compared against.
	sess, err := f.sessions.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	renewed, _, err := f.sessions.Renew(sess)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	token = renewed
	if got := call(); got != http.StatusUnauthorized {
		t.Fatalf("a revoked session was renewed back to life: got %d", got)
	}
}

// Revocation ends sessions; it does not lock anyone out. Someone whose
// session was ended signs in again and carries on, which is what makes it a
// control an administrator will actually use.
func TestAfterRevocationSigningInAgainWorks(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	f.browser.get("http://mdm.kalesi.example/signin")
	first := f.browser.sessionCookie("mdm.kalesi.example")

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx,
		`UPDATE tenants SET sessions_invalid_before = now() WHERE id = $1`, tenantA); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	resp, body := f.browser.get("http://mdm.kalesi.example/devices")
	if resp.StatusCode != 200 {
		t.Fatalf("could not sign in again after revocation: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Devices") {
		t.Fatalf("did not land back where they were going: %s", body)
	}
	if second := f.browser.sessionCookie("mdm.kalesi.example"); second == first {
		t.Fatal("the revoked session was handed back")
	}
}

// A callback is only good for the sign-in that started it, in the browser
// that started it.
func TestTheCallbackRefusesAStateThatDidNotStartHere(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)

	// Start a real sign-in so the browser holds a genuine flow cookie, then
	// come back with someone else's state.
	resp := f.browser.once("GET", "http://mdm.kalesi.example/signin")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("sign-in did not redirect: %d", resp.StatusCode)
	}
	r := f.browser.once("GET",
		"http://mdm.kalesi.example/signin/callback?code=whatever&state=not-the-one")
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("a mismatched state was accepted: got %d", r.StatusCode)
	}
}

func TestTheCallbackRefusesASignInWithNoFlowAtAll(t *testing.T) {
	f := newSignInFixture(t)
	r := f.browser.once("GET",
		"http://mdm.kalesi.example/signin/callback?code=whatever&state=anything")
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("a callback with no flow cookie was accepted: got %d", r.StatusCode)
	}
}

// A sign-in begun on one tenant's hostname and finished on another's. The
// flow carries the tenant it started at, so the two have to agree for the
// same reason a session and a hostname do.
func TestASignInStartedAtOneTenantCannotFinishAtAnother(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)

	resp := f.browser.once("GET", "http://mdm.kalesi.example/signin")
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("redirect: %v", err)
	}
	state := loc.Query().Get("state")

	// The flow cookie is scoped to mdm.kalesi.example, so hand it over by
	// hand: this is the attacker who has one and is trying to spend it on
	// the other tenant's hostname.
	u, _ := url.Parse("http://mdm.kalesi.example/")
	var flow string
	for _, c := range f.browser.client.Jar.Cookies(u) {
		if c.Name == flowCookie {
			flow = c.Value
		}
	}
	if flow == "" {
		t.Fatal("no flow cookie was set")
	}

	r := httptest.NewRequest("GET",
		"http://"+hostB+"/signin/callback?code=x&state="+state, nil)
	r.Host = hostB
	r.AddCookie(&http.Cookie{Name: flowCookie, Value: flow})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a Kalesi sign-in finished at Arbor: got %d", rec.Code)
	}
}

// ------------------------------------------------------------- the details

// A browser with no session wants the sign-in page. A program wants a 401 it
// can read. The difference is the Accept header and nothing else.
func TestABrowserIsSentToSignInAndAProgramIsNot(t *testing.T) {
	f := newSignInFixture(t)

	r := httptest.NewRequest("GET", "http://"+hostA+"/devices", nil)
	r.Host = hostA
	r.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusFound {
		t.Fatalf("a browser was not sent to sign in: got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/signin") || !strings.Contains(loc, "next=") {
		t.Fatalf("sent somewhere unhelpful: %s", loc)
	}

	r = httptest.NewRequest("GET", "http://"+hostA+"/api/devices", nil)
	r.Host = hostA
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a program got a redirect instead of 401: got %d", rec.Code)
	}
}

// An open redirect through the "where was I going" parameter would be a
// phishing link on the tenant's own domain.
func TestTheReturnPathCannotPointOffSite(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)

	for _, bad := range []string{
		"https://evil.example/steal",
		"//evil.example/steal",
		"/\\evil.example",
	} {
		resp, _ := f.browser.get("http://mdm.kalesi.example/signin?next=" +
			url.QueryEscape(bad))
		if resp.StatusCode != 200 {
			t.Fatalf("%s: sign-in ended at %d", bad, resp.StatusCode)
		}
		if got := resp.Request.URL.Host; got != "mdm.kalesi.example" {
			t.Fatalf("%s: ended up at %s", bad, got)
		}
	}
}

func TestTheReturnPathIsHonouredWhenItIsLocal(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	resp, _ := f.browser.get("http://mdm.kalesi.example/signin?next=%2Fdevices")
	if resp.Request.URL.Path != "/devices" {
		t.Fatalf("did not return to where they were going: %s", resp.Request.URL.Path)
	}
}

func TestSignOutEndsTheSession(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	f.browser.get("http://mdm.kalesi.example/signin")

	token := f.browser.sessionCookie("mdm.kalesi.example")
	if token == "" {
		t.Fatal("not signed in")
	}
	sess, err := f.sessions.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	r := httptest.NewRequest("POST", "http://"+hostA+"/signout",
		strings.NewReader("csrf="+url.QueryEscape(
			f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role))))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)

	if rec.Code != http.StatusFound {
		t.Fatalf("sign-out got %d", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("sign-out did not clear the session cookie")
	}
}

func TestSignOutWithoutTheFormTokenIsRefused(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	f.browser.get("http://mdm.kalesi.example/signin")

	r := httptest.NewRequest("POST", "http://"+hostA+"/signout", strings.NewReader(""))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie,
		Value: f.browser.sessionCookie("mdm.kalesi.example")})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a cross-site sign-out worked: got %d", rec.Code)
	}
}

// A sign-in is a thing that happened to a tenant, so it belongs in that
// tenant's own audit log, written in the same transaction as the role lookup.
func TestASignInIsAudited(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	f.browser.get("http://mdm.kalesi.example/signin")

	resp, body := f.browser.get("http://mdm.kalesi.example/api/audit")
	if resp.StatusCode != 200 {
		t.Fatalf("audit: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "session.start") {
		t.Fatalf("the sign-in was not recorded: %s", body)
	}
	if !strings.Contains(body, "role:it_admin") {
		t.Fatalf("the record does not say what was granted: %s", body)
	}
}

// Renewal is invisible when it works, which is why it needs a test. A
// session old enough to be worth replacing comes back with a fresh cookie,
// and the person never sees a sign-in page they did not ask for.
func TestAStaleSessionIsRenewedOnUse(t *testing.T) {
	f := newSignInFixture(t)
	now := time.Now().UTC()

	// Sign in two hours ago, then last use the console ten minutes ago.
	// That leaves a token well inside its idle window and its lifetime, and
	// older than the interval at which it is worth re-minting.
	f.sessions.Now = func() time.Time { return now.Add(-2 * time.Hour) }
	_, sess, err := f.sessions.Start(session.Session{
		TenantID: tenantA, Subject: "o.martins", Role: "it_admin"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	f.sessions.Now = func() time.Time { return now.Add(-10 * time.Minute) }
	aged, _, err := f.sessions.Renew(sess)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	f.sessions.Now = func() time.Time { return time.Now().UTC() }

	r := httptest.NewRequest("GET", "http://"+hostA+"/api/devices", nil)
	r.Host = hostA
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: aged})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)

	if rec.Code != 200 {
		t.Fatalf("a renewable session was refused: %d", rec.Code)
	}
	var fresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			fresh = c.Value
		}
	}
	if fresh == "" || fresh == aged {
		t.Fatal("a stale session was not renewed")
	}
	// The replacement is a real session for the same person, and it did not
	// quietly restart the clock on the absolute lifetime.
	got, err := f.sessions.Verify(fresh)
	if err != nil {
		t.Fatalf("the renewed cookie does not verify: %v", err)
	}
	if got.Subject != sess.Subject || !got.StartedAt.Equal(sess.StartedAt) {
		t.Fatalf("renewal changed who the session is for: %+v", got)
	}
	if !got.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatal("renewal moved the absolute expiry")
	}
}

// Sign-out on a shared machine has to end the provider's session as well
// as ours, or the next person at the keyboard is signed in as the last.
func TestSignOutEndsTheProviderSessionToo(t *testing.T) {
	f := newSignInFixture(t)
	f.idp.SignInAs(okonkwo)
	f.browser.get("http://mdm.kalesi.example/signin")
	token := f.browser.sessionCookie("mdm.kalesi.example")
	if token == "" {
		t.Fatal("not signed in")
	}
	sess, _ := f.sessions.Verify(token)

	// One hop at a time: ours, then the provider's, then back to our
	// sign-in page over https (the console's own scheme for a real host).
	step := *f.browser.client
	step.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := step.PostForm("http://mdm.kalesi.example/signout",
		url.Values{"csrf": {f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)}})
	if err != nil {
		t.Fatalf("sign out: %v", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, f.idp.Issuer()+"/logout") {
		t.Fatalf("sign-out went to %d %s, not the provider's end-session page", resp.StatusCode, loc)
	}
	resp, err = step.Get(loc)
	if err != nil {
		t.Fatalf("provider logout: %v", err)
	}
	resp.Body.Close()
	if f.idp.LoggedOut() != 1 {
		t.Fatal("the provider's session was not ended")
	}
	if back := f.idp.LastLogout.Get("post_logout_redirect_uri"); back != "https://mdm.kalesi.example/signin" {
		t.Fatalf("the provider was told to send the person to %q", back)
	}
	if resp.Header.Get("Location") != "https://mdm.kalesi.example/signin" {
		t.Fatalf("the provider sent the person to %q", resp.Header.Get("Location"))
	}
	if f.idp.LastLogout.Get("client_id") != "kalesi-console" {
		t.Fatal("the provider was not told which application asked")
	}
	if f.browser.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatal("our session cookie survived the sign-out")
	}
}
