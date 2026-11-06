package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/branding"
	"platform/internal/directory"
)

// Self-service sign-up. A stranger reaches these routes, so the tests are
// about what a stranger can cause: one email to an address they typed, and
// nothing else until they prove the address is theirs.

const signupHost = "signup.example"

func withSignup(t *testing.T, f fixture) fixture {
	t.Helper()
	f.g.signup = &SignupConfig{
		Host: signupHost, TenantDomain: "mdm.example",
		Brand: branding.Brand{ProductName: "Device Care", Colour: "#1F4E79", MarkLetter: "D"},
		// The fixture's real SMTP server, so the link is read out of a
		// delivered message rather than out of the database.
		Mail:           f.emailChannel,
		BurstPerMinute: 1000,
	}
	f.h = f.g.Handler()
	cleanSignups(t)
	return f
}

func cleanSignups(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	for _, s := range []string{
		`DELETE FROM signups`,
		`DELETE FROM tenant_keys WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'su-%')`,
		`DELETE FROM tenant_branding WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'su-%')`,
		`DELETE FROM tenant_role_map WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'su-%')`,
		`DELETE FROM tenant_identity WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'su-%')`,
		`DELETE FROM tenant_domains WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'su-%')`,
		`DELETE FROM command_signing_keys`,
		`DELETE FROM tenants WHERE slug LIKE 'su-%'`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("clean: %v", err)
		}
	}
}

func adminExec(t *testing.T, sql string, args ...any) {
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

func adminUUID(t *testing.T, sql string, args ...any) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	var id uuid.UUID
	if err := conn.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
		t.Fatalf("query: %v", err)
	}
	return id
}

func adminCount(t *testing.T, sql string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	return n
}

// public sends a request with no credential of any kind, from a given
// address, with a browser's Accept header.
func public(t *testing.T, f fixture, method, host, path, ip string, vals url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if vals == nil {
		r = httptest.NewRequest(method, "http://"+host+path, nil)
	} else {
		r = httptest.NewRequest(method, "http://"+host+path, strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Host = host
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

var linkRE = regexp.MustCompile(`https?://` + signupHost + `/signup/([A-Za-z0-9_-]+)`)

// askFor is step 1 and returns the token out of the delivered email.
func askFor(t *testing.T, f fixture, email, company, ip string) string {
	t.Helper()
	before := len(f.mail.Received())
	rec := public(t, f, "POST", signupHost, "/signup", ip, url.Values{
		"email": {email}, "company": {company},
	})
	if rec.Code != 200 {
		t.Fatalf("sign-up request: %d %s", rec.Code, firstLine(rec.Body.String(), "said"))
	}
	got := f.mail.Received()
	if len(got) != before+1 {
		t.Fatalf("%d emails were sent for one request", len(got)-before)
	}
	m := got[len(got)-1]
	if len(m.To) != 1 || m.To[0] != strings.ToLower(email) {
		t.Fatalf("the email went to %v, not to %s", m.To, email)
	}
	// The body is dot-stuffed and wrapped by the channel; the link is on
	// one line by construction.
	match := linkRE.FindStringSubmatch(m.Data)
	if match == nil {
		t.Fatalf("no link in the email:\n%s", m.Data)
	}
	return match[1]
}

func firstLine(body, marker string) string {
	i := strings.Index(body, marker)
	if i == -1 {
		return ""
	}
	j := strings.Index(body[i:], "</div>")
	if j == -1 {
		return body[i:]
	}
	return body[i : i+j]
}

func finish(t *testing.T, f fixture, token, slug, group string) *httptest.ResponseRecorder {
	t.Helper()
	rec := public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.10",
		url.Values{"slug": {slug}})
	if rec.Code != 303 {
		t.Fatalf("slug: %d", rec.Code)
	}
	return public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.10", url.Values{
		"issuer": {"https://login.microsoftonline.com/su/v2.0"}, "client_id": {"su-console"},
		"client_secret": {"s3cret"}, "admin_group": {group},
	})
}

func TestAStrangerBecomesATenantByProvingTheirEmail(t *testing.T) {
	f := withSignup(t, newFixture(t))

	// Step 1: the page, then the request. One row, one email, no tenant.
	rec := public(t, f, "GET", signupHost, "/signup", "203.0.113.10", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Device Care") {
		t.Fatalf("sign-up page: %d", rec.Code)
	}
	token := askFor(t, f, "Ada@Arbor-Foods.example", "Arbor Foods", "203.0.113.10")
	if n := adminCount(t, `SELECT count(*) FROM tenants WHERE slug LIKE 'su-%'`); n != 0 {
		t.Fatal("a tenant exists before the address was proven")
	}
	// The token in the link is not what the row holds.
	if n := adminCount(t, `SELECT count(*) FROM signups WHERE encode(token_hash, 'base64') LIKE $1`,
		token[:8]+"%"); n != 0 {
		t.Fatal("the row holds the token itself rather than its hash")
	}

	// Step 2: the link. The address is now proven; the first page asks
	// for the console's address and suggests one.
	rec = public(t, f, "GET", signupHost, "/signup/"+token, "203.0.113.10", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `value="arbor-foods"`) {
		t.Fatalf("open: %d\n%s", rec.Code, rec.Body.String())
	}
	if n := adminCount(t, `SELECT count(*) FROM signups WHERE verified_at IS NOT NULL`); n != 1 {
		t.Fatal("opening the link did not record the proof")
	}

	// Step 3: the address, then the second page shows the redirect URL the
	// provider must be told, derived from the slug.
	rec = public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.10",
		url.Values{"slug": {"su-arbor"}})
	if rec.Code != 303 {
		t.Fatalf("slug: %d", rec.Code)
	}
	rec = public(t, f, "GET", signupHost, "/signup/"+token, "203.0.113.10", nil)
	if !strings.Contains(rec.Body.String(), "https://su-arbor.mdm.example/signin/callback") {
		t.Fatalf("the redirect URL is not shown:\n%s", rec.Body.String())
	}

	// Step 4: the provider. The tenant now exists, answers on its host,
	// and has a way in.
	rec = public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.10", url.Values{
		"issuer": {"https://login.microsoftonline.com/arbor/v2.0"}, "client_id": {"arbor-console"},
		"client_secret": {"s3cret"}, "admin_group": {"MDM-Owners"},
	})
	if rec.Code != 303 || !strings.HasSuffix(rec.Header().Get("Location"), "/done") {
		t.Fatalf("finish: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = public(t, f, "GET", signupHost, "/signup/"+token+"/done", "203.0.113.10", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "https://su-arbor.mdm.example") {
		t.Fatalf("done: %d\n%s", rec.Code, rec.Body.String())
	}
	// The welcome: one more email, to the proven address, naming the
	// console and the group, so the person has it somewhere other than a
	// page behind a spent link.
	got := f.mail.Received()
	if len(got) != 2 {
		t.Fatalf("%d emails after sign-up, want the link and the welcome", len(got))
	}
	welcome := got[1]
	if len(welcome.To) != 1 || welcome.To[0] != "ada@arbor-foods.example" {
		t.Fatalf("the welcome went to %v", welcome.To)
	}
	for _, want := range []string{"https://su-arbor.mdm.example/signin", "MDM-Owners", "Arbor Foods"} {
		if !strings.Contains(welcome.Data, want) {
			t.Fatalf("the welcome does not say %q:\n%s", want, welcome.Data)
		}
	}
	if strings.Contains(welcome.Data, token) {
		t.Fatal("the welcome carries the spent token")
	}

	tenant, err := f.g.dir.ResolveHost(context.Background(), "su-arbor.mdm.example")
	if err != nil || !tenant.Active() || tenant.Name != "Arbor Foods" {
		t.Fatalf("the new tenant does not resolve: %+v %v", tenant, err)
	}
	cfg, err := f.g.dir.Identity(context.Background(), tenant.ID)
	if err != nil || cfg.RedirectURL != "https://su-arbor.mdm.example/signin/callback" {
		t.Fatalf("identity: %+v %v", cfg, err)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_role_map WHERE tenant_id = $1
	                        AND claim_value = 'MDM-Owners' AND role = 'super_admin'`, tenant.ID); n != 1 {
		t.Fatal("the admin group is not mapped to super_admin")
	}
	// The sign-up host serves a stranger a sign-up and nothing else; the
	// tenant's own host does not serve sign-up.
	if rec := public(t, f, "GET", signupHost, "/devices", "203.0.113.10", nil); rec.Code != 404 {
		t.Fatalf("the sign-up host served /devices: %d", rec.Code)
	}
	if rec := public(t, f, "GET", "su-arbor.mdm.example", "/signup", "203.0.113.10", nil); rec.Code == 200 {
		t.Fatal("a tenant's host served the sign-up page")
	}
}

func TestALinkWorksOnceAndNotAfterItsDay(t *testing.T) {
	f := withSignup(t, newFixture(t))

	// Once.
	token := askFor(t, f, "ada@arbor.example", "Arbor", "203.0.113.11")
	if rec := finish(t, f, token, "su-once", "Owners"); rec.Code != 303 ||
		!strings.HasSuffix(rec.Header().Get("Location"), "/done") {
		t.Fatalf("first finish: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec := public(t, f, "GET", signupHost, "/signup/"+token, "203.0.113.11", nil)
	if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "already been used") {
		t.Fatalf("a used link opened: %d", rec.Code)
	}
	rec = public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.11", url.Values{
		"issuer": {"https://login.example/v2.0"}, "client_id": {"x"},
		"client_secret": {"y"}, "admin_group": {"Owners"},
	})
	if rec.Code != http.StatusGone {
		t.Fatalf("a used link finished again: %d", rec.Code)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenants WHERE slug LIKE 'su-%'`); n != 1 {
		t.Fatalf("%d tenants from one link", n)
	}

	// Not after its day. The expiry is moved back with the admin
	// connection rather than by waiting.
	token = askFor(t, f, "bola@arbor.example", "Arbor", "203.0.113.11")
	adminExec(t, `UPDATE signups SET expires_at = now() - interval '1 minute' WHERE email = 'bola@arbor.example'`)
	rec = public(t, f, "GET", signupHost, "/signup/"+token, "203.0.113.11", nil)
	if rec.Code != http.StatusGone || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("an expired link opened: %d", rec.Code)
	}
	// Every step after the link refuses it, not only the first.
	for _, step := range []string{"/slug", "/finish"} {
		rec := public(t, f, "POST", signupHost, "/signup/"+token+step, "203.0.113.11", url.Values{
			"slug": {"su-late"}, "issuer": {"https://login.example/v2.0"}, "client_id": {"x"},
			"client_secret": {"y"}, "admin_group": {"Owners"},
		})
		if rec.Code != http.StatusGone {
			t.Fatalf("an expired link passed %s: %d", step, rec.Code)
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM tenants WHERE slug = 'su-late'`); n != 0 {
		t.Fatal("an expired link created a tenant")
	}

	// A token we never issued is not found, with no hint of why.
	rec = public(t, f, "GET", signupHost, "/signup/"+strings.Repeat("A", 43), "203.0.113.11", nil)
	if rec.Code != 404 {
		t.Fatalf("an invented token: %d", rec.Code)
	}
}

func TestAskingAgainReplacesTheFirstLink(t *testing.T) {
	f := withSignup(t, newFixture(t))
	first := askFor(t, f, "ada@arbor.example", "Arbor", "203.0.113.12")
	second := askFor(t, f, "ada@arbor.example", "Arbor", "203.0.113.12")
	if rec := public(t, f, "GET", signupHost, "/signup/"+first, "203.0.113.12", nil); rec.Code != http.StatusGone {
		t.Fatalf("the replaced link still opens: %d", rec.Code)
	}
	if rec := public(t, f, "GET", signupHost, "/signup/"+second, "203.0.113.12", nil); rec.Code != 200 {
		t.Fatalf("the new link does not open: %d", rec.Code)
	}
}

func TestOnlyAWorkAddressMaySignUp(t *testing.T) {
	f := withSignup(t, newFixture(t))
	before := len(f.mail.Received())
	for _, addr := range []string{
		"someone@gmail.com", "someone@outlook.com", "someone@proton.me",
		"Ada Obi <ada@arbor.example>", "not-an-address", "ada@localhost", "",
	} {
		rec := public(t, f, "POST", signupHost, "/signup", "203.0.113.13", url.Values{
			"email": {addr}, "company": {"Arbor"},
		})
		if rec.Code == 200 {
			t.Fatalf("%q was accepted", addr)
		}
	}
	rec := public(t, f, "POST", signupHost, "/signup", "203.0.113.13", url.Values{
		"email": {"ada@arbor.example"}, "company": {"  "},
	})
	if rec.Code == 200 {
		t.Fatal("a sign-up with no company was accepted")
	}
	if n := len(f.mail.Received()); n != before {
		t.Fatalf("%d emails were sent for refused requests", n-before)
	}
	if n := adminCount(t, `SELECT count(*) FROM signups`); n != 0 {
		t.Fatalf("%d rows were written for refused requests", n)
	}
}

func TestTheCapsHoldPerDomainAndPerAddress(t *testing.T) {
	f := withSignup(t, newFixture(t))

	// Per domain: five a day, from different people at the same company.
	for i := 0; i < directory.MaxSignupsPerDomainPerDay; i++ {
		askFor(t, f, "person"+string(rune('a'+i))+"@arbor.example", "Arbor", "203.0.113.2"+string(rune('0'+i)))
	}
	rec := public(t, f, "POST", signupHost, "/signup", "203.0.113.30", url.Values{
		"email": {"sixth@arbor.example"}, "company": {"Arbor"},
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the sixth sign-up from one domain: %d", rec.Code)
	}

	// Per address: ten a day, across different companies.
	for i := 0; i < directory.MaxSignupsPerIPPerDay; i++ {
		askFor(t, f, "p@company"+string(rune('a'+i))+".example", "Company", "203.0.113.99")
	}
	rec = public(t, f, "POST", signupHost, "/signup", "203.0.113.99", url.Values{
		"email": {"p@another.example"}, "company": {"Another"},
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the eleventh sign-up from one address: %d", rec.Code)
	}
	// The same request from elsewhere is fine: the cap is on the caller.
	askFor(t, f, "p@another.example", "Another", "203.0.113.100")
}

func TestATakenAddressIsRefusedWithoutCreatingAnything(t *testing.T) {
	f := withSignup(t, newFixture(t))
	token := askFor(t, f, "ada@arbor.example", "Arbor", "203.0.113.14")
	// The seeded tenant's slug.
	rec := public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.14",
		url.Values{"slug": {"kalesi"}})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "taken") {
		t.Fatalf("a taken slug: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	for _, bad := range []string{"Arbor Foods", "su_arbor", "-su", ""} {
		rec := public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.14",
			url.Values{"slug": {bad}})
		if bad != "" && !strings.Contains(rec.Header().Get("Location"), "said=") {
			t.Fatalf("slug %q was accepted", bad)
		}
	}
	// A finish with no provider creates nothing and says what is missing.
	public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.14", url.Values{"slug": {"su-arbor2"}})
	rec = public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.14", url.Values{
		"issuer": {"https://login.example/v2.0"}, "client_id": {"x"}, "client_secret": {"y"},
	})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "said=") {
		t.Fatalf("a finish with no admin group: %d", rec.Code)
	}
	rec = public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.14", url.Values{
		"issuer": {"http://login.example/v2.0"}, "client_id": {"x"}, "client_secret": {"y"},
		"admin_group": {"Owners"},
	})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "said=") {
		t.Fatalf("an http issuer: %d", rec.Code)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenants WHERE slug LIKE 'su-%'`); n != 0 {
		t.Fatal("a refused finish created a tenant")
	}
	// And no welcome for a tenant that does not exist: the link email is
	// the only one.
	if n := len(f.mail.Received()); n != 1 {
		t.Fatalf("%d emails after refused finishes, want 1", n)
	}
}

func TestSignupIsAbsentWhenNotConfigured(t *testing.T) {
	f := newFixture(t)
	for _, host := range []string{signupHost, hostA} {
		rec := public(t, f, "GET", host, "/signup", "203.0.113.15", nil)
		if rec.Code == 200 {
			t.Fatalf("%s served sign-up with none configured", host)
		}
	}
}
