package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/directory"
	"platform/internal/localauth"
	"platform/internal/session"
)

// The platform owner's console (0048). It can suspend every customer, so the
// tests are about who can reach it, what it shows, and what a customer's
// session is worth there: nothing.

const (
	opsHost = "ops.example"
	opsSite = "http://" + opsHost
)

type opsFixture struct {
	fixture
	server *httptest.Server
}

func cleanOperators(t *testing.T) {
	t.Helper()
	for _, s := range []string{`DELETE FROM operator_events`, `DELETE FROM operator_tokens`, `DELETE FROM operator_accounts`} {
		exec(t, s)
	}
}

func newOpsFixture(t *testing.T) *opsFixture {
	t.Helper()
	f := newFixture(t)
	cleanOperators(t)
	t.Cleanup(func() { cleanOperators(t) })
	f.g.operator = &OperatorConfig{Host: opsHost}
	f.h = f.g.Handler()
	srv := httptest.NewServer(f.h)
	t.Cleanup(srv.Close)
	return &opsFixture{fixture: f, server: srv}
}

func (f *opsFixture) browser(t *testing.T) *browser {
	t.Helper()
	return newBrowser(t, f.server.Listener.Addr().String())
}

var opsSecretRE = regexp.MustCompile(`<code>([A-Z2-7]{20,})</code>`)

func opsSecretFrom(t *testing.T, body string) []byte {
	t.Helper()
	m := opsSecretRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no secret on the page:\n%.600s", body)
	}
	return secretFrom(t, `user-select:all">`+m[1]+`</code>`)
}

func opsCookieOf(b *browser, name string) string {
	u, _ := url.Parse(opsSite + "/")
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// onboard takes a brand new owner all the way through the invitation: the
// link, a password, the authenticator, the recovery codes. The browser ends
// signed in.
func (f *opsFixture) onboard(t *testing.T, b *browser, email string) (id uuid.UUID, secret []byte, codes []string) {
	t.Helper()
	ctx := context.Background()
	o, err := f.g.dir.CreateOperator(ctx, email, "Owner "+email[:1], "test")
	if err != nil {
		t.Fatal(err)
	}
	token, purpose, _, err := f.g.dir.IssueOperatorLink(ctx, o.ID, "test", time.Now().UTC())
	if err != nil || purpose != "invite" {
		t.Fatalf("link: %v %q", err, purpose)
	}
	if resp, page := read(b, opsSite+"/accept/"+token); resp.StatusCode != 200 || !strings.Contains(page, "Choose a password") {
		t.Fatalf("the invitation did not open (%d): %.300s", resp.StatusCode, page)
	}
	resp, page := b.postForm(opsSite+"/accept/"+token, url.Values{"password": {localPassword}, "confirm": {localPassword}})
	if resp.StatusCode != 200 || !strings.Contains(page, "Set up your authenticator") || !strings.Contains(page, "data:image/png;base64,") {
		t.Fatalf("the password did not lead to the authenticator (%d): %.500s", resp.StatusCode, page)
	}
	secret = opsSecretFrom(t, page)
	resp, codesPage := b.postForm(opsSite+"/signin/enrol", url.Values{"code": {localauth.Code(secret, time.Now())}})
	if resp.StatusCode != 200 || !strings.Contains(codesPage, "Keep these recovery codes") {
		t.Fatalf("the authenticator did not finish the sign-in (%d): %.400s", resp.StatusCode, codesPage)
	}
	return o.ID, secret, recoveryCodes(t, codesPage)
}

func atTheOpsForm(body string) bool {
	return strings.Contains(body, `action="/signin"`) && strings.Contains(body, `name="password"`)
}

// opsRaw is one request with exactly the cookies given and nothing else.
func opsRaw(t *testing.T, h http.Handler, method, host, path string, cookies map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.Host = host
	r.RemoteAddr = "192.0.2.50:40000"
	r.Header.Set("Accept", "text/html")
	for k, v := range cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// ------------------------------------------------------------------ where

func TestTheOwnersConsoleAnswersOnItsOwnHostAndNowhereElse(t *testing.T) {
	f := newOpsFixture(t)
	b := f.browser(t)

	if resp, page := read(b, opsSite+"/signin"); resp.StatusCode != 200 || !strings.Contains(page, "Platform operations") {
		t.Fatalf("the owner's sign-in is not on its own host (%d): %.200s", resp.StatusCode, page)
	}
	// A customer's hostname serves a customer's pages, never these.
	for _, p := range []string{"/orgs", "/licences", "/operators", "/events", "/signups", "/accept/x", "/reset/x"} {
		rec := opsRaw(t, f.h, "GET", hostA, p, nil)
		if strings.Contains(rec.Body.String(), "Platform operations") {
			t.Errorf("%s on a customer's hostname served an owner page", p)
		}
	}
	// And the owner's host serves no customer.
	if rec := opsRaw(t, f.h, "GET", opsHost, "/api/devices", nil); strings.Contains(rec.Body.String(), "HQ-MBP-001") {
		t.Error("the owner's host served a customer's devices")
	}
	// Turned off, the host is nothing at all.
	f.g.operator = nil
	h := f.g.Handler()
	if rec := opsRaw(t, h, "GET", opsHost, "/signin", nil); rec.Code != 404 || strings.Contains(rec.Body.String(), "Platform operations") {
		t.Errorf("with the console off its host answered %d", rec.Code)
	}
}

// ------------------------------------------------------------------- in

func TestAnOwnerGetsInByInvitationPasswordAndAuthenticator(t *testing.T) {
	f := newOpsFixture(t)
	b := f.browser(t)
	id, secret, codes := f.onboard(t, b, "tobi@example.com")

	if len(codes) != 10 {
		t.Fatalf("%d recovery codes", len(codes))
	}
	// The secret and the codes are not kept as they are.
	if n := adminCount(t, `SELECT count(*) FROM operator_accounts WHERE totp_secret_sealed = $1`, secret); n != 0 {
		t.Fatal("the authenticator secret is stored unsealed")
	}
	for _, c := range codes {
		if n := adminCount(t, `SELECT count(*) FROM operator_accounts WHERE $1 = ANY(recovery_hashes)`, c); n != 0 {
			t.Fatal("a recovery code is stored as it is")
		}
	}
	if st := adminString(t, `SELECT status FROM operator_accounts WHERE id = $1`, id); st != "active" {
		t.Fatalf("status %q after the authenticator", st)
	}
	if _, dash := read(b, opsSite+"/"); !strings.Contains(dash, "Overview") {
		t.Fatal("the new session does not reach the overview")
	}

	// Later: a fresh browser needs the password and then a code, and a code is
	// good once.
	b2 := f.browser(t)
	resp, page := b2.postForm(opsSite+"/signin", url.Values{"email": {"tobi@example.com"}, "password": {localPassword}})
	if resp.StatusCode != 200 || !strings.Contains(page, "Second step") {
		t.Fatalf("the password did not lead to the second step (%d): %.300s", resp.StatusCode, page)
	}
	if opsCookieOf(b2, opsCookie) != "" {
		t.Fatal("a session exists after the password alone")
	}
	if _, body := read(b2, opsSite+"/orgs"); !atTheOpsForm(body) {
		t.Fatalf("the half-signed-in browser reached a page:\n%.200s", body)
	}
	good := localauth.Code(secret, time.Now().Add(localauth.TOTPStep))
	if _, body := b2.postForm(opsSite+"/signin/mfa", url.Values{"code": {"000000"}}); !strings.Contains(body, "did not work") || opsCookieOf(b2, opsCookie) != "" {
		t.Fatalf("a wrong code was taken: %.300s", body)
	}
	resp, body := b2.postForm(opsSite+"/signin/mfa", url.Values{"code": {good}})
	if resp.StatusCode != 200 || !strings.Contains(body, "Overview") || opsCookieOf(b2, opsCookie) == "" {
		t.Fatalf("the right code did not sign in (%d): %.300s", resp.StatusCode, body)
	}
	// The same code a second time, from another browser that has the password.
	b3 := f.browser(t)
	b3.postForm(opsSite+"/signin", url.Values{"email": {"tobi@example.com"}, "password": {localPassword}})
	if _, body := b3.postForm(opsSite+"/signin/mfa", url.Values{"code": {good}}); strings.Contains(body, "Overview") || opsCookieOf(b3, opsCookie) != "" {
		t.Fatal("a code that was already used signed somebody in")
	}
	// A recovery code works once.
	if _, body := b3.postForm(opsSite+"/signin/mfa", url.Values{"code": {codes[0]}}); !strings.Contains(body, "Overview") {
		t.Fatalf("a recovery code did not work: %.300s", body)
	}
	b4 := f.browser(t)
	b4.postForm(opsSite+"/signin", url.Values{"email": {"tobi@example.com"}, "password": {localPassword}})
	if _, body := b4.postForm(opsSite+"/signin/mfa", url.Values{"code": {codes[0]}}); strings.Contains(body, "Overview") {
		t.Fatal("a recovery code worked twice")
	}
}

func TestAnInvitationWorksOnceAndOnlyOnce(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	o, _ := f.g.dir.CreateOperator(ctx, "a@example.com", "A", "test")
	token, _, _, _ := f.g.dir.IssueOperatorLink(ctx, o.ID, "test", time.Now().UTC())

	b := f.browser(t)
	if _, page := b.postForm(opsSite+"/accept/"+token, url.Values{"password": {localPassword}, "confirm": {localPassword}}); !strings.Contains(page, "Set up your authenticator") {
		t.Fatalf("the first use failed: %.300s", page)
	}
	other := f.browser(t)
	resp, page := other.postForm(opsSite+"/accept/"+token, url.Values{"password": {"another-long-passphrase-9"}, "confirm": {"another-long-passphrase-9"}})
	if resp.StatusCode != http.StatusGone || !strings.Contains(page, "expired") {
		t.Fatalf("a used link was accepted again (%d): %.300s", resp.StatusCode, page)
	}
	if resp, _ := read(other, opsSite+"/accept/"+token); resp.StatusCode != http.StatusGone {
		t.Fatalf("a used link still opens (%d)", resp.StatusCode)
	}
	// A newer link replaces an older one that was never used.
	o2, _ := f.g.dir.CreateOperator(ctx, "b@example.com", "B", "test")
	first, _, _, _ := f.g.dir.IssueOperatorLink(ctx, o2.ID, "test", time.Now().UTC())
	second, _, _, _ := f.g.dir.IssueOperatorLink(ctx, o2.ID, "test", time.Now().UTC())
	if resp, _ := read(other, opsSite+"/accept/"+first); resp.StatusCode != http.StatusGone {
		t.Fatalf("an older link still works after a newer one was made (%d)", resp.StatusCode)
	}
	if resp, _ := read(other, opsSite+"/accept/"+second); resp.StatusCode != 200 {
		t.Fatalf("the newer link does not work (%d)", resp.StatusCode)
	}
	// A password the policy refuses does not cost the person their link.
	if _, page := other.postForm(opsSite+"/accept/"+second, url.Values{"password": {"short"}, "confirm": {"short"}}); !strings.Contains(page, "will not do") {
		t.Fatalf("a short password was taken: %.300s", page)
	}
	if resp, _ := read(other, opsSite+"/accept/"+second); resp.StatusCode != 200 {
		t.Fatal("a refused password used the link up")
	}
}

// A password somebody else set, or a reset second factor, is not a way in.
func TestAPasswordAloneIsNotASignInUntilTheAuthenticatorIsSetUp(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	o, _ := f.g.dir.CreateOperator(ctx, "a@example.com", "A", "test")
	token, _, _, _ := f.g.dir.IssueOperatorLink(ctx, o.ID, "test", time.Now().UTC())
	b := f.browser(t)
	b.postForm(opsSite+"/accept/"+token, url.Values{"password": {localPassword}, "confirm": {localPassword}})

	// The password is set, the authenticator is not. Walking away here and
	// coming back with just the password must get nowhere.
	fresh := f.browser(t)
	resp, body := fresh.postForm(opsSite+"/signin", url.Values{"email": {"a@example.com"}, "password": {localPassword}})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "did not match") {
		t.Fatalf("a password with no authenticator went somewhere (%d): %.300s", resp.StatusCode, body)
	}
	if resp, _ := read(fresh, opsSite+"/signin/enrol"); strings.Contains(opsCookieOf(fresh, opsPending), "f1.") || resp.StatusCode == 0 {
		t.Fatal("a pending cookie was set")
	}
}

func TestEveryWayToFailAnOwnerSignInLooksTheSame(t *testing.T) {
	f := newOpsFixture(t)
	f.onboard(t, f.browser(t), "real@example.com")
	f.onboard(t, f.browser(t), "other@example.com")
	other, _ := f.g.dir.OperatorByEmail(context.Background(), "other@example.com")
	if err := f.g.dir.SetOperatorStatus(context.Background(), other.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	f.g.dir.CreateOperator(context.Background(), "invited@example.com", "", "test")

	tries := map[string]url.Values{
		"nobody":   {"email": {"nobody@example.com"}, "password": {localPassword}},
		"wrong":    {"email": {"real@example.com"}, "password": {"not-the-password-at-all-1"}},
		"disabled": {"email": {"other@example.com"}, "password": {localPassword}},
		"invited":  {"email": {"invited@example.com"}, "password": {localPassword}},
	}
	var first string
	for name, form := range tries {
		resp, body := f.browser(t).postForm(opsSite+"/signin", form)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
		// Whatever was typed is put back in the form, so compare what the
		// page says, not the page.
		said := regexp.MustCompile(`role="alert">([^<]*)<`).FindStringSubmatch(body)
		if said == nil {
			t.Fatalf("%s: no message:\n%.300s", name, body)
		}
		if first == "" {
			first = said[1]
		} else if said[1] != first {
			t.Errorf("%s says %q, another says %q", name, said[1], first)
		}
	}
}

func TestFiveWrongOwnerPasswordsLockTheAccountEvenAgainstTheRightOne(t *testing.T) {
	f := newOpsFixture(t)
	f.onboard(t, f.browser(t), "real@example.com")
	for i := 0; i < 5; i++ {
		f.browser(t).postForm(opsSite+"/signin", url.Values{"email": {"real@example.com"}, "password": {"wrong-wrong-wrong-wrong-1"}})
	}
	resp, body := f.browser(t).postForm(opsSite+"/signin", url.Values{"email": {"real@example.com"}, "password": {localPassword}})
	if resp.StatusCode != http.StatusUnauthorized || strings.Contains(body, "Second step") {
		t.Fatalf("the right password got past a lock (%d): %.200s", resp.StatusCode, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM operator_events WHERE action = 'operator.locked'`); n != 1 {
		t.Fatalf("%d lock records", n)
	}
}

func TestWrongSecondFactorCodesCountTowardTheLock(t *testing.T) {
	f := newOpsFixture(t)
	f.onboard(t, f.browser(t), "real@example.com")
	b := f.browser(t)
	b.postForm(opsSite+"/signin", url.Values{"email": {"real@example.com"}, "password": {localPassword}})
	for i := 0; i < 5; i++ {
		b.postForm(opsSite+"/signin/mfa", url.Values{"code": {"000000"}})
	}
	if n := adminCount(t, `SELECT count(*) FROM operator_events WHERE action = 'operator.locked'`); n != 1 {
		t.Fatalf("five wrong codes locked the account %d times", n)
	}
}

// ------------------------------------------------------------- sessions

func TestAnOwnersSessionEndsWhenTheAccountIsDisabledOrItsPasswordChanges(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	b1, b2 := f.browser(t), f.browser(t)
	id1, _, _ := f.onboard(t, b1, "one@example.com")
	f.onboard(t, b2, "two@example.com")

	if _, body := read(b1, opsSite+"/orgs"); !strings.Contains(body, "Organisations") {
		t.Fatal("the session does not work to begin with")
	}
	time.Sleep(20 * time.Millisecond)
	old := opsCookieOf(b1, opsCookie)
	if err := f.g.dir.SetOperatorStatus(ctx, id1, true, "two@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, body := read(b1, opsSite+"/orgs"); !atTheOpsForm(body) {
		t.Fatalf("a disabled owner's session still works:\n%.200s", body)
	}
	// Enabled again, the old session stays dead: it began before the
	// disabling. The browser dropped its cookie when it was refused, so the
	// old one is replayed by hand.
	if err := f.g.dir.SetOperatorStatus(ctx, id1, false, "two@example.com"); err != nil {
		t.Fatal(err)
	}
	if rec := opsRaw(t, f.h, "GET", opsHost, "/orgs", map[string]string{opsCookie: old}); rec.Code != http.StatusSeeOther {
		t.Fatalf("re-enabling an owner brought an old session back (%d)", rec.Code)
	}

	// A password reset ends every session.
	time.Sleep(20 * time.Millisecond)
	token, purpose, _, err := f.g.dir.IssueOperatorLink(ctx, id1, "two@example.com", time.Now().UTC())
	if err != nil || purpose != "reset" {
		t.Fatalf("an active owner with an authenticator was offered %q (%v)", purpose, err)
	}
	b3 := f.browser(t)
	_, body := b3.postForm(opsSite+"/reset/"+token, url.Values{"password": {"a-different-long-passphrase-4"}, "confirm": {"a-different-long-passphrase-4"}})
	if !strings.Contains(body, "Your password is changed") {
		t.Fatalf("the reset did not finish: %.300s", body)
	}
	if opsCookieOf(b3, opsCookie) != "" {
		t.Fatal("a reset link signed somebody in without the second factor")
	}
	// The second factor was not touched by the reset.
	if n := adminCount(t, `SELECT count(*) FROM operator_accounts WHERE id = $1 AND totp_enabled`, id1); n != 1 {
		t.Fatal("a password reset removed the second factor")
	}
}

func TestResettingTheAuthenticatorMakesTheOwnerStartFromALink(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	b := f.browser(t)
	id, _, _ := f.onboard(t, b, "one@example.com")
	time.Sleep(20 * time.Millisecond)
	if err := f.g.dir.ResetOperatorMFA(ctx, id, "test"); err != nil {
		t.Fatal(err)
	}
	if _, body := read(b, opsSite+"/"); !atTheOpsForm(body) {
		t.Fatal("a session survived its owner's authenticator being reset")
	}
	// The old password gets nowhere until a link sets up a new authenticator.
	if resp, _ := f.browser(t).postForm(opsSite+"/signin", url.Values{"email": {"one@example.com"}, "password": {localPassword}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("the old password still opens the second step after a reset")
	}
}

// What a customer's session is worth here: nothing. Each of the three layers
// that say so is tried on its own.
func TestACustomersSessionIsNothingOnTheOwnersConsole(t *testing.T) {
	f := newOpsFixture(t)
	b := f.browser(t)
	id, _, _ := f.onboard(t, b, "one@example.com")

	forge := func(tenant uuid.UUID, subject, role string) string {
		tok, _, err := f.g.sessions.Start(session.Session{TenantID: tenant, Subject: subject, Email: "x@example.com", Role: role})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	// What a genuine owner session looks like, so the refusals below are not
	// refusals of everything.
	if rec := opsRaw(t, f.h, "GET", opsHost, "/orgs", map[string]string{opsCookie: forge(opsRealm, opsSubject(id), opsRole)}); rec.Code != 200 {
		t.Fatalf("the control session was refused: %d", rec.Code)
	}
	cases := map[string]string{
		"another realm":                   forge(tenantA, opsSubject(id), opsRole),
		"a tenant role":                   forge(opsRealm, opsSubject(id), "super_admin"),
		"a subject not marked an owner's": forge(opsRealm, id.String(), opsRole),
		"a real tenant session":           f.cookie(t, "a-super"),
	}
	for name, tok := range cases {
		rec := opsRaw(t, f.h, "GET", opsHost, "/orgs", map[string]string{opsCookie: tok})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin" {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}

	// And the other way: an owner's session is no credential for a customer.
	ownerTok := opsCookieOf(b, opsCookie)
	if rec := opsRaw(t, f.h, "GET", hostA, "/api/devices", map[string]string{sessionCookie: ownerTok}); (rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden) || strings.Contains(rec.Body.String(), "HQ-MBP-001") {
		t.Errorf("an owner's session on a customer's API: %d", rec.Code)
	}
	// The half-signed-in cookie is no session either.
	b2 := f.browser(t)
	b2.postForm(opsSite+"/signin", url.Values{"email": {"one@example.com"}, "password": {localPassword}})
	pend := opsCookieOf(b2, opsPending)
	if pend == "" {
		t.Fatal("no pending cookie to try")
	}
	if rec := opsRaw(t, f.h, "GET", opsHost, "/orgs", map[string]string{opsCookie: pend}); rec.Code != http.StatusSeeOther {
		t.Errorf("the pending cookie as a session: %d", rec.Code)
	}
	if rec := opsRaw(t, f.h, "GET", opsHost, "/signin/mfa", map[string]string{opsPending: ownerTok}); rec.Code != http.StatusSeeOther {
		t.Errorf("a session as the pending cookie: %d", rec.Code)
	}
}

// -------------------------------------------------------------- the pages

func TestTheOwnersPagesShowOrganisationsAsCountsAndNeverWhatIsInsideThem(t *testing.T) {
	f := newOpsFixture(t)
	b := f.browser(t)
	f.onboard(t, b, "one@example.com")

	orgs, err := f.g.dir.List(context.Background())
	if err != nil || len(orgs) < 2 {
		t.Fatalf("%d organisations in the fixture (%v)", len(orgs), err)
	}
	serial := adminString(t, `SELECT serial FROM devices LIMIT 1`)
	deviceName := adminString(t, `SELECT name FROM devices LIMIT 1`)

	pages := []string{"/", "/orgs", "/orgs/" + orgs[0].Slug, "/signups", "/licences", "/operators", "/events", "/account"}
	for _, p := range pages {
		resp, body := read(b, opsSite+p)
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", p, resp.StatusCode)
			continue
		}
		if strings.Contains(body, serial) || strings.Contains(body, deviceName) {
			t.Errorf("%s shows what is inside an organisation", p)
		}
		for h, want := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
			if resp.Header.Get(h) != want {
				t.Errorf("%s: %s is %q", p, h, resp.Header.Get(h))
			}
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: no frame-ancestors in the policy", p)
		}
	}
	_, list := read(b, opsSite+"/orgs")
	for _, o := range orgs {
		if !strings.Contains(list, o.Name) {
			t.Errorf("organisation %q is not listed", o.Name)
		}
	}
	// The filters.
	if _, body := read(b, opsSite+"/orgs?q="+url.QueryEscape(orgs[0].Slug)); !strings.Contains(body, orgs[0].Name) || strings.Contains(body, orgs[1].Name) {
		t.Error("the search did not narrow the list")
	}
	if _, body := read(b, opsSite+"/orgs?status=suspended"); strings.Contains(body, orgs[0].Name) {
		t.Error("the suspended filter listed an active organisation")
	}
	if resp, _ := read(b, opsSite+"/orgs/no-such-organisation"); resp.StatusCode != 404 {
		t.Errorf("an unknown organisation: %d", resp.StatusCode)
	}
	_, detail := read(b, opsSite+"/orgs/"+orgs[0].Slug)
	for _, want := range []string{"devices in use", "admin seats in use", "Licence", "Usage, last 30 days"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the organisation page lacks %q", want)
		}
	}
	_, lic := read(b, opsSite+"/licences")
	for _, p := range directory.Plans() {
		if !strings.Contains(lic, p.Name) {
			t.Errorf("plan %q is not on the licences page", p.Name)
		}
	}
	if _, ev := read(b, opsSite+"/events"); !strings.Contains(ev, "operator.signed_in") {
		t.Error("the sign-in is not in the activity record")
	}
}

func TestTheOwnersCountsAreTheRealOnes(t *testing.T) {
	f := newOpsFixture(t)
	b := f.browser(t)
	f.onboard(t, b, "one@example.com")
	orgs, _ := f.g.dir.List(context.Background())
	u, err := f.g.dir.Usage(context.Background(), orgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	_, detail := read(b, opsSite+"/orgs/"+orgs[0].Slug)
	want := regexp.MustCompile(`<b>` + strconv.Itoa(u.ActiveDevices) + ` <span style="font-size:15px">of ` + strconv.Itoa(u.DeviceCap) + `</span></b>`)
	if !want.MatchString(detail) {
		t.Fatalf("the page does not show %d of %d devices:\n%.1500s", u.ActiveDevices, u.DeviceCap, detail)
	}
	// Near the limit is said so.
	exec(t, `UPDATE tenants SET device_cap = $2 WHERE id = $1`, orgs[0].ID, max(1, u.ActiveDevices))
	f.g.opsCache = opsOrgCache{}
	_, list := read(b, opsSite+"/licences")
	if !strings.Contains(list, "at the limit") && u.ActiveDevices > 0 {
		t.Errorf("an organisation at its limit is not flagged:\n%.1500s", list)
	}
	_, dash := read(b, opsSite+"/")
	if u.ActiveDevices > 0 && !strings.Contains(dash, "at 80% of their device allowance") {
		t.Error("the overview has no near-limit count")
	}
}

func TestTheOwnersCookiesAreAsStrictAsTheyCanBe(t *testing.T) {
	f := newOpsFixture(t)
	f.onboard(t, f.browser(t), "one@example.com")
	f.g.insecureCookies = false // as in production
	defer func() { f.g.insecureCookies = true }()

	r := httptest.NewRequest("POST", "http://"+opsHost+"/signin", strings.NewReader(url.Values{
		"email": {"one@example.com"}, "password": {localPassword}}.Encode()))
	r.Host = opsHost
	r.RemoteAddr = "192.0.2.51:40000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == opsPending {
			found = true
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
				t.Errorf("the pending cookie is %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("no cookie was set")
	}
}

func TestOwnerSignInFormsRefuseAnotherSite(t *testing.T) {
	f := newOpsFixture(t)
	f.onboard(t, f.browser(t), "one@example.com")
	r := httptest.NewRequest("POST", "http://"+opsHost+"/signin", strings.NewReader(url.Values{
		"email": {"one@example.com"}, "password": {localPassword}}.Encode()))
	r.Host = opsHost
	r.RemoteAddr = "192.0.2.52:40000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a form posted from another site got %d", rec.Code)
	}
}

func TestSigningOutEndsTheBrowsersSession(t *testing.T) {
	f := newOpsFixture(t)
	b := f.browser(t)
	f.onboard(t, b, "one@example.com")
	_, dash := read(b, opsSite+"/")
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(dash)
	if m == nil {
		t.Fatal("no sign-out form on the page")
	}
	_, body := b.postForm(opsSite+"/signout", url.Values{"csrf": {m[1]}})
	if !strings.Contains(body, "You are signed out") {
		t.Fatalf("sign-out did not say so: %.300s", body)
	}
	if _, body := read(b, opsSite+"/orgs"); !atTheOpsForm(body) {
		t.Fatal("the browser still reaches a page after signing out")
	}
	if n := adminCount(t, `SELECT count(*) FROM operator_events WHERE action = 'operator.signed_out'`); n != 1 {
		t.Fatalf("%d sign-out records", n)
	}
}

func TestAnOwnerPageWithNoSessionSendsYouToSignIn(t *testing.T) {
	f := newOpsFixture(t)
	for _, p := range []string{"/", "/orgs", "/orgs/kalesi", "/signups", "/licences", "/operators", "/events", "/account"} {
		rec := opsRaw(t, f.h, "GET", opsHost, p, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin" {
			t.Errorf("%s with no session: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Body.String(), "Organisations") && strings.Contains(rec.Body.String(), "devices in use") {
			t.Errorf("%s showed content with no session", p)
		}
	}
}

// However an account stops being active, its session stops with it.
func TestAnOwnerMarkedDisabledLosesTheSessionWhateverDidIt(t *testing.T) {
	f := newOpsFixture(t)
	b := f.browser(t)
	id, _, _ := f.onboard(t, b, "one@example.com")
	f.onboard(t, f.browser(t), "two@example.com")
	exec(t, `UPDATE operator_accounts SET status = 'disabled' WHERE id = $1`, id)
	if _, body := read(b, opsSite+"/orgs"); !atTheOpsForm(body) {
		t.Fatal("a session outlived its account being disabled directly")
	}
}

// Unknown is not zero, and the flags sit at 80 and 100 percent.
func TestUsageThatCannotBeReadIsUnknownAndTheFlagsSitAtEightyAndAHundred(t *testing.T) {
	s := directory.Summary{Name: "X", Slug: "x"}
	if o := opsMeasure(s, directory.Usage{}, errors.New("no")); !o.NoUsage || o.Devices != 0 {
		t.Fatalf("%+v", o)
	}
	for _, c := range []struct {
		devices, cap int
		flag         string
		percent      int
	}{{0, 50, "", 0}, {39, 50, "", 78}, {40, 50, "near", 80}, {49, 50, "near", 98}, {50, 50, "over", 100}, {80, 50, "over", 100}, {5, 0, "", 0}} {
		o := opsMeasure(s, directory.Usage{ActiveDevices: c.devices, DeviceCap: c.cap}, nil)
		if o.Flag != c.flag || o.Percent != c.percent || o.NoUsage {
			t.Errorf("%d of %d: flag %q percent %d", c.devices, c.cap, o.Flag, o.Percent)
		}
	}
}
