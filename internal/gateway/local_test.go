package gateway

import (
	"encoding/base32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/localauth"
)

// Sign-in for a tenant that has no identity provider (0044).

const localPassword = "blue-lamp-ferry-cloud-7"

var (
	hashOnce   sync.Once
	cachedHash string
)

// passwordHash is the hash of localPassword, made once: argon2id is slow
// on purpose and these tests make a lot of accounts.
func passwordHash(t *testing.T) string {
	t.Helper()
	hashOnce.Do(func() {
		h, err := localauth.Hash(localPassword)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		cachedHash = h
	})
	return cachedHash
}

type localFixture struct {
	fixture
	server *httptest.Server
}

// newLocalFixture is tenant A with no identity provider: its sign-in is the
// form, and its people are rows.
func newLocalFixture(t *testing.T) *localFixture {
	t.Helper()
	f := newFixture(t)
	exec(t, `INSERT INTO tenant_identity (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim, protocol)
	         VALUES ($1, '', '', ''::bytea, 'http://mdm.kalesi.example/signin', 'groups', 'local')`, tenantA)
	srv := httptest.NewServer(f.g.Handler())
	t.Cleanup(srv.Close)
	return &localFixture{fixture: f, server: srv}
}

func (f *localFixture) browser(t *testing.T) *browser {
	t.Helper()
	return newBrowser(t, f.server.Listener.Addr().String())
}

// account makes an account directly, active with the test password unless
// it is invited.
func (f *localFixture) account(t *testing.T, email, name, role, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	hash := ""
	if status != "invited" {
		hash = passwordHash(t)
	}
	exec(t, `INSERT INTO local_accounts (id, tenant_id, email, name, role, status, password_hash, password_set_at, created_by)
	         VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7 <> '' THEN now() END, 'test')`,
		id, tenantA, email, name, role, status, hash)
	return id
}

// read is GET with the whole body, which browser.get does not promise.
func read(b *browser, to string) (*http.Response, string) {
	b.t.Helper()
	req, _ := http.NewRequest("GET", to, nil)
	req.Header.Set("Accept", "text/html")
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("GET %s: %v", to, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(body)
}

const site = "http://mdm.kalesi.example"

func (b *browser) signIn(email, password string) (*http.Response, string) {
	b.t.Helper()
	return b.postForm(site+"/signin/local", url.Values{"email": {email}, "password": {password}})
}

func (b *browser) signedIn() bool { return b.sessionCookie("mdm.kalesi.example") != "" }

// atTheForm says the page is the sign-in form: the browser has no session.
func atTheForm(body string) bool {
	return strings.Contains(body, `name="password"`) && strings.Contains(body, `action="/signin/local"`)
}

var secretRE = regexp.MustCompile(`user-select:all">([A-Z2-7]{20,})</code>`)

func secretFrom(t *testing.T, body string) []byte {
	t.Helper()
	m := secretRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no secret on the page:\n%.600s", body)
	}
	s, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m[1])
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	return s
}

var codeRE = regexp.MustCompile(`\b[a-z2-9]{5}-[a-z2-9]{5}\b`)
var preRE = regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)

// recoveryCodes reads the codes out of the block that holds them, and
// nowhere else on the page.
func recoveryCodes(t *testing.T, page string) []string {
	t.Helper()
	m := preRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no code block on the page:\n%.400s", page)
	}
	return codeRE.FindAllString(m[1], -1)
}

// ----------------------------------------------------------------- the basics

func TestALocalTenantSignsInWithAnEmailAndAPassword(t *testing.T) {
	f := newLocalFixture(t)
	id := f.account(t, "t.eze@kalesi.example", "T. Eze", "employee", "active")
	b := f.browser(t)

	// The form, in the tenant's own words.
	_, form := read(b, site+"/signin")
	if !atTheForm(form) || !strings.Contains(form, "Forgot your password?") {
		t.Fatalf("the sign-in page is not the form:\n%.500s", form)
	}
	resp, body := b.signIn("T.Eze@Kalesi.example", localPassword)
	if resp.StatusCode != 200 || !strings.Contains(body, "Your devices") || !b.signedIn() {
		t.Fatalf("sign-in ended at %d (session %v): %.400s", resp.StatusCode, b.signedIn(), body)
	}
	// The platform has now met them, under a subject that is never reused,
	// and the sign-in is in the audit log under their name.
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND subject = $2 AND email = 't.eze@kalesi.example'`,
		tenantA, "local:"+id.String()); n != 1 {
		t.Fatalf("%d person rows", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'session.start' AND actor = $2`,
		tenantA, "local:"+id.String()); n != 1 {
		t.Fatalf("%d sign-ins audited", n)
	}
	// An employee takes no administrator seat.
	if n := adminCount(t, `SELECT count(*) FROM tenant_admins WHERE tenant_id = $1 AND subject = $2 AND last_seen_at > now() - interval '1 day'`,
		tenantA, "local:"+id.String()); n != 0 {
		t.Fatal("an employee took a seat")
	}
}

// Every way a sign-in can fail before the second factor looks the same: an
// address with no account, a wrong password, a disabled account, one that
// was invited and never chose a password. What a stranger learns is
// nothing. The control --break-enumeration says something different for an
// address that has no account.
func TestEveryWayToFailASignInLooksTheSame(t *testing.T) {
	f := newLocalFixture(t)
	f.account(t, "active@kalesi.example", "Active", "employee", "active")
	f.account(t, "off@kalesi.example", "Off", "employee", "disabled")
	f.account(t, "new@kalesi.example", "New", "employee", "invited")

	normal := func(body, email string) string { return strings.ReplaceAll(body, email, "EMAIL") }
	var first string
	for i, c := range []struct{ email, pw string }{
		{"nobody@kalesi.example", localPassword},
		{"active@kalesi.example", "the-wrong-password-1"},
		{"off@kalesi.example", localPassword},
		{"new@kalesi.example", localPassword},
		{"new@kalesi.example", ""},
	} {
		b := f.browser(t)
		resp, body := b.signIn(c.email, c.pw)
		if resp.StatusCode != http.StatusUnauthorized || b.signedIn() || !atTheForm(body) {
			t.Fatalf("%s: %d (session %v)", c.email, resp.StatusCode, b.signedIn())
		}
		got := normal(body, c.email)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("%s: the answer differs from the one for an unknown address", c.email)
		}
	}
}

// Five wrong answers lock the account for fifteen minutes, and a locked
// account refuses even the right password: otherwise the lock tells a
// guesser nothing and the right answer during it tells them everything.
func TestFiveWrongPasswordsLockTheAccountEvenAgainstTheRightOne(t *testing.T) {
	f := newLocalFixture(t)
	id := f.account(t, "t.eze@kalesi.example", "T. Eze", "employee", "active")
	b := f.browser(t)
	for i := 0; i < 5; i++ {
		if _, body := b.signIn("t.eze@kalesi.example", "wrong-password-number-"+string(rune('a'+i))); !atTheForm(body) {
			t.Fatal("a wrong password did not return the form")
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM local_accounts WHERE id = $1 AND locked_until > now()`, id); n != 1 {
		t.Fatal("five wrong passwords did not lock the account")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'local.locked'`, tenantA); n != 1 {
		t.Fatalf("%d lock records", n)
	}
	b2 := f.browser(t)
	if _, body := b2.signIn("t.eze@kalesi.example", localPassword); b2.signedIn() || !atTheForm(body) {
		t.Fatal("the right password got through a locked account")
	}
	// Fifteen minutes on, it opens, and the count starts again.
	exec(t, `UPDATE local_accounts SET locked_until = now() - interval '1 minute' WHERE id = $1`, id)
	b3 := f.browser(t)
	if _, body := b3.signIn("t.eze@kalesi.example", localPassword); !b3.signedIn() || !strings.Contains(body, "Your devices") {
		t.Fatalf("the lock did not lift: %.300s", body)
	}
	if n := adminCount(t, `SELECT failed_count FROM local_accounts WHERE id = $1`, id); n != 0 {
		t.Fatalf("the failure count is %d after a good sign-in", n)
	}
}

// ------------------------------------------------------------ the second factor

// An administrator's password alone is half a sign-in. It ends in a cookie
// that is good for the second-factor page and nothing else; the session
// exists only after the code.
func TestAnAdministratorMustSetUpASecondStepAndThenNeedsItEveryTime(t *testing.T) {
	f := newLocalFixture(t)
	f.account(t, "o.martins@kalesi.example", "O. Martins", "it_admin", "active")

	b := f.browser(t)
	resp, page := b.signIn("o.martins@kalesi.example", localPassword)
	if resp.StatusCode != 200 || !strings.Contains(page, "Set up the second step") || !strings.Contains(page, "data:image/png;base64,") {
		t.Fatalf("an administrator was not sent to set up the second step (%d): %.500s", resp.StatusCode, page)
	}
	if b.signedIn() {
		t.Fatal("an administrator has a session before the second step")
	}
	// The half-signed-in cookie is no credential.
	if _, body := read(b, site+"/devices"); strings.Contains(body, "HQ-MBP-001") || !atTheForm(body) {
		t.Fatalf("the pending cookie opened the console:\n%.300s", body)
	}
	if _, body := read(b, site+"/api/devices"); strings.Contains(body, "HQ-MBP-001") {
		t.Fatal("the pending cookie opened the API")
	}

	// The same secret on a second look, so a refresh does not strand the
	// phone that has already scanned it.
	_, again := read(b, site+"/signin/local/enrol")
	secret := secretFrom(t, page)
	if string(secretFrom(t, again)) != string(secret) {
		t.Fatal("opening the enrolment page twice made two secrets")
	}
	// The secret is sealed in the table, not stored as it is.
	if n := adminCount(t, `SELECT count(*) FROM local_accounts WHERE totp_secret_sealed = $1`, secret); n != 0 {
		t.Fatal("the second-factor secret is stored unsealed")
	}

	// A wrong code does not turn it on; the right one does, signs in, and
	// shows the recovery codes once.
	if _, body := b.postForm(site+"/signin/local/enrol", url.Values{"code": {"000000"}}); !strings.Contains(body, "did not match") || b.signedIn() {
		t.Fatalf("a wrong code was taken: %.300s", body)
	}
	resp, codesPage := b.postForm(site+"/signin/local/enrol", url.Values{"code": {localauth.Code(secret, time.Now())}})
	if resp.StatusCode != 200 || !strings.Contains(codesPage, "Save your recovery codes") || !b.signedIn() {
		t.Fatalf("the second step did not finish the sign-in (%d): %.400s", resp.StatusCode, codesPage)
	}
	codes := recoveryCodes(t, codesPage)
	if len(codes) != 10 {
		t.Fatalf("%d recovery codes shown, want 10", len(codes))
	}
	if n := adminCount(t, `SELECT cardinality(recovery_hashes) FROM local_accounts WHERE email = 'o.martins@kalesi.example'`); n != 10 {
		t.Fatalf("%d recovery hashes kept", n)
	}
	for _, c := range codes {
		if n := adminCount(t, `SELECT count(*) FROM local_accounts WHERE $1 = ANY(recovery_hashes)`, c); n != 0 {
			t.Fatal("a recovery code is stored as it is")
		}
	}
	if _, dash := read(b, site+"/"); !strings.Contains(dash, "Dashboard") {
		t.Fatal("the new session does not reach the dashboard")
	}

	// Next time: password, then the code, and a code is good once.
	next := localauth.Code(secret, time.Now().Add(localauth.TOTPStep))
	b2 := f.browser(t)
	if _, body := b2.signIn("o.martins@kalesi.example", localPassword); !strings.Contains(body, "One more step") || b2.signedIn() {
		t.Fatalf("the password alone was enough: %.300s", body)
	}
	if _, body := b2.postForm(site+"/signin/local/mfa", url.Values{"code": {"123456"}}); !strings.Contains(body, "did not work") || b2.signedIn() {
		t.Fatalf("a wrong code was taken: %.300s", body)
	}
	// Wrong second-factor answers count toward the lock like wrong
	// passwords, and a good sign-in then clears the count.
	if n := adminCount(t, `SELECT failed_count FROM local_accounts WHERE email = 'o.martins@kalesi.example'`); n != 1 {
		t.Fatalf("a wrong second-factor answer was counted %d times, want 1", n)
	}
	if _, body := b2.postForm(site+"/signin/local/mfa", url.Values{"code": {next}}); !b2.signedIn() || !strings.Contains(body, "Dashboard") {
		t.Fatalf("the right code did not sign in: %.300s", body)
	}
	// The same code again, from somebody who watched it typed: refused.
	b3 := f.browser(t)
	b3.signIn("o.martins@kalesi.example", localPassword)
	if _, body := b3.postForm(site+"/signin/local/mfa", url.Values{"code": {next}}); b3.signedIn() || !strings.Contains(body, "did not work") {
		t.Fatal("a code was accepted twice")
	}
	// A recovery code stands in for the phone, once.
	b4 := f.browser(t)
	b4.signIn("o.martins@kalesi.example", localPassword)
	if _, body := b4.postForm(site+"/signin/local/mfa", url.Values{"code": {codes[0]}}); !b4.signedIn() || !strings.Contains(body, "Dashboard") {
		t.Fatalf("a recovery code did not sign in: %.300s", body)
	}
	b5 := f.browser(t)
	b5.signIn("o.martins@kalesi.example", localPassword)
	if _, body := b5.postForm(site+"/signin/local/mfa", url.Values{"code": {codes[0]}}); b5.signedIn() || !strings.Contains(body, "did not work") {
		t.Fatal("a recovery code worked twice")
	}
}

// Who must have the second factor is the tenant's to choose: the roles that
// can lock, wipe and approve, or everyone. The control --break-mfarequired
// lets an administrator in on a password alone.
func TestTheSecondFactorFollowsTheTenantsPolicy(t *testing.T) {
	f := newLocalFixture(t)
	f.account(t, "p.eneh@kalesi.example", "P. Eneh", "helpdesk", "active")

	b := f.browser(t)
	if _, body := b.signIn("p.eneh@kalesi.example", localPassword); !b.signedIn() || strings.Contains(body, "second step") {
		t.Fatalf("the help desk was held to a second step under the default policy: %.300s", body)
	}
	exec(t, `UPDATE tenant_identity SET local_mfa = 'everyone' WHERE tenant_id = $1`, tenantA)
	b2 := f.browser(t)
	if _, body := b2.signIn("p.eneh@kalesi.example", localPassword); b2.signedIn() || !strings.Contains(body, "Set up the second step") {
		t.Fatalf("the policy for everyone did not reach the help desk: %.300s", body)
	}
	// And an administrator is held to it under either policy.
	f.account(t, "s@kalesi.example", "S", "security_manager", "active")
	exec(t, `UPDATE tenant_identity SET local_mfa = 'admins' WHERE tenant_id = $1`, tenantA)
	b3 := f.browser(t)
	if _, body := b3.signIn("s@kalesi.example", localPassword); b3.signedIn() || !strings.Contains(body, "Set up the second step") {
		t.Fatalf("a security manager was not held to the second step: %.300s", body)
	}
}

// -------------------------------------------------------------- invitations

var acceptRE = regexp.MustCompile(`/signin/local/accept/([A-Za-z0-9_-]{43})`)
var resetRE = regexp.MustCompile(`/signin/local/reset/([A-Za-z0-9_-]{43})`)

func TestAnInvitationChoosesAPasswordOnceAndOnlyOnce(t *testing.T) {
	f := newLocalFixture(t)
	rec := postForm(t, f.fixture, "a-super", "/users/invite", url.Values{
		"email": {"Kemi.Adeleke@Kalesi.example"}, "name": {"Kemi Adeleke"}, "role": {"employee"}})
	m := acceptRE.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil {
		t.Fatalf("the invitation link was not shown (%d):\n%.600s", rec.Code, rec.Body.String())
	}
	token := m[1]
	if n := adminCount(t, `SELECT count(*) FROM local_tokens WHERE encode(token_hash, 'base64') LIKE $1`, token[:8]+"%"); n != 0 {
		t.Fatal("the link's token is stored as it is")
	}
	// Not shown again on the next load of the page.
	if _, page := getHTML(t, f.fixture, hostA, "/users", "a-super"); strings.Contains(page, token) {
		t.Fatal("the link is shown on the next page load")
	}
	if n := adminCount(t, `SELECT count(*) FROM local_accounts WHERE email = 'kemi.adeleke@kalesi.example' AND status = 'invited' AND password_hash = ''`); n != 1 {
		t.Fatal("the invited account is not waiting without a password")
	}

	b := f.browser(t)
	_, page := read(b, site+"/signin/local/accept/"+token)
	if !strings.Contains(page, "kemi.adeleke@kalesi.example") || !strings.Contains(page, "Set password") {
		t.Fatalf("the invitation page:\n%.500s", page)
	}
	link := site + "/signin/local/accept/" + token
	// A password the policy refuses does not cost the person their link.
	for _, bad := range []struct{ pw, confirm, want string }{
		{"short", "short", "at least 12"},
		{"passwordpassword", "passwordpassword", "first anyone tries"},
		{"kemi.adeleke-is-great-2026", "kemi.adeleke-is-great-2026", "name, address"},
		{localPassword, localPassword + "x", "not the same"},
	} {
		if resp, body := b.postForm(link, url.Values{"password": {bad.pw}, "confirm": {bad.confirm}}); resp.StatusCode != 422 || !strings.Contains(body, bad.want) {
			t.Fatalf("%q: %d, want 422 saying %q:\n%.400s", bad.pw, resp.StatusCode, bad.want, body)
		}
	}
	resp, body := b.postForm(link, url.Values{"password": {localPassword}, "confirm": {localPassword}})
	if resp.StatusCode != 200 || !strings.Contains(body, "Your password is set") || !atTheForm(body) {
		t.Fatalf("setting the password (%d): %.400s", resp.StatusCode, body)
	}
	// Spent. The same link, again: gone.
	if resp, body := b.postForm(link, url.Values{"password": {"another-good-passphrase-9"}, "confirm": {"another-good-passphrase-9"}}); resp.StatusCode != http.StatusGone {
		t.Fatalf("a spent invitation was taken again (%d): %.300s", resp.StatusCode, body)
	}
	if resp, _ := read(b, link); resp.StatusCode != http.StatusGone {
		t.Fatalf("a spent invitation page opened (%d)", resp.StatusCode)
	}
	// And the account signs in with the password they chose, not the second one.
	b2 := f.browser(t)
	if _, body := b2.signIn("kemi.adeleke@kalesi.example", localPassword); !b2.signedIn() {
		t.Fatalf("the new person could not sign in: %.300s", body)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action IN ('local.invited','local.password_set')`, tenantA); n != 2 {
		t.Fatalf("%d invitation records, want 2", n)
	}
}

// A link from one tenant is nothing at another's address.
func TestALinkFromOneTenantIsNothingAtAnother(t *testing.T) {
	f := newLocalFixture(t)
	rec := postForm(t, f.fixture, "a-super", "/users/invite", url.Values{
		"email": {"kemi@kalesi.example"}, "role": {"employee"}})
	token := acceptRE.FindStringSubmatch(rec.Body.String())[1]
	other := httptest.NewRequest("GET", "http://"+hostB+"/signin/local/accept/"+token, nil)
	other.Host = hostB
	other.Header.Set("Accept", "text/html")
	out := httptest.NewRecorder()
	f.h.ServeHTTP(out, other)
	if out.Code == 200 && strings.Contains(out.Body.String(), "Set password") {
		t.Fatal("a link opened at another tenant's hostname")
	}
}

func TestAResetLinkChangesThePasswordAndEndsEverySession(t *testing.T) {
	f := newLocalFixture(t)
	id := f.account(t, "t.eze@kalesi.example", "T. Eze", "employee", "active")

	old := f.browser(t)
	if _, body := old.signIn("t.eze@kalesi.example", localPassword); !old.signedIn() || !strings.Contains(body, "Your devices") {
		t.Fatal("setup: could not sign in")
	}
	rec := postForm(t, f.fixture, "a-super", "/users/"+id.String()+"/reset-link", url.Values{})
	m := resetRE.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("the reset link was not shown:\n%.500s", rec.Body.String())
	}
	b := f.browser(t)
	newPassword := "green-tin-river-moon-42"
	resp, body := b.postForm(site+"/signin/local/reset/"+m[1], url.Values{"password": {newPassword}, "confirm": {newPassword}})
	if resp.StatusCode != 200 || !strings.Contains(body, "signed out everywhere") {
		t.Fatalf("reset (%d): %.400s", resp.StatusCode, body)
	}
	// The session made with the old password is gone.
	if _, page := read(old, site+"/"); !atTheForm(page) {
		t.Fatalf("an old session survived a password reset:\n%.300s", page)
	}
	// The old password no longer works; the new one does.
	b2 := f.browser(t)
	if _, page := b2.signIn("t.eze@kalesi.example", localPassword); b2.signedIn() || !atTheForm(page) {
		t.Fatal("the old password still works")
	}
	b3 := f.browser(t)
	if _, page := b3.signIn("t.eze@kalesi.example", newPassword); !b3.signedIn() || !strings.Contains(page, "Your devices") {
		t.Fatalf("the new password does not work: %.300s", page)
	}
}

func TestForgottenPasswordSaysTheSameWhetherOrNotTheAddressExists(t *testing.T) {
	f := newLocalFixture(t)
	f.account(t, "t.eze@kalesi.example", "T. Eze", "employee", "active")
	before := len(f.mail.Received())

	ask := func(email string) string {
		b := f.browser(t)
		_, body := b.postForm(site+"/signin/local/forgot", url.Values{"email": {email}})
		return strings.ReplaceAll(body, email, "EMAIL")
	}
	known, unknown := ask("t.eze@kalesi.example"), ask("nobody@kalesi.example")
	if known != unknown || !strings.Contains(known, "If that address has an account here") {
		t.Fatalf("the two answers differ:\n--- known\n%.500s\n--- unknown\n%.500s", known, unknown)
	}
	// One mail, to the real address, with a link that works.
	var got []string
	for i := 0; i < 100; i++ {
		got = nil
		for _, m := range f.mail.Received()[before:] {
			got = append(got, strings.Join(m.To, ",")+"\n"+m.Data)
		}
		if len(got) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // long enough for a wrong second mail to arrive
	if len(f.mail.Received())-before != 1 {
		t.Fatalf("%d emails for one real address and one unknown", len(f.mail.Received())-before)
	}
	if !strings.HasPrefix(got[0], "t.eze@kalesi.example") || resetRE.FindStringSubmatch(got[0]) == nil {
		t.Fatalf("the email:\n%s", got[0])
	}
	// Asking again at once sends nothing: the form cannot fill an inbox.
	ask("t.eze@kalesi.example")
	time.Sleep(300 * time.Millisecond)
	if len(f.mail.Received())-before != 1 {
		t.Fatal("a second link was sent within the minute")
	}
}

// ----------------------------------------------------------- keeping people

func TestTheLastSuperAdminCannotBeRemoved(t *testing.T) {
	f := newLocalFixture(t)
	one := f.account(t, "one@kalesi.example", "One", "super_admin", "active")
	two := f.account(t, "two@kalesi.example", "Two", "super_admin", "active")

	said := func(rec *httptest.ResponseRecorder) string { return said(rec) }
	if s := said(postForm(t, f.fixture, "a-super", "/users/"+one.String()+"/disable", url.Values{})); s != "Done." {
		t.Fatalf("disabling one of two: %q", s)
	}
	if s := said(postForm(t, f.fixture, "a-super", "/users/"+two.String()+"/disable", url.Values{})); !strings.Contains(s, "nobody who can manage access") {
		t.Fatalf("disabling the last: %q", s)
	}
	if s := said(postForm(t, f.fixture, "a-super", "/users/"+two.String()+"/role", url.Values{"role": {"employee"}})); !strings.Contains(s, "nobody who can manage access") {
		t.Fatalf("demoting the last: %q", s)
	}
	if n := adminCount(t, `SELECT count(*) FROM local_accounts WHERE id = $1 AND role = 'super_admin' AND status = 'active'`, two); n != 1 {
		t.Fatal("the last super admin was changed anyway")
	}
	// Enabling the first makes the second removable.
	if s := said(postForm(t, f.fixture, "a-super", "/users/"+one.String()+"/enable", url.Values{})); s != "Done." {
		t.Fatalf("enabling: %q", s)
	}
	if s := said(postForm(t, f.fixture, "a-super", "/users/"+two.String()+"/role", url.Values{"role": {"employee"}})); s != "Done." {
		t.Fatalf("demoting one of two: %q", s)
	}
}

func TestDisablingAnAccountEndsItsSessionAndFreesItsSeat(t *testing.T) {
	f := newLocalFixture(t)
	id := f.account(t, "p.eneh@kalesi.example", "P. Eneh", "helpdesk", "active")
	b := f.browser(t)
	if _, body := b.signIn("p.eneh@kalesi.example", localPassword); !b.signedIn() || !strings.Contains(body, "Dashboard") {
		t.Fatalf("setup: %.300s", body)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_admins WHERE subject = $1 AND last_seen_at > now() - interval '1 day'`, "local:"+id.String()); n != 1 {
		t.Fatal("setup: the help desk took no seat")
	}
	if s := said(postForm(t, f.fixture, "a-super", "/users/"+id.String()+"/disable", url.Values{})); s != "Done." {
		t.Fatalf("disable: %q", s)
	}
	if _, page := read(b, site+"/devices"); !atTheForm(page) {
		t.Fatalf("a disabled account kept its session:\n%.300s", page)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_admins WHERE subject = $1 AND last_seen_at > now() - interval '1 day'`, "local:"+id.String()); n != 0 {
		t.Fatal("a disabled account still holds a seat")
	}
	b2 := f.browser(t)
	if _, page := b2.signIn("p.eneh@kalesi.example", localPassword); b2.signedIn() || !atTheForm(page) {
		t.Fatal("a disabled account signed in")
	}
	// Enabled again, with the password it had.
	postForm(t, f.fixture, "a-super", "/users/"+id.String()+"/enable", url.Values{})
	b3 := f.browser(t)
	if _, page := b3.signIn("p.eneh@kalesi.example", localPassword); !b3.signedIn() {
		t.Fatalf("an enabled account cannot sign in: %.300s", page)
	}
}

func TestAChangedRoleTakesEffectAtOnce(t *testing.T) {
	f := newLocalFixture(t)
	id := f.account(t, "p.eneh@kalesi.example", "P. Eneh", "helpdesk", "active")
	b := f.browser(t)
	b.signIn("p.eneh@kalesi.example", localPassword)
	if _, page := read(b, site+"/devices"); !strings.Contains(page, "HQ-MBP-001") {
		t.Fatal("setup: the help desk cannot see the fleet")
	}
	postForm(t, f.fixture, "a-super", "/users/"+id.String()+"/role", url.Values{"role": {"employee"}})
	// The old session, which carried the old role, is gone.
	if _, page := read(b, site+"/devices"); !atTheForm(page) {
		t.Fatal("a session kept the role it was made with")
	}
	b2 := f.browser(t)
	if _, page := b2.signIn("p.eneh@kalesi.example", localPassword); !strings.Contains(page, "Your devices") || strings.Contains(page, "HQ-MBP-001") {
		t.Fatalf("the new role is not the employee's: %.300s", page)
	}
}

func TestAnAddressAlreadyHereCannotBeInvitedAgain(t *testing.T) {
	f := newLocalFixture(t)
	f.account(t, "t.eze@kalesi.example", "T. Eze", "employee", "active")
	rec := postForm(t, f.fixture, "a-super", "/users/invite", url.Values{"email": {"T.Eze@kalesi.example"}, "role": {"employee"}})
	if !strings.Contains(said(rec), "already has an account") {
		t.Fatalf("a duplicate invitation: %q", said(rec))
	}
	for _, bad := range []string{"not-an-address", "a b@c.example", "kemi@kalesi.example\r\nBcc: x@evil.example", "Kemi <kemi@kalesi.example>", ""} {
		rec := postForm(t, f.fixture, "a-super", "/users/invite", url.Values{"email": {bad}, "role": {"employee"}})
		if !strings.Contains(said(rec), "not an email address") {
			t.Fatalf("%q: %q", bad, said(rec))
		}
	}
	rec = postForm(t, f.fixture, "a-super", "/users/invite", url.Values{"email": {"k@kalesi.example"}, "role": {"emperor"}})
	if !strings.Contains(said(rec), "not a role") {
		t.Fatalf("a made-up role: %q", said(rec))
	}
}

func TestTheUsersPageIsASuperAdminsAlone(t *testing.T) {
	f := newLocalFixture(t)
	for _, who := range []string{"a-itadmin", "a-helpdesk", "a-auditor", "a-employee", "a-secmgr"} {
		if rec, _ := getHTML(t, f.fixture, hostA, "/users", who); rec.Code != http.StatusForbidden {
			t.Fatalf("%s opened the Users page: %d", who, rec.Code)
		}
		rec := postForm(t, f.fixture, who, "/users/invite", url.Values{"email": {"x@kalesi.example"}, "role": {"super_admin"}})
		if !strings.Contains(said(rec), "may not") {
			t.Fatalf("%s invited someone: %q", who, said(rec))
		}
	}
	rec, page := getHTML(t, f.fixture, hostA, "/users", "a-super")
	if rec.Code != 200 || !strings.Contains(page, "Invite someone") {
		t.Fatalf("a super admin cannot open it: %d", rec.Code)
	}
	// And the menu says so: Users for the Super Admin, not for the IT admin.
	if !strings.Contains(page, `href="/users"`) {
		t.Fatal("the Super Admin's menu has no Users entry")
	}
	if _, it := getHTML(t, f.fixture, hostA, "/devices", "a-itadmin"); strings.Contains(it, `href="/users"`) {
		t.Fatal("the IT admin's menu shows Users")
	}
}

// ----------------------------------------------------------------- the account

func TestAPersonChangesTheirOwnPassword(t *testing.T) {
	f := newLocalFixture(t)
	f.account(t, "t.eze@kalesi.example", "T. Eze", "employee", "active")
	b := f.browser(t)
	b.signIn("t.eze@kalesi.example", localPassword)
	other := f.browser(t)
	other.signIn("t.eze@kalesi.example", localPassword)

	_, page := read(b, site+"/account")
	if !strings.Contains(page, "Change your password") || !strings.Contains(page, "t.eze@kalesi.example") {
		t.Fatalf("the account page:\n%.500s", page)
	}
	cs := func(vals url.Values) string {
		sess, err := f.sessions.Verify(b.sessionCookie("mdm.kalesi.example"))
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		vals.Set("csrf", f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role))
		_, body := b.postForm(site+"/account/password", vals)
		return body
	}
	next := "green-tin-river-moon-42"
	if body := cs(url.Values{"current": {"not-it-at-all-1234"}, "password": {next}, "confirm": {next}}); !strings.Contains(body, "current password is not right") {
		t.Fatalf("a wrong current password: %.400s", body)
	}
	if body := cs(url.Values{"current": {localPassword}, "password": {"short"}, "confirm": {"short"}}); !strings.Contains(body, "at least 12") {
		t.Fatalf("a short new password: %.400s", body)
	}
	if body := cs(url.Values{"current": {localPassword}, "password": {next}, "confirm": {next}}); !strings.Contains(body, "Password changed") {
		t.Fatalf("the change: %.400s", body)
	}
	// This browser is still signed in; the other one, which had the old
	// password's session, is not.
	if _, p := read(b, site+"/account"); !strings.Contains(p, "Change your password") {
		t.Fatal("the browser that changed it was signed out")
	}
	if _, p := read(other, site+"/"); !atTheForm(p) {
		t.Fatal("another session survived a password change")
	}
	b2 := f.browser(t)
	if b2.signIn("t.eze@kalesi.example", next); !b2.signedIn() {
		t.Fatal("the new password does not sign in")
	}
}

// ------------------------------------------------------------------ the modes

// A tenant with an identity provider takes its people from there. A local
// account it happens to hold does not sign in: it would be a way round the
// provider's own controls. The control --break-localprotocol takes the
// password at any tenant.
func TestATenantWithAnIdentityProviderDoesNotSignInWithAPassword(t *testing.T) {
	f := newFixture(t)
	exec(t, `INSERT INTO tenant_identity (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim, protocol)
	         VALUES ($1, 'https://login.example/kalesi', 'c', ''::bytea, 'http://mdm.kalesi.example/signin/callback', 'groups', 'oidc')`, tenantA)
	exec(t, `INSERT INTO local_accounts (tenant_id, email, name, role, status, password_hash, password_set_at, created_by)
	         VALUES ($1, 'o@kalesi.example', 'O', 'employee', 'active', $2, now(), 'test')`, tenantA, passwordHash(t))
	srv := httptest.NewServer(f.g.Handler())
	defer srv.Close()
	b := newBrowser(t, srv.Listener.Addr().String())
	resp, body := b.postForm(site+"/signin/local", url.Values{"email": {"o@kalesi.example"}, "password": {localPassword}})
	if resp.StatusCode != http.StatusNotFound || b.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatalf("a password signed in at an identity-provider tenant (%d): %.300s", resp.StatusCode, body)
	}
}

func TestTheOIDCCallbackRefusesALocalTenant(t *testing.T) {
	f := newLocalFixture(t)
	b := f.browser(t)
	resp, _ := read(b, site+"/signin/callback?code=x&state=y")
	if resp.StatusCode == 200 || b.signedIn() {
		t.Fatalf("the OIDC callback did something at a local tenant (%d)", resp.StatusCode)
	}
}

// Leaving local sign-in for an identity provider must not strand the tenant:
// nobody can sign in with a password afterwards, so a group has to be mapped
// to Super Admin first.
func TestAnIdentityProviderCannotReplaceLocalSignInUntilAGroupIsMapped(t *testing.T) {
	f := newLocalFixture(t)
	save := func(secret string) string {
		return said(postForm(t, f.fixture, "a-super", "/identity", url.Values{
			"protocol": {"oidc"}, "issuer": {"https://login.example/kalesi"}, "client_id": {"c"},
			"client_secret": {secret}, "role_claim": {"groups"}}))
	}
	if s := save(""); !strings.Contains(s, "client secret") {
		t.Fatalf("no secret: %q", s)
	}
	if s := save("s3cret"); !strings.Contains(s, "Map a group to Super Admin") {
		t.Fatalf("no admin mapping: %q", s)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_identity WHERE tenant_id = $1 AND protocol = 'local'`, tenantA); n != 1 {
		t.Fatal("the tenant was switched anyway")
	}
	exec(t, `INSERT INTO tenant_role_map (tenant_id, claim_value, role) VALUES ($1, 'MDM-Owners', 'super_admin')`, tenantA)
	if s := save("s3cret"); !strings.Contains(s, "Saved") {
		t.Fatalf("with a mapping: %q", s)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_identity WHERE tenant_id = $1 AND protocol = 'oidc'`, tenantA); n != 1 {
		t.Fatal("the tenant did not switch")
	}
}

// ------------------------------------------------------------------ signing up

func TestSignUpWithNoIdentityProviderMakesTheSignerTheFirstAdministrator(t *testing.T) {
	f := withSignup(t, newFixture(t))
	exec(t, `DELETE FROM local_tokens WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'su-%')`)
	exec(t, `DELETE FROM local_accounts WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'su-%')`)

	token := askFor(t, f, "Ada@Arbor-Foods.example", "Arbor Foods", "203.0.113.10")
	if rec := public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.10", url.Values{"slug": {"su-local"}}); rec.Code != 303 {
		t.Fatalf("slug: %d", rec.Code)
	}
	page := public(t, f, "GET", signupHost, "/signup/"+token, "203.0.113.10", nil).Body.String()
	if !strings.Contains(page, "I do not have one") || !strings.Contains(page, "ada@arbor-foods.example") {
		t.Fatalf("the sign-up page does not offer the no-provider path:\n%.800s", page)
	}
	// A weak password is refused without creating anything.
	rec := public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.10", url.Values{
		"mode": {"local"}, "name": {"Ada Obi"}, "password": {"short"}, "confirm": {"short"}})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "at+least+12") {
		t.Fatalf("a weak password: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if n := adminCount(t, `SELECT count(*) FROM tenants WHERE slug = 'su-local'`); n != 0 {
		t.Fatal("a tenant was made with a refused password")
	}
	pw := "orange-kettle-garden-77"
	rec = public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.10", url.Values{
		"mode": {"local"}, "name": {"Ada Obi"}, "password": {pw}, "confirm": {pw}})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "/done?how=local") {
		t.Fatalf("finish: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	done := public(t, f, "GET", signupHost, "/signup/"+token+"/done?how=local", "203.0.113.10", nil).Body.String()
	if !strings.Contains(done, "ada@arbor-foods.example") || !strings.Contains(done, "authenticator app") {
		t.Fatalf("the done page:\n%.600s", done)
	}
	// One active Super Admin, the signer, with a hash and no role map.
	if n := adminCount(t, `SELECT count(*) FROM local_accounts a JOIN tenants t ON t.id = a.tenant_id
	                        WHERE t.slug = 'su-local' AND a.email = 'ada@arbor-foods.example' AND a.role = 'super_admin'
	                          AND a.status = 'active' AND a.password_hash LIKE '$argon2id$%' AND a.name = 'Ada Obi'`); n != 1 {
		t.Fatal("the signer is not the first administrator")
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_role_map m JOIN tenants t ON t.id = m.tenant_id WHERE t.slug = 'su-local'`); n != 0 {
		t.Fatal("a local tenant has a role map")
	}
	got := f.mail.Received()
	welcome := got[len(got)-1]
	if !strings.Contains(welcome.Data, "password you chose") || strings.Contains(welcome.Data, "identity provider") {
		t.Fatalf("the welcome:\n%s", welcome.Data)
	}
	// And they can sign in on the new host: the password, then the
	// second-factor set-up their role needs.
	rec = public(t, f, "POST", "su-local.mdm.example", "/signin/local", "203.0.113.10",
		url.Values{"email": {"ada@arbor-foods.example"}, "password": {pw}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/signin/local/enrol" {
		t.Fatalf("the new administrator's first sign-in: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}
