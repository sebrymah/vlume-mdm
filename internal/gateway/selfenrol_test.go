package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"platform/internal/authz"
	"platform/internal/qr/qrtest"
	"platform/internal/session"
)

// Self-service enrolment (0045): one link for everybody, a code for your own
// phone. Every rule that makes that safe is a test here and a control in
// run_go.sh.

const desktopUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
const phoneUA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36"

// asPerson is a request from somebody signed in with an address, the way a
// real sign-in leaves them. (A dev bearer token has no address, and a
// session made from one is the "cannot tell who you are" case below.)
func (f fixture) asPerson(t *testing.T, method, host, path string, tenant [16]byte, subject string, role authz.Role,
	email string, vals url.Values, ua string) *httptest.ResponseRecorder {
	t.Helper()
	tok, _, err := f.sessions.Start(session.Session{TenantID: tenant, Subject: subject, Role: string(role), Email: email})
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	return f.send(t, method, host, path, tok, tenant, subject, role, vals, ua)
}

func (f fixture) send(t *testing.T, method, host, path, cookie string, tenant [16]byte, subject string,
	role authz.Role, vals url.Values, ua string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if vals != nil {
		vals.Set("csrf", f.g.csrfFor(tenant, subject, string(role)))
		body = strings.NewReader(vals.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "http://"+host+path, body)
	r.Host = host
	if vals != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

func selfStart(t *testing.T, f fixture, vals url.Values, ua string) *httptest.ResponseRecorder {
	return f.asPerson(t, "POST", hostA, "/enrol/start", tenantA, "t.eze", authz.Employee, "t.eze@kalesi.example", vals, ua)
}

func setSelfMode(t *testing.T, f fixture, mode string) {
	t.Helper()
	rec := postForm(t, f, "a-itadmin", "/android/self-enrol", url.Values{"mode": {mode}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "Saved") {
		t.Fatalf("setting %q: %d %q", mode, rec.Code, said(rec))
	}
}

func selfReady(t *testing.T) fixture {
	t.Helper()
	f := newFixture(t)
	baseline(t, f)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}
	return f
}

func TestSelfEnrolmentIsOffUntilAnAdministratorTurnsItOn(t *testing.T) {
	f := selfReady(t)
	issued := len(f.google.TokenUsage)

	// The page says so, in words.
	rec := f.asPerson(t, "GET", hostA, "/enrol", tenantA, "t.eze", authz.Employee, "t.eze@kalesi.example", nil, desktopUA)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "has not turned this on") {
		t.Fatalf("the page when off: %d\n%.400s", rec.Code, rec.Body.String())
	}
	// There is no menu entry to lead to it.
	me := f.asPerson(t, "GET", hostA, "/me", tenantA, "t.eze", authz.Employee, "t.eze@kalesi.example", nil, desktopUA)
	if strings.Contains(me.Body.String(), `href="/enrol"`) {
		t.Fatal("the menu offers Enrol my phone while it is off")
	}
	// And asking anyway makes nothing and asks Google for nothing.
	rec = selfStart(t, f, url.Values{"label": {"x"}}, desktopUA)
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "has not turned this on") {
		t.Fatalf("asking while off: %d %q", rec.Code, said(rec))
	}
	if len(f.google.TokenUsage) != issued {
		t.Fatal("Google was asked for a token while self-enrolment was off")
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE source = 'self'`); n != 0 {
		t.Fatalf("%d self-service tokens were recorded while it was off", n)
	}

	// Turned on, the entry appears.
	setSelfMode(t, f, "personal")
	me = f.asPerson(t, "GET", hostA, "/me", tenantA, "t.eze", authz.Employee, "t.eze@kalesi.example", nil, desktopUA)
	if !strings.Contains(me.Body.String(), `href="/enrol"`) {
		t.Fatal("the menu does not offer Enrol my phone once it is on")
	}
	// A person who is not signed in is sent to sign in and brought back.
	r := httptest.NewRequest("GET", "http://"+hostA+"/enrol", nil)
	r.Host = hostA
	r.Header.Set("Accept", "text/html")
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/signin?next=") {
		t.Fatalf("a stranger at the link: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOnlyAnAdministratorMayTurnSelfEnrolmentOn(t *testing.T) {
	f := selfReady(t)
	for _, who := range []string{"a-employee", "a-helpdesk", "a-auditor", "a-secmgr"} {
		rec := postForm(t, f, who, "/android/self-enrol", url.Values{"mode": {"personal"}})
		if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "may not do that") {
			t.Fatalf("%s: %d %q", who, rec.Code, said(rec))
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_enrolment WHERE self_enrol <> 'off'`); n != 0 {
		t.Fatal("a role that may not, turned it on")
	}
	if rec := postForm(t, f, "a-itadmin", "/android/self-enrol", url.Values{"mode": {"everyone"}}); !strings.Contains(said(rec), "not one of the choices") {
		t.Fatalf("a made-up setting: %q", said(rec))
	}
	setSelfMode(t, f, "any")
	if n := adminCount(t, `SELECT count(*) FROM tenant_enrolment WHERE self_enrol = 'any' AND updated_by = 'o.martins'`); n != 1 {
		t.Fatal("the setting, or who made it, was not recorded")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE action = 'android.self_enrol_mode'`); n != 1 {
		t.Fatal("the change was not audited")
	}
	// The administrator's page shows the one link to send everybody.
	page := f.asPerson(t, "GET", hostA, "/android", tenantA, "o.martins", authz.ITAdmin, "o.martins@kalesi.example", nil, desktopUA)
	if !strings.Contains(page.Body.String(), "https://"+hostA+"/enrol") {
		t.Fatalf("the Android page does not show the link to send:\n%.300s", page.Body.String())
	}
}

func TestACodeIsForTheSignedInPersonAndNobodyElse(t *testing.T) {
	f := selfReady(t)
	setSelfMode(t, f, "personal")
	issued := len(f.google.TokenUsage)

	// The person tries to name somebody else, and to ask for a company phone.
	rec := selfStart(t, f, url.Values{
		"label": {"Tolu's phone\r\nBcc: x@evil.example"}, "assigned_to": {"ceo@kalesi.example"}, "ownership": {"company"}}, desktopUA)
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("the code page: %d %q", rec.Code, said(rec))
	}
	if len(f.google.TokenUsage) != issued+1 {
		t.Fatalf("%d tokens issued, want 1", len(f.google.TokenUsage)-issued)
	}
	// Whose it is comes from the session: the address typed in the form is ignored.
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens
		WHERE source = 'self' AND assigned_to = 't.eze@kalesi.example' AND created_by = 't.eze' AND ownership = 'personal'`); n != 1 {
		t.Fatalf("the token is not recorded as this person's own, personal phone (%d)", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE assigned_to LIKE 'ceo@%'`); n != 0 {
		t.Fatal("a code was made for an address the person typed")
	}
	// The label cannot carry a line break into the table or the audit log.
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE label LIKE E'%\n%' OR label LIKE E'%\r%'`); n != 0 {
		t.Fatal("a line break reached the label")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE action = 'android.self_enrol_started'`); n != 1 {
		t.Fatal("the request was not audited")
	}
	// The picture scans to Google's link for a personal phone.
	imgs := qrtest.PageImages(body)
	if len(imgs) != 1 {
		t.Fatalf("%d QR codes on the page, want 1", len(imgs))
	}
	got := qrtest.ScanDataURL(t, imgs[0])
	if !strings.HasPrefix(got, "https://enterprise.google.com/android/enroll?et=") {
		t.Fatalf("the QR code scans to %q", got)
	}
	if strings.Contains(body, "Enrol this phone") {
		t.Fatal("a desktop browser was offered the phone-only button")
	}
	if !strings.Contains(body, "stops working at") {
		t.Fatal("the page does not say when the code stops working")
	}

	// On the phone itself the way in is a button, not a picture to scan.
	rec = selfStart(t, f, url.Values{}, phoneUA)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Enrol this phone") {
		t.Fatalf("a phone was not offered the button: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `href="https://enterprise.google.com/android/enroll?et=`) {
		t.Fatal("the button does not lead to Google's link")
	}
}

func TestOnlyWhenTheOrganisationAllowsItCanAPersonAskForACompanyPhone(t *testing.T) {
	f := selfReady(t)
	setSelfMode(t, f, "any")
	rec := selfStart(t, f, url.Values{"ownership": {"company"}}, desktopUA)
	imgs := qrtest.PageImages(rec.Body.String())
	if rec.Code != 200 || len(imgs) != 1 {
		t.Fatalf("company phone: %d, %d QR codes", rec.Code, len(imgs))
	}
	got := qrtest.ScanDataURL(t, imgs[0])
	var payload map[string]any
	if err := json.Unmarshal([]byte(got), &payload); err != nil {
		t.Fatalf("a company phone's code is not Google's provisioning payload: %q", got)
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE source = 'self' AND ownership = 'company'`); n != 1 {
		t.Fatal("the company phone was not recorded as one")
	}
	if !strings.Contains(rec.Body.String(), "six times") {
		t.Fatal("the page does not tell the person to tap six times")
	}

	// In personal mode the same request gets a personal phone.
	setSelfMode(t, f, "personal")
	rec = selfStart(t, f, url.Values{"ownership": {"company"}}, desktopUA)
	if rec.Code != 200 {
		t.Fatalf("personal mode: %d", rec.Code)
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE source = 'self' AND ownership = 'company'`); n != 1 {
		t.Fatalf("in personal mode a person got a second company phone (%d)", n)
	}
}

func TestAPersonGetsFiveCodesADayAndNoMore(t *testing.T) {
	f := selfReady(t)
	setSelfMode(t, f, "personal")
	issued := len(f.google.TokenUsage)
	for i := 0; i < 5; i++ {
		if rec := selfStart(t, f, url.Values{}, desktopUA); rec.Code != 200 {
			t.Fatalf("code %d: %d %q", i+1, rec.Code, said(rec))
		}
	}
	rec := selfStart(t, f, url.Values{}, desktopUA)
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "several codes today") {
		t.Fatalf("the sixth: %d %q", rec.Code, said(rec))
	}
	if got := len(f.google.TokenUsage) - issued; got != 5 {
		t.Fatalf("Google issued %d tokens, want 5", got)
	}
	// The limit is per person, not for the whole organisation.
	rec = f.asPerson(t, "POST", hostA, "/enrol/start", tenantA, "r.chukwu", authz.Auditor, "r.chukwu@kalesi.example", url.Values{}, desktopUA)
	if rec.Code != 200 {
		t.Fatalf("a second person was stopped by the first's limit: %d %q", rec.Code, said(rec))
	}
}

func TestSomeoneWhoHasLeftCannotEnrolAPhone(t *testing.T) {
	f := selfReady(t)
	setSelfMode(t, f, "personal")
	exec(t, `INSERT INTO people (tenant_id, subject, email, source, left_at, left_by)
	         VALUES ($1, 'z.leaver', 'z.leaver@kalesi.example', 'hr', now(), 'hr-feed')`, tenantA)
	issued := len(f.google.TokenUsage)
	rec := f.asPerson(t, "POST", hostA, "/enrol/start", tenantA, "z.leaver", authz.Employee, "z.leaver@kalesi.example", url.Values{}, desktopUA)
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "account has been closed") {
		t.Fatalf("a leaver: %d %q", rec.Code, said(rec))
	}
	if len(f.google.TokenUsage) != issued {
		t.Fatal("Google was asked for a token for somebody who has left")
	}
	// The next hire who is given the same address is not the leaver.
	rec = f.asPerson(t, "POST", hostA, "/enrol/start", tenantA, "n.newhire", authz.Employee, "z.leaver@kalesi.example", url.Values{}, desktopUA)
	if rec.Code != 200 {
		t.Fatalf("the next hire with a reused address was refused: %d %q", rec.Code, said(rec))
	}

	// HR can name somebody who never signed in: a record with an address and
	// no subject. Whoever then signs in with that address is refused, because
	// the record cannot say whether it is the leaver or a later hire, and the
	// cautious reading is the one that keeps a leaver's phone out.
	exec(t, `INSERT INTO people (tenant_id, subject, email, source, left_at, left_by)
	         VALUES ($1, '', 'y.never@kalesi.example', 'hr', now(), 'hr-feed')`, tenantA)
	issued = len(f.google.TokenUsage)
	rec = f.asPerson(t, "POST", hostA, "/enrol/start", tenantA, "y.never", authz.Employee, "Y.Never@kalesi.example", url.Values{}, desktopUA)
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "account has been closed") {
		t.Fatalf("a leaver HR named before they ever signed in: %d %q", rec.Code, said(rec))
	}
	if len(f.google.TokenUsage) != issued {
		t.Fatal("Google was asked for a token for a leaver known only by address")
	}
}

func TestWithNoAddressThereIsNoCode(t *testing.T) {
	f := selfReady(t)
	setSelfMode(t, f, "personal")
	issued := len(f.google.TokenUsage)
	rec := f.asPerson(t, "POST", hostA, "/enrol/start", tenantA, "t.eze", authz.Employee, "", url.Values{"assigned_to": {"x@kalesi.example"}}, desktopUA)
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "cannot tell which address is yours") {
		t.Fatalf("no address: %d %q", rec.Code, said(rec))
	}
	if len(f.google.TokenUsage) != issued {
		t.Fatal("a token was made for somebody with no address")
	}
}

func TestOneOrganisationsSettingIsNotAnothers(t *testing.T) {
	f := selfReady(t)
	setSelfMode(t, f, "personal")
	// Arbor never turned it on. Its people are refused, whatever Kalesi did.
	rec := f.asPerson(t, "POST", hostB, "/enrol/start", tenantB, "j.okafor", authz.ITAdmin, "j.okafor@arbor.example", url.Values{}, desktopUA)
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "has not turned this on") {
		t.Fatalf("the other organisation: %d %q", rec.Code, said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE tenant_id = $1`, tenantB); n != 0 {
		t.Fatal("a token was made in the organisation that had not turned it on")
	}
}
