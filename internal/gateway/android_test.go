package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/android"
	"platform/internal/qr/qrtest"
)

// Android Enterprise, end to end against the fake Google: bind, deliver the
// policy, hand out a token, a phone enrols, sync judges it, a command goes
// through Google, and the binding is the one this person started.

// bindAndroid walks the round trip as the Super Admin: press Bind, follow
// Google, come back, and read the callback's answer.
func bindAndroid(t *testing.T, f fixture, bearer string) string {
	t.Helper()
	cookie := f.cookie(t, bearer)
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	csrf := f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)

	// 1. Bind: a redirect to Google and a state cookie.
	r := httptest.NewRequest("POST", "http://"+hostA+"/android/bind",
		strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/fake-signin") {
		return "bind did not send to Google: " + said(rec)
	}
	var state *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == androidBindCookie {
			state = c
		}
	}
	if state == nil {
		return "bind set no state cookie"
	}

	// 2. Google: the fake signs in and redirects to our callback. The
	// redirect is read, not followed: our host is not on the network.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.Get(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("fake google: %v", err)
	}
	resp.Body.Close()
	cb := resp.Header.Get("Location")
	if !strings.Contains(cb, "/android/callback?enterpriseToken=") {
		t.Fatalf("Google did not send us back: %d %s", resp.StatusCode, cb)
	}
	u, _ := url.Parse(cb)

	// 3. Back here, with the state cookie.
	r = httptest.NewRequest("GET", "http://"+hostA+"/android/callback?"+u.RawQuery, nil)
	r.Host = hostA
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	r.AddCookie(&http.Cookie{Name: androidBindCookie, Value: state.Value})
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return said(rec)
}

func TestATenantBindsItsOwnEnterpriseAndThePolicyGoesWithIt(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)

	msg := bindAndroid(t, f, "a-super")
	if !strings.Contains(msg, "Bound to enterprises/") {
		t.Fatalf("bind: %q", msg)
	}
	// The policy was delivered at binding, as Google's JSON, and the one
	// rule Google cannot enforce was named rather than dropped.
	if !strings.Contains(msg, "Your Android policy has been delivered") {
		t.Fatalf("no policy delivered at binding: %q", msg)
	}
	var delivered int
	for key, p := range f.google.Policies {
		if strings.HasSuffix(key, "/policies/default") {
			delivered++
			if p.PasswordRequirements == nil || p.PasswordRequirements.PasswordMinimumLength != 8 ||
				p.EncryptionPolicy != "ENABLED_WITH_PASSWORD" {
				t.Fatalf("the delivered policy does not carry the baseline: %+v", p)
			}
		}
	}
	if delivered != 1 {
		t.Fatalf("%d policies delivered", delivered)
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enterprises WHERE tenant_id = $1`, tenantA); n != 1 {
		t.Fatal("the binding was not recorded")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'android.bound'`, tenantA); n != 1 {
		t.Fatal("the binding was not audited")
	}
	// Saving a policy with a rule Google cannot enforce says so.
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Phones", "os_family": "android",
		"rules": map[string]any{"os_version_min": "14.0", "jailbreak_blocked": true, "passcode_required": true},
	})
	if code != http.StatusCreated {
		t.Fatalf("policy: %d %v", code, body)
	}
	judged, _ := body["android_judged_only"].([]any)
	if len(judged) != 2 {
		t.Fatalf("the rules Google cannot enforce were not named: %v", body)
	}
	// Binding twice is refused.
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "already has") {
		t.Fatalf("bound twice: %q", msg)
	}
	// Only a Super Admin binds.
	if msg := bindAndroid(t, f, "a-itadmin"); !strings.Contains(msg, "may not") {
		t.Fatalf("an IT admin bound an enterprise: %q", msg)
	}
}

func TestACallbackNobodyHereStartedBindsNothing(t *testing.T) {
	f := newFixture(t)
	// A signup URL Google issued to somebody, and its token, arriving at
	// our callback with no binding in progress on this session.
	su, err := f.g.android.CreateSignupURL(context.Background(), "https://elsewhere.example/cb")
	if err != nil {
		t.Fatalf("signup url: %v", err)
	}
	token := f.google.EnterpriseToken(su.Name)
	rec, _ := getHTML(t, f, hostA, "/android/callback?enterpriseToken="+url.QueryEscape(token)+
		"&signup="+url.QueryEscape(su.Name), "a-super")
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "not started from here") {
		t.Fatalf("a stray callback: %d %q", rec.Code, said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enterprises WHERE tenant_id = $1`, tenantA); n != 0 {
		t.Fatal("a callback nobody started bound an enterprise")
	}
}

var androidTokenRE = regexp.MustCompile(`letter-spacing:\.08em[^>]*>([A-Z0-9]{16,})<`)

func TestAPhoneEnrolsIsSyncedAndJudged(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}

	// A token, for a named person, shown once on the page.
	cookie := f.cookie(t, "a-itadmin")
	sess, _ := f.sessions.Verify(cookie)
	vals := url.Values{"label": {"Kemi's phone"}, "assigned_to": {"kemi@kalesi.example"},
		"ownership": {"personal"}, "csrf": {f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)}}
	r := httptest.NewRequest("POST", "http://"+hostA+"/android/tokens", strings.NewReader(vals.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	m := androidTokenRE.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil {
		t.Fatalf("token page: %d\n%s", rec.Code, rec.Body.String())
	}
	token := m[1]
	if n := adminCount(t, `SELECT count(*) FROM android_enrollment_tokens WHERE tenant_id = $1 AND assigned_to = 'kemi@kalesi.example'`, tenantA); n != 1 {
		t.Fatal("the token was not recorded with who it is for")
	}

	// A personal device's token asks Google for a work profile; a company
	// one does not (F2, F10).
	var personal, company int
	for _, usage := range f.google.TokenUsage {
		switch usage {
		case "PERSONAL_USAGE_ALLOWED":
			personal++
		case "PERSONAL_USAGE_DISALLOWED":
			company++
		}
	}
	if personal != 1 || company != 0 {
		t.Fatalf("token usage: %v", f.google.TokenUsage)
	}

	// The phone enrols at Google with it: secure, encrypted, Android 15.
	name := f.google.Enrol(token, "PHONE-0001", "Pixel 8a", "15", true, true)
	if name == "" {
		t.Fatal("the fake Google did not accept the token")
	}
	// A sync makes it ours, on Kemi's page, and judges it: compliant.
	rec2, body := do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin"))
	if rec2.Code != 200 || body["created"] != float64(1) || body["judged"] != float64(1) {
		t.Fatalf("sync: %d %v", rec2.Code, body)
	}
	dev := adminUUID(t, `SELECT id FROM devices WHERE tenant_id = $1 AND android_name = $2`, tenantA, name)
	_, d := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "compliant" || d["os_family"] != "android" ||
		d["ownership"] != "personal" || d["name"] != "Kemi's phone" {
		t.Fatalf("the synced device: %v", d)
	}
	if n := adminCount(t, `SELECT count(*) FROM devices WHERE id = $1 AND assigned_to = 'kemi@kalesi.example'`, dev); n != 1 {
		t.Fatal("the phone is not on Kemi's page")
	}
	// The phone drops its screen lock; the next sync judges it again, and
	// a second sync creates nothing new.
	f.google.Report(name, false, true, "15")
	rec2, body = do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin"))
	if rec2.Code != 200 || body["created"] != float64(0) {
		t.Fatalf("second sync: %d %v", rec2.Code, body)
	}
	_, d = do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "not_compliant" {
		t.Fatalf("after losing its screen lock the phone is %v", d["state"])
	}

	// Commands go through Google and are done when Google says so.
	rec2, body = do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/lock", "a-itadmin",
		map[string]any{"reason": "Left in a taxi"}))
	if rec2.Code >= 300 {
		t.Fatalf("lock: %d %v", rec2.Code, body)
	}
	if got := f.google.Commands[name]; len(got) != 1 || got[0] != "LOCK" {
		t.Fatalf("Google was asked %v", got)
	}
	if body["state"] != "acknowledged" {
		t.Fatalf("a command Google carried out is %v, want acknowledged", body["state"])
	}
	// A selective wipe takes the work profile and leaves the person's own
	// data: no full-wipe flags.
	rec2, body = do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		map[string]any{"reason": "Leaving on Friday", "scope": "selective"}))
	if rec2.Code >= 300 {
		t.Fatalf("selective wipe: %d %v", rec2.Code, body)
	}
	flags, wiped := f.google.Wipes[name]
	if !wiped {
		t.Fatalf("Google was not asked to wipe: %v", f.google.Calls)
	}
	for _, fl := range flags {
		if fl == "WIPE_EXTERNAL_STORAGE" {
			t.Fatal("a selective wipe carried the full-wipe flag")
		}
	}
}

// Lost mode goes through Google, and the lock screen says who the phone
// belongs to: the tenant, never the platform.
func TestLostModeOnAnAndroidPhoneShowsTheTenantsName(t *testing.T) {
	f := newFixture(t)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}
	ent := adminString(t, `SELECT name FROM android_enterprises WHERE tenant_id = $1`, tenantA)
	tok, err := f.g.android.CreateEnrollmentToken(context.Background(), ent,
		android.TokenInput{PolicyName: ent + "/policies/default", OneTime: true})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	name := f.google.Enrol(tok.Value, "PHONE-0002", "Pixel 8a", "15", true, true)
	if rec, body := do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin")); rec.Code != 200 {
		t.Fatalf("sync: %d %v", rec.Code, body)
	}
	dev := adminUUID(t, `SELECT id FROM devices WHERE tenant_id = $1 AND android_name = $2`, tenantA, name)

	// Who a finder should call is part of the brand. An undialable
	// number is refused; a good one is kept.
	if rec := postForm(t, f, "a-itadmin", "/branding", url.Values{
		"product_name": {"Kalesi Device Care"}, "colour": {"#0F6E66"}, "mark_letter": {"K"},
		"lost_phone": {"call me maybe"}, "lost_email": {"itdesk@kalesi.example"},
	}); !strings.Contains(said(rec), "Not saved") {
		t.Fatalf("an undialable number was kept: %q", said(rec))
	}
	if rec := postForm(t, f, "a-itadmin", "/branding", url.Values{
		"product_name": {"Kalesi Device Care"}, "colour": {"#0F6E66"}, "mark_letter": {"K"},
		"lost_phone": {"+234 800 000 0000"}, "lost_email": {"itdesk@kalesi.example"},
	}); !strings.Contains(said(rec), "Saved") {
		t.Fatalf("branding with contact details: %q", said(rec))
	}

	// The help desk may not.
	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/lost-mode", "a-helpdesk",
		map[string]any{"reason": "Left on the train"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the help desk put a phone in lost mode: %d", rec.Code)
	}
	// IT may, with a reason, and Google carries it out.
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/lost-mode", "a-itadmin",
		map[string]any{"reason": "Left on the train"}))
	if rec.Code >= 300 || body["state"] != "acknowledged" {
		t.Fatalf("lost mode: %d %v", rec.Code, body)
	}
	if got := f.google.Commands[name]; len(got) != 1 || got[0] != "START_LOST_MODE" {
		t.Fatalf("Google was asked %v", got)
	}
	brand := adminString(t, `SELECT product_name FROM tenant_branding WHERE tenant_id = $1`, tenantA)
	if msg := f.google.LostMessages[name]; !strings.Contains(msg, brand) {
		t.Fatalf("the lock screen does not name the tenant %q: %q", brand, msg)
	}
	// And says who to call, both in the words and in the fields Google
	// shows as buttons.
	if msg := f.google.LostMessages[name]; !strings.Contains(msg, "please call +234 800 000 0000 or email itdesk@kalesi.example") ||
		!strings.HasSuffix(msg, "| +234 800 000 0000 | itdesk@kalesi.example") {
		t.Fatalf("the lock screen does not say who to call: %q", msg)
	}
	// And ended, through the same door.
	rec, body = do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/lost-mode/end", "a-itadmin",
		map[string]any{"reason": "Handed in at reception"}))
	if rec.Code >= 300 || body["state"] != "acknowledged" {
		t.Fatalf("end lost mode: %d %v", rec.Code, body)
	}
	if got := f.google.Commands[name]; len(got) != 2 || got[1] != "STOP_LOST_MODE" {
		t.Fatalf("Google was asked %v", got)
	}
}

func adminString(t *testing.T, sql string, args ...any) string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	var s string
	if err := conn.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
		t.Fatalf("query: %v", err)
	}
	return s
}

func TestUnbindingLeavesDevicesAndStopsEnrolment(t *testing.T) {
	f := newFixture(t)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}
	rec := postForm(t, f, "a-super", "/android/unbind", url.Values{})
	if !strings.Contains(said(rec), "Unbound") {
		t.Fatalf("unbind: %q", said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM android_enterprises WHERE tenant_id = $1`, tenantA); n != 0 {
		t.Fatal("the binding survived")
	}
	rec = postForm(t, f, "a-itadmin", "/android/tokens", url.Values{"label": {"x"}})
	if !strings.Contains(said(rec), "Bind an Android Enterprise first") {
		t.Fatalf("a token after unbinding: %q", said(rec))
	}
	rec2, _ := do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin"))
	if rec2.Code != http.StatusConflict {
		t.Fatalf("sync after unbinding: %d", rec2.Code)
	}
	_ = uuid.Nil
}

// The invitation. What an administrator sends is Google's link, because the
// phone talks to Google; it goes to the person by the tenant's own mail;
// and the address is checked before Google is asked for anything.
func TestAnInvitationCarriesGooglesLinkAndGoesToThePerson(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}
	before := len(f.mail.Received())

	rec := postForm(t, f, "a-itadmin", "/android/tokens", url.Values{
		"label": {"Kemi's phone"}, "assigned_to": {"kemi@kalesi.example"}, "ownership": {"personal"}, "send": {"1"}})
	body := rec.Body.String()
	m := androidTokenRE.FindStringSubmatch(body)
	if rec.Code != 200 || m == nil {
		t.Fatalf("token page: %d\n%s", rec.Code, body)
	}
	link := "https://enterprise.google.com/android/enroll?et=" + m[1]
	if !strings.Contains(body, link) {
		t.Fatalf("the page does not show Google's link %s:\n%s", link, body)
	}
	if !strings.Contains(body, "Emailed to") || !strings.Contains(body, "kemi@kalesi.example") {
		t.Fatalf("the page does not say the link was emailed:\n%s", body)
	}
	got := f.mail.Received()
	if len(got) != before+1 {
		t.Fatalf("%d emails left, want 1", len(got)-before)
	}
	last := got[len(got)-1]
	if strings.Join(last.To, ",") != "kemi@kalesi.example" {
		t.Fatalf("the invitation went to %v", last.To)
	}
	for _, want := range []string{link, "Kemi's phone", "work profile"} {
		if !strings.Contains(last.Data, want) {
			t.Fatalf("the invitation does not carry %q:\n%s", want, last.Data)
		}
	}
	// T12 in an inbox: the tenant's name, nobody else's.
	if !strings.Contains(last.Data, "Kalesi Device Care") {
		t.Fatalf("the invitation does not come from the tenant:\n%s", last.Data)
	}
	for _, leak := range []string{"operator", "platform", "MDM"} {
		if strings.Contains(last.Data, leak) {
			t.Fatalf("the invitation leaks %q:\n%s", leak, last.Data)
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'android.invite_sent'`, tenantA); n != 1 {
		t.Fatalf("%d invitations audited, want 1", n)
	}

	// Without the box ticked, nothing is sent and the link is still shown.
	rec = postForm(t, f, "a-itadmin", "/android/tokens", url.Values{
		"label": {"Spare phone"}, "assigned_to": {"stores@kalesi.example"}, "ownership": {"company"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "enterprise.google.com/android/enroll?et=") {
		t.Fatalf("no link without mail: %d", rec.Code)
	}
	if len(f.mail.Received()) != before+1 {
		t.Fatal("an email left although the box was not ticked")
	}

	// An address that is not one address is refused before Google is
	// asked: a line break in it would otherwise be a mail header.
	issued := len(f.google.TokenUsage)
	rec = postForm(t, f, "a-itadmin", "/android/tokens", url.Values{
		"label": {"x"}, "assigned_to": {"kemi@kalesi.example\r\nBcc: x@evil.example"}, "ownership": {"personal"}, "send": {"1"}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "one email address") {
		t.Fatalf("a bad address was not refused in words: %d %s", rec.Code, said(rec))
	}
	if len(f.google.TokenUsage) != issued {
		t.Fatal("Google was asked for a token before the address was checked")
	}
	if len(f.mail.Received()) != before+1 {
		t.Fatal("an email left for a bad address")
	}
}

// The QR code on an invitation is scanned the way a phone scans it, and what
// comes out is the right thing for that kind of phone.
func TestTheInvitationShowsAQRThatScansToTheRightThing(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}

	// A personal phone: the camera opens Google's link.
	rec := postForm(t, f, "a-itadmin", "/android/tokens", url.Values{
		"label": {"Kemi's phone"}, "assigned_to": {"kemi@kalesi.example"}, "ownership": {"personal"}})
	body := rec.Body.String()
	m := androidTokenRE.FindStringSubmatch(body)
	if rec.Code != 200 || m == nil {
		t.Fatalf("token page: %d", rec.Code)
	}
	imgs := qrtest.PageImages(body)
	if len(imgs) != 1 {
		t.Fatalf("a personal invitation shows %d QR codes, want 1", len(imgs))
	}
	link := "https://enterprise.google.com/android/enroll?et=" + m[1]
	if got := qrtest.ScanDataURL(t, imgs[0]); got != link {
		t.Fatalf("the QR code scans to %q, not Google's link %q", got, link)
	}
	if !strings.Contains(body, "camera") {
		t.Fatal("the page does not say what to do with a link QR code")
	}

	// A company phone: the welcome screen reads Google's provisioning payload.
	rec = postForm(t, f, "a-itadmin", "/android/tokens", url.Values{
		"label": {"Field phone 7"}, "assigned_to": {"stores@kalesi.example"}, "ownership": {"company"}})
	body = rec.Body.String()
	m = androidTokenRE.FindStringSubmatch(body)
	if rec.Code != 200 || m == nil {
		t.Fatalf("company token page: %d", rec.Code)
	}
	imgs = qrtest.PageImages(body)
	if len(imgs) != 1 {
		t.Fatalf("a company invitation shows %d QR codes, want 1", len(imgs))
	}
	got := qrtest.ScanDataURL(t, imgs[0])
	if strings.Contains(got, "enterprise.google.com") {
		t.Fatalf("a company phone was given a link QR code, which a welcome screen cannot use: %q", got)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(got), &payload); err != nil {
		t.Fatalf("the company QR code is not Google's provisioning payload: %q", got)
	}
	if !strings.Contains(got, m[1]) {
		t.Fatalf("the provisioning payload does not carry this token (%s): %q", m[1], got)
	}
	if !strings.Contains(body, "six times") {
		t.Fatal("the page does not tell the person to tap six times")
	}
}
