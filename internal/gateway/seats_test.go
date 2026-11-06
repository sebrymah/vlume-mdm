package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"platform/internal/identity/idptest"
)

// T8: administrator seats, through the real sign-in.

func person(n int, groups ...string) idptest.Person {
	return idptest.Person{
		Subject: "9f2c1a40-0000-4000-8000-0000000000" + string(rune('a'+n)) + "0",
		Email:   "admin" + string(rune('a'+n)) + "@kalesi.example",
		Name:    "Admin " + strings.ToUpper(string(rune('a'+n))),
		Groups:  groups,
	}
}

// signInFresh walks one person through the whole sign-in in a browser of
// their own, and says where they ended up.
func signInFresh(t *testing.T, f *signInFixture, p idptest.Person) (int, string, bool) {
	t.Helper()
	f.idp.SignInAs(p)
	b := newBrowser(t, f.server.Listener.Addr().String())
	resp, body := b.get("http://mdm.kalesi.example/signin")
	return resp.StatusCode, body, b.sessionCookie("mdm.kalesi.example") != ""
}

func TestAPlanWithTwoSeatsTurnsTheThirdAdministratorAway(t *testing.T) {
	f := newSignInFixture(t)
	adminExec(t, `UPDATE tenants SET admin_seats = 2 WHERE id = $1`, tenantA)

	// Two administrators take the two seats.
	for i := 0; i < 2; i++ {
		code, body, in := signInFresh(t, f, person(i, "All-Staff", "IT-Operations"))
		if code != 200 || !in || !strings.Contains(body, "Dashboard") {
			t.Fatalf("administrator %d could not sign in: %d %s", i, code, body)
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_admins WHERE tenant_id = $1`, tenantA); n != 2 {
		t.Fatalf("%d seats recorded, want 2", n)
	}

	// The third is told, in words, what is wrong and whose job it is.
	code, body, in := signInFresh(t, f, person(2, "All-Staff", "Security-Team"))
	if code != http.StatusForbidden || in {
		t.Fatalf("a third administrator got in: %d (cookie %v) %s", code, in, body)
	}
	for _, want := range []string{"administrator seat", "2 administrator seats", "release a seat"} {
		if !strings.Contains(strings.ToLower(body), want) {
			t.Fatalf("the refusal does not say %q: %s", want, body)
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'session.seat_refused'`, tenantA); n != 1 {
		t.Fatalf("%d refusals audited, want 1", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'quota.reached' AND object_ref = 'quota:seats'`, tenantA); n != 1 {
		t.Fatalf("%d seat notifications queued, want 1", n)
	}

	// An employee is not an administrator and takes no seat.
	code, _, in = signInFresh(t, f, person(3, "All-Staff"))
	if code != 200 || !in {
		t.Fatalf("an employee was refused by the seat count: %d", code)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_admins WHERE tenant_id = $1`, tenantA); n != 2 {
		t.Fatalf("an employee took a seat: %d rows", n)
	}

	// A seat holder coming back keeps the seat rather than needing another.
	code, _, in = signInFresh(t, f, person(0, "All-Staff", "IT-Operations"))
	if code != 200 || !in {
		t.Fatalf("a seat holder was refused on return: %d", code)
	}

	// The Sign-in page shows the count, and a Super Admin can release one.
	cookie := f.cookie(t, "a-super")
	r := httptest.NewRequest("GET", "http://"+hostA+"/identity", nil)
	r.Host = hostA
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "2 of 2") {
		t.Fatalf("the page does not show the seats: %d %s", rec.Code, rec.Body.String())
	}
	sess, _ := f.sessions.Verify(cookie)
	csrf := f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)
	r = httptest.NewRequest("POST", "http://"+hostA+"/identity/seats/release",
		strings.NewReader(url.Values{"csrf": {csrf}, "subject": {person(1).Subject}}.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("release: %d %s", rec.Code, rec.Body.String())
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'seat.released'`, tenantA); n != 1 {
		t.Fatal("the release was not audited")
	}
	code, _, in = signInFresh(t, f, person(2, "All-Staff", "Security-Team"))
	if code != 200 || !in {
		t.Fatalf("the freed seat could not be taken: %d", code)
	}
}

// A seat is held by use, not for ever. Someone who has not signed in for
// longer than the window has let it go, and comes back as a newcomer.
func TestASeatNotUsedForThirtyDaysHasLapsed(t *testing.T) {
	f := newSignInFixture(t)
	adminExec(t, `UPDATE tenants SET admin_seats = 1 WHERE id = $1`, tenantA)

	if code, _, in := signInFresh(t, f, person(0, "All-Staff", "IT-Operations")); code != 200 || !in {
		t.Fatalf("first administrator: %d", code)
	}
	// Forty days of silence, then somebody else arrives: the seat is theirs.
	adminExec(t, `UPDATE tenant_admins SET last_seen_at = now() - interval '40 days' WHERE tenant_id = $1`, tenantA)
	if code, _, in := signInFresh(t, f, person(1, "All-Staff", "IT-Operations")); code != 200 || !in {
		t.Fatalf("the lapsed seat was not free: %d", code)
	}
	// And the first person, back after the gap, is a newcomer to a full plan.
	code, _, in := signInFresh(t, f, person(0, "All-Staff", "IT-Operations"))
	if code != http.StatusForbidden || in {
		t.Fatalf("a lapsed seat holder got in past a full plan: %d", code)
	}
}

// "Sign this one person out." Their sessions end at once; everybody
// else's carry on; the record says who did it.
func TestOnePersonCanBeSignedOutEverywhere(t *testing.T) {
	f := newFixture(t)
	victim := f.cookie(t, "a-itadmin")
	other := f.cookie(t, "a-auditor")
	use := func(cookie string) int {
		r := req(t, "GET", hostA, "/api/devices", "")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		rec, _ := do(t, f, r)
		return rec.Code
	}
	if use(victim) != 200 || use(other) != 200 {
		t.Fatal("the sessions do not work before the sign-out")
	}
	time.Sleep(1100 * time.Millisecond) // the stamp is now(); the sessions started a moment before it

	rec := postForm(t, f, "a-super", "/identity/seats/signout", url.Values{"subject": {idp["a-itadmin"].Subject}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign out: %d %s", rec.Code, rec.Body.String())
	}
	if code := use(victim); code != http.StatusUnauthorized {
		t.Fatalf("the signed-out person is still in: %d", code)
	}
	if code := use(other); code != 200 {
		t.Fatalf("somebody else was signed out too: %d", code)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'session.revoked'`, tenantA); n != 1 {
		t.Fatal("the sign-out was not audited")
	}
	// They can come back: a session started after the stamp is fine.
	again := f.cookie(t, "a-itadmin")
	if code := use(again); code != 200 {
		t.Fatalf("a new session after the sign-out is refused: %d", code)
	}
}
