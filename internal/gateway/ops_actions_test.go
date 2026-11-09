package gateway

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"platform/internal/directory"
	"platform/internal/localauth"
)

// What an owner can change (0048). Each change is a form behind a session, a
// token and the same site, and each leaves a line in a record the owner cannot
// edit.

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFrom(t *testing.T, b *browser) string {
	t.Helper()
	_, page := read(b, opsSite+"/account")
	m := csrfRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no form token on the page:\n%.300s", page)
	}
	return m[1]
}

// ownerAt is a signed-in owner, the organisation tenant A's short name, and a
// way to post a form with the token.
func ownerAt(t *testing.T, f *opsFixture, email string) (b *browser, slug string, post func(path string, v url.Values) (*http.Response, string)) {
	t.Helper()
	b = f.browser(t)
	f.onboard(t, b, email)
	slug = adminString(t, `SELECT slug FROM tenants WHERE id = $1`, tenantA)
	tok := csrfFrom(t, b)
	post = func(path string, v url.Values) (*http.Response, string) {
		if v == nil {
			v = url.Values{}
		}
		v.Set("csrf", tok)
		return b.postForm(opsSite+path, v)
	}
	return b, slug, post
}

func orgStatus(t *testing.T, slug string) string {
	t.Helper()
	return adminString(t, `SELECT status FROM tenants WHERE slug = $1`, slug)
}

func eventCount(t *testing.T, action, target, detailLike string) int {
	t.Helper()
	return adminCount(t, `SELECT count(*) FROM operator_events WHERE action = $1 AND target = $2 AND detail LIKE $3`, action, target, detailLike)
}

func TestAnOwnerCanSuspendAndResumeAnOrganisationAndItIsRecorded(t *testing.T) {
	f := newOpsFixture(t)
	_, slug, post := ownerAt(t, f, "one@example.com")
	devices := func() int {
		rec := opsRaw(t, f.h, "GET", hostA, "/api/devices", map[string]string{sessionCookie: f.cookie(t, "a-super")})
		return rec.Code
	}
	if devices() != 200 {
		t.Fatalf("the organisation's own API answers %d before anything is done", devices())
	}

	// It takes the short name and a reason.
	if resp, body := post("/orgs/"+slug+"/suspend", url.Values{"confirm": {"nope"}, "reason": {"non-payment"}}); resp.StatusCode != 422 || !strings.Contains(body, "type its short name") {
		t.Fatalf("a wrong confirmation was taken (%d): %.300s", resp.StatusCode, body)
	}
	if resp, body := post("/orgs/"+slug+"/suspend", url.Values{"confirm": {slug}, "reason": {"  "}}); resp.StatusCode != 422 || !strings.Contains(body, "Say why") {
		t.Fatalf("no reason was taken (%d): %.300s", resp.StatusCode, body)
	}
	if orgStatus(t, slug) != "active" {
		t.Fatal("a refused suspension changed the organisation")
	}

	resp, body := post("/orgs/"+slug+"/suspend", url.Values{"confirm": {strings.ToUpper(slug)}, "reason": {"non-payment"}})
	if resp.StatusCode != 200 || !strings.Contains(body, "Suspended.") || orgStatus(t, slug) != "suspended" {
		t.Fatalf("suspend did not work (%d): %.300s", resp.StatusCode, body)
	}
	if c := devices(); c != 403 {
		t.Fatalf("a suspended organisation's API answers %d", c)
	}
	if n := eventCount(t, "org.suspended", slug, "non-payment"); n != 1 {
		t.Fatalf("%d records of the suspension", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM operator_events WHERE action = 'org.suspended' AND actor = 'one@example.com'`); n != 1 {
		t.Fatal("the record does not name who did it")
	}
	// Suspending what is suspended, and resuming what is not, are refused.
	if resp, body := post("/orgs/"+slug+"/suspend", url.Values{"confirm": {slug}, "reason": {"again"}}); resp.StatusCode != 422 || !strings.Contains(body, "not active") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}

	resp, body = post("/orgs/"+slug+"/resume", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Resumed.") || orgStatus(t, slug) != "active" || devices() != 200 {
		t.Fatalf("resume did not work (%d): %.300s", resp.StatusCode, body)
	}
	if n := eventCount(t, "org.resumed", slug, ""); n != 1 {
		t.Fatalf("%d records of the resume", n)
	}
	if resp, body := post("/orgs/"+slug+"/resume", nil); resp.StatusCode != 422 || !strings.Contains(body, "not suspended") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if resp, _ := post("/orgs/no-such-organisation/resume", nil); resp.StatusCode != 404 {
		t.Fatalf("an unknown organisation: %d", resp.StatusCode)
	}
}

func TestOwnerChangesNeedASessionTheFormTokenAndTheSameSite(t *testing.T) {
	f := newOpsFixture(t)
	b, slug, _ := ownerAt(t, f, "one@example.com")
	form := url.Values{"confirm": {slug}, "reason": {"x"}}
	unchanged := func(what string) {
		t.Helper()
		if orgStatus(t, slug) != "active" {
			t.Fatalf("%s: the organisation was suspended", what)
		}
	}

	// No token.
	if resp, _ := b.postForm(opsSite+"/orgs/"+slug+"/suspend", form); resp.StatusCode != http.StatusForbidden {
		t.Errorf("no token: %d", resp.StatusCode)
	}
	unchanged("no token")
	// A token that belongs to somebody else's session.
	other := url.Values{"confirm": {slug}, "reason": {"x"}, "csrf": {f.g.csrfFor(tenantA, "f.okonkwo", "super_admin")}}
	if resp, _ := b.postForm(opsSite+"/orgs/"+slug+"/suspend", other); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a tenant's token: %d", resp.StatusCode)
	}
	unchanged("a tenant's token")
	// From another site.
	good := url.Values{"confirm": {slug}, "reason": {"x"}, "csrf": {csrfFrom(t, b)}}
	req, _ := http.NewRequest("POST", opsSite+"/orgs/"+slug+"/suspend", strings.NewReader(good.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("another site: %d", resp.StatusCode)
	}
	unchanged("another site")
	// No session.
	for _, p := range []string{"/orgs/" + slug + "/suspend", "/orgs/" + slug + "/plan", "/orgs/" + slug + "/quota",
		"/orgs/" + slug + "/feature", "/operators/invite", "/signups/cancel"} {
		if rec := opsRaw(t, f.h, "POST", opsHost, p, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin" {
			t.Errorf("%s with no session: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	unchanged("no session")
	if n := adminCount(t, `SELECT count(*) FROM operator_events WHERE action LIKE 'org.%'`); n != 0 {
		t.Fatalf("%d records of changes that were refused", n)
	}
}

func TestAPlanAnAllowanceAndASwitchChangeAndAreRecordedWithTheirOldValues(t *testing.T) {
	f := newOpsFixture(t)
	_, slug, post := ownerAt(t, f, "one@example.com")
	was := adminString(t, `SELECT plan FROM tenants WHERE slug = $1`, slug)
	to := "scale"
	if was == "scale" {
		to = "starter"
	}
	plan, _ := directory.PlanByName(to)

	if resp, body := post("/orgs/"+slug+"/plan", url.Values{"plan": {"platinum"}}); resp.StatusCode != 422 || !strings.Contains(body, "not a plan") {
		t.Fatalf("(%d) %.200s", resp.StatusCode, body)
	}
	exec(t, `UPDATE tenants SET features = '{"android": true}' WHERE slug = $1`, slug)
	if resp, body := post("/orgs/"+slug+"/plan", url.Values{"plan": {to}}); resp.StatusCode != 200 || !strings.Contains(body, "Plan changed") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if got := adminCount(t, `SELECT device_cap FROM tenants WHERE slug = $1`, slug); got != plan.DeviceCap {
		t.Fatalf("device cap %d, plan says %d", got, plan.DeviceCap)
	}
	if adminString(t, `SELECT features::text FROM tenants WHERE slug = $1`, slug) != "{}" {
		t.Fatal("a plan change kept the switches set for this organisation alone")
	}
	if n := eventCount(t, "org.plan_set", slug, to+" (was "+was+")"); n != 1 {
		t.Fatalf("%d records of the plan change", n)
	}

	// The allowance: numbers in range only, and the old ones in the record.
	for _, bad := range []url.Values{
		{"devices": {"0"}, "seats": {"5"}, "rate": {"100"}},
		{"devices": {"-3"}, "seats": {"5"}, "rate": {"100"}},
		{"devices": {"ten"}, "seats": {"5"}, "rate": {"100"}},
		{"devices": {"1000001"}, "seats": {"5"}, "rate": {"100"}},
		{"devices": {"10"}, "seats": {"10001"}, "rate": {"100"}},
		{"devices": {"10"}, "seats": {"5"}, "rate": {"100001"}},
		{"devices": {"10"}, "seats": {"5"}},
	} {
		if resp, _ := post("/orgs/"+slug+"/quota", bad); resp.StatusCode != 422 {
			t.Errorf("%v: %d", bad, resp.StatusCode)
		}
	}
	if got := adminCount(t, `SELECT device_cap FROM tenants WHERE slug = $1`, slug); got != plan.DeviceCap {
		t.Fatal("a refused allowance changed the organisation")
	}
	if resp, body := post("/orgs/"+slug+"/quota", url.Values{"devices": {"77"}, "seats": {"7"}, "rate": {"777"}}); resp.StatusCode != 200 || !strings.Contains(body, "Allowance changed") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if adminCount(t, `SELECT device_cap FROM tenants WHERE slug = $1`, slug) != 77 ||
		adminCount(t, `SELECT admin_seats FROM tenants WHERE slug = $1`, slug) != 7 ||
		adminCount(t, `SELECT api_rate_per_min FROM tenants WHERE slug = $1`, slug) != 777 {
		t.Fatal("the allowance was not set")
	}
	if adminString(t, `SELECT plan FROM tenants WHERE slug = $1`, slug) != to {
		t.Fatal("an allowance change moved the plan")
	}
	if n := eventCount(t, "org.quota_set", slug, "devices "+strconv.Itoa(plan.DeviceCap)+" to 77%"); n != 1 {
		t.Fatalf("%d records of the allowance change", n)
	}

	// Switches: on, off, and back to what the plan says.
	sw := func(feature, to string) (*http.Response, string) {
		return post("/orgs/"+slug+"/feature", url.Values{"feature": {feature}, "to": {to}})
	}
	if resp, body := sw("android", "on"); resp.StatusCode != 200 || !strings.Contains(body, "Switch changed") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if adminString(t, `SELECT features->>'android' FROM tenants WHERE slug = $1`, slug) != "true" {
		t.Fatal("the switch was not turned on")
	}
	sw("android", "off")
	if adminString(t, `SELECT features->>'android' FROM tenants WHERE slug = $1`, slug) != "false" {
		t.Fatal("the switch was not turned off")
	}
	sw("android", "plan")
	if adminCount(t, `SELECT count(*) FROM tenants WHERE slug = $1 AND features ? 'android'`, slug) != 0 {
		t.Fatal("'what the plan says' left the organisation's own switch in place")
	}
	if n := eventCount(t, "org.feature_set", slug, "android on (was %"); n != 1 {
		t.Fatalf("%d records of turning a switch on", n)
	}
	for _, bad := range []url.Values{{"feature": {"teleport"}, "to": {"on"}}, {"feature": {"android"}, "to": {"maybe"}}} {
		if resp, _ := post("/orgs/"+slug+"/feature", bad); resp.StatusCode != 422 {
			t.Errorf("%v: %d", bad, resp.StatusCode)
		}
	}
}

func TestCancellingASignUpEndsItsLinkAndIsRecorded(t *testing.T) {
	f := newOpsFixture(t)
	b, _, post := ownerAt(t, f, "one@example.com")
	sum := sha256.Sum256([]byte("a link"))
	if _, err := f.g.dir.StartSignup(context.Background(), "ada@arbor.example", "Arbor Foods", "203.0.113.5", sum[:]); err != nil {
		t.Fatal(err)
	}
	if _, page := read(b, opsSite+"/signups"); !strings.Contains(page, "ada@arbor.example") || !strings.Contains(page, "Cancel link") {
		t.Fatalf("the open sign-up and its button are not on the page:\n%.1500s", page)
	}
	if resp, body := post("/signups/cancel", url.Values{"email": {"ada@arbor.example"}}); resp.StatusCode != 200 || !strings.Contains(body, "no longer works") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	rows, _ := f.g.dir.ListSignups(context.Background(), false)
	if len(rows) != 0 {
		t.Fatal("the cancelled sign-up is still open")
	}
	if n := eventCount(t, "signup.cancelled", "ada@arbor.example", ""); n != 1 {
		t.Fatalf("%d records", n)
	}
	if resp, body := post("/signups/cancel", url.Values{"email": {"ada@arbor.example"}}); resp.StatusCode != 422 || !strings.Contains(body, "no open link") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
}

var opsLinkRE = regexp.MustCompile(`http://ops\.example/(accept|reset)/[A-Za-z0-9_-]{43}`)

func TestOwnersAreAddedLinkedDisabledAndResetByEachOther(t *testing.T) {
	f := newOpsFixture(t)
	b1, _, post := ownerAt(t, f, "one@example.com")

	// An invitation: one link, shown once, in the answer to the form.
	resp, body := post("/operators/invite", url.Values{"email": {"Two@Example.com"}, "name": {"Two"}})
	link := opsLinkRE.FindString(body)
	if resp.StatusCode != 200 || link == "" || !strings.Contains(link, "/accept/") {
		t.Fatalf("no invitation link (%d): %.600s", resp.StatusCode, body)
	}
	if _, again := read(b1, opsSite+"/operators"); strings.Contains(again, "/accept/") {
		t.Fatal("the link is still on the page the next time it is opened")
	}
	if resp, body := post("/operators/invite", url.Values{"email": {"two@example.com"}}); resp.StatusCode != 422 || !strings.Contains(body, "already an owner") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if resp, body := post("/operators/invite", url.Values{"email": {"not an address"}}); resp.StatusCode != 422 || !strings.Contains(body, "not an email address") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}

	// The link takes the new owner all the way in.
	b2 := f.browser(t)
	_, page := b2.postForm(link, url.Values{"password": {localPassword}, "confirm": {localPassword}})
	secret := opsSecretFrom(t, page)
	if _, codes := b2.postForm(opsSite+"/signin/enrol", url.Values{"code": {localauth.Code(secret, time.Now())}}); !strings.Contains(codes, "Keep these recovery codes") {
		t.Fatalf("the invitation did not finish: %.300s", codes)
	}
	one, _ := f.g.dir.OperatorByEmail(context.Background(), "one@example.com")
	two, _ := f.g.dir.OperatorByEmail(context.Background(), "two@example.com")

	// An active owner with an authenticator is offered a password reset.
	if _, body := post("/operators/"+two.ID.String()+"/link", nil); !strings.Contains(opsLinkRE.FindString(body), "/reset/") {
		t.Fatalf("an active owner was not offered a reset: %.500s", body)
	}
	// Nobody acts on their own account in the ways that would lock them out.
	for _, p := range []string{"/disable", "/reset-mfa"} {
		if resp, body := post("/operators/"+one.ID.String()+p, nil); resp.StatusCode != 422 || !strings.Contains(body, "your own account") {
			t.Errorf("%s on yourself: %d %.200s", p, resp.StatusCode, body)
		}
	}

	// Reset the authenticator: two is signed out and starts again from a link.
	if resp, body := post("/operators/"+two.ID.String()+"/reset-mfa", nil); resp.StatusCode != 200 || !strings.Contains(body, "authenticator is removed") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if _, dash := read(b2, opsSite+"/"); !atTheOpsForm(dash) {
		t.Fatal("a session survived its authenticator being reset")
	}
	if _, body := post("/operators/"+two.ID.String()+"/link", nil); !strings.Contains(opsLinkRE.FindString(body), "/accept/") {
		t.Fatalf("an owner with no authenticator was not offered an invitation: %.500s", body)
	}

	// Disable and enable.
	if resp, body := post("/operators/"+two.ID.String()+"/disable", nil); resp.StatusCode != 200 || !strings.Contains(body, "Disabled.") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if resp, body := post("/operators/"+two.ID.String()+"/link", nil); resp.StatusCode != 422 || !strings.Contains(body, "disabled") {
		t.Fatalf("a link for a disabled owner (%d): %.300s", resp.StatusCode, body)
	}
	if resp, body := post("/operators/"+two.ID.String()+"/enable", nil); resp.StatusCode != 200 || !strings.Contains(body, "Enabled.") {
		t.Fatalf("(%d) %.300s", resp.StatusCode, body)
	}
	if resp, _ := post("/operators/"+uuidNil()+"/disable", nil); resp.StatusCode != 404 {
		t.Fatalf("an unknown owner: %d", resp.StatusCode)
	}

	for _, want := range []struct{ action, target string }{
		{"operator.invited", "two@example.com"}, {"operator.link_issued", "two@example.com"},
		{"operator.mfa_reset", two.ID.String()}, {"operator.disabled", two.ID.String()}, {"operator.enabled", two.ID.String()},
	} {
		if n := adminCount(t, `SELECT count(*) FROM operator_events WHERE action = $1 AND target = $2 AND actor = 'one@example.com'`, want.action, want.target); n < 1 {
			t.Errorf("no record of %s by one@example.com", want.action)
		}
	}
}

func uuidNil() string { return "00000000-0000-0000-0000-000000000000" }
