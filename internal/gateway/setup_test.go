package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"platform/internal/android"
	"strings"
	"testing"
)

// postForm sends a console form as a signed-in person, with the token every
// form carries.
func postForm(t *testing.T, f fixture, bearer, path string, vals url.Values) *httptest.ResponseRecorder {
	t.Helper()
	cookie := f.cookie(t, bearer)
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	vals.Set("csrf", f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role))
	r := httptest.NewRequest("POST", "http://"+hostA+path, strings.NewReader(vals.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

func said(rec *httptest.ResponseRecorder) string {
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc == nil {
		return ""
	}
	return loc.Query().Get("said")
}

// ---------------------------------------------------------------- the list

// The fixture's tenant A is branded, signed in and has devices, so it starts
// most of the way through. What is left is what the list should say.
func TestTheSetupListSaysWhatIsLeft(t *testing.T) {
	f := newFixture(t)
	_, body := do(t, f, req(t, "GET", hostA, "/api/setup", "a-itadmin"))

	steps, _ := body["Steps"].([]any)
	if len(steps) < 7 {
		t.Fatalf("got %d steps", len(steps))
	}
	byKey := map[string]map[string]any{}
	for _, s := range steps {
		m := s.(map[string]any)
		byKey[m["Key"].(string)] = m
	}

	// Seeded state: branded, one admin mapping (so sign-in is NOT done, it
	// wants at least two groups), no notification targets, two devices.
	if byKey["brand"]["Done"] != true {
		t.Fatal("a branded tenant reads as unbranded")
	}
	if byKey["device"]["Done"] != true {
		t.Fatal("a tenant with devices reads as having none")
	}
	if byKey["notify"]["Done"] != false {
		t.Fatal("a tenant with no notification target reads as done")
	}
	if byKey["network"]["Done"] != false || byKey["network"]["Optional"] != true {
		t.Fatalf("the network step on a fresh tenant: %v", byKey["network"])
	}
	// Honest about what cannot be done.
	if b, _ := byKey["abm"]["Blocked"].(string); !strings.Contains(b, "vendor certificate") {
		t.Fatalf("the Apple step does not say what it is waiting on: %v", byKey["abm"])
	}
	// The fixture has Google (faked), so Android is possible and not yet
	// bound. Take Google away and the step says what is missing.
	if byKey["android"]["Blocked"] != "" || byKey["android"]["Done"] != false || byKey["android"]["Href"] != "/android" {
		t.Fatalf("the Android step with Google configured: %v", byKey["android"])
	}
	f.g.android = android.NotConfigured{}
	_, body = do(t, f, req(t, "GET", hostA, "/api/setup", "a-itadmin"))
	for _, s := range body["Steps"].([]any) {
		if m := s.(map[string]any); m["Key"] == "android" {
			if b, _ := m["Blocked"].(string); !strings.Contains(b, "service account") {
				t.Fatalf("the Android step without Google does not say what is missing: %v", m)
			}
		}
	}
}

func TestBlockedAndOptionalStepsDoNotStopATenantBeingReady(t *testing.T) {
	f := newFixture(t)
	// Finish the two required things the seed leaves undone.
	exec(t, `INSERT INTO tenant_role_map (tenant_id, claim_value, role)
	          VALUES ($1, 'IT-Operations', 'it_admin'), ($1, 'MDM-Owners', 'super_admin')
	          ON CONFLICT DO NOTHING`, tenantA)
	exec(t, `INSERT INTO tenant_identity
	           (tenant_id, issuer, client_id, client_secret_sealed, redirect_url)
	         VALUES ($1, 'https://login.example/v2.0', 'c', '\x00', 'https://x/signin/callback')
	         ON CONFLICT DO NOTHING`, tenantA)
	do(t, f, jsonReq(t, "POST", hostA, "/api/notifications", "a-itadmin",
		map[string]any{"topic": "device.lost", "kind": "log", "endpoint": "-"}))

	_, body := do(t, f, req(t, "GET", hostA, "/api/setup", "a-itadmin"))
	if body["Ready"] != true {
		t.Fatalf("not ready with every required step done: %v", body["Steps"])
	}
}

// The PRD's first success metric, shown rather than measured elsewhere.
func TestTheTimeToFirstDeviceIsShown(t *testing.T) {
	f := newFixture(t)
	exec(t, `UPDATE tenants SET created_at = now() - interval '47 minutes' WHERE id = $1`, tenantA)
	exec(t, `UPDATE devices SET created_at = now() - interval '5 minutes' WHERE tenant_id = $1`, tenantA)

	_, page := getHTML(t, f, hostA, "/setup", "a-itadmin")
	if !strings.Contains(page, "Sign-up to first device") {
		t.Fatal("the metric is not on the page")
	}
	if !strings.Contains(page, "42 minutes") {
		t.Fatalf("the metric is wrong or missing: %s", page)
	}
}

// Seeded data has devices older than their tenant. Saying nothing is better
// than saying something false.
func TestAnImpossibleMetricIsNotShown(t *testing.T) {
	f := newFixture(t)
	exec(t, `UPDATE tenants SET created_at = now() WHERE id = $1`, tenantA)
	exec(t, `UPDATE devices SET created_at = now() - interval '1 day' WHERE tenant_id = $1`, tenantA)
	_, page := getHTML(t, f, hostA, "/setup", "a-itadmin")
	if strings.Contains(page, "Sign-up to first device") {
		t.Fatal("a negative time-to-first-device was shown")
	}
}

// ---------------------------------------------------------------- branding

func TestBrandingIsSavedFromTheConsole(t *testing.T) {
	f := newFixture(t)
	rec := postForm(t, f, "a-itadmin", "/branding", url.Values{
		"product_name": {"Kalesi Fleet"}, "colour": {"#0F6E66"},
		"mark_letter": {"k"}, "legal_footer": {"Kalesi Foods Ltd"},
	})
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "Saved") {
		t.Fatalf("got %d %q", rec.Code, said(rec))
	}
	_, page := getHTML(t, f, hostA, "/", "a-itadmin")
	if !strings.Contains(page, "Kalesi Fleet") {
		t.Fatal("the new name is not on the dashboard")
	}
	if !strings.Contains(page, `>K<`) && !strings.Contains(page, ">K</span>") {
		t.Fatal("the mark letter was not upper-cased")
	}
}

// Accessibility is not something a tenant can switch off by choosing badly.
func TestAnUnreadableColourIsRefusedWithTheReason(t *testing.T) {
	f := newFixture(t)
	rec := postForm(t, f, "a-itadmin", "/branding", url.Values{
		"product_name": {"Kalesi Fleet"}, "colour": {"#FFFF00"}, "mark_letter": {"K"},
	})
	msg := said(rec)
	if !strings.Contains(msg, "Not saved") {
		t.Fatalf("an unreadable colour was saved: %q", msg)
	}
	if !strings.Contains(msg, "4.5") && !strings.Contains(strings.ToLower(msg), "contrast") {
		t.Fatalf("the reason is unhelpful: %q", msg)
	}
	_, page := getHTML(t, f, hostA, "/", "a-itadmin")
	if strings.Contains(page, "#FFFF00") {
		t.Fatal("the refused colour reached the page")
	}
}

func TestHelpdeskMayNotRebrand(t *testing.T) {
	f := newFixture(t)
	rec := postForm(t, f, "a-helpdesk", "/branding", url.Values{
		"product_name": {"Nope"}, "colour": {"#0F6E66"}, "mark_letter": {"N"},
	})
	if !strings.Contains(said(rec), "may not") {
		t.Fatalf("helpdesk rebranded the tenant: %q", said(rec))
	}
}

// ---------------------------------------------------------------- sign-in

// Anybody who can edit the role map can map their own group to super_admin,
// so editing it has to be gated to people who already are. That is the whole
// reason access.manage exists as its own action.
func TestOnlyASuperAdminMayDecideWhoGetsIn(t *testing.T) {
	f := newFixture(t)
	for _, bearer := range []string{"a-itadmin", "a-secmgr", "a-helpdesk", "a-auditor", "a-employee"} {
		rec, _ := getHTML(t, f, hostA, "/identity", bearer)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s reached the sign-in settings: %d", bearer, rec.Code)
		}
		post := postForm(t, f, bearer, "/identity/roles", url.Values{
			"claim_value": {"My-Own-Group"}, "role": {"super_admin"},
		})
		if !strings.Contains(said(post), "may not") {
			t.Fatalf("%s mapped a group to super_admin: %q", bearer, said(post))
		}
	}
	rec, _ := getHTML(t, f, hostA, "/identity", "a-super")
	if rec.Code != 200 {
		t.Fatalf("a super admin could not reach the sign-in settings: %d", rec.Code)
	}
}

func TestAGroupIsMappedAndUnmappedFromTheConsole(t *testing.T) {
	f := newFixture(t)
	rec := postForm(t, f, "a-super", "/identity/roles", url.Values{
		"claim_value": {"Service-Desk"}, "role": {"helpdesk"},
	})
	if !strings.Contains(said(rec), "Saved") {
		t.Fatalf("got %q", said(rec))
	}
	_, page := getHTML(t, f, hostA, "/identity", "a-super")
	if !strings.Contains(page, "Service-Desk") {
		t.Fatal("the mapping is not on the page")
	}

	rec = postForm(t, f, "a-super", "/identity/roles/remove", url.Values{
		"claim_value": {"Service-Desk"},
	})
	if !strings.Contains(said(rec), "Removed") {
		t.Fatalf("got %q", said(rec))
	}
	_, page = getHTML(t, f, hostA, "/identity", "a-super")
	if strings.Contains(page, "Service-Desk") {
		t.Fatal("the mapping is still on the page")
	}
}

// The lock-out guard. Removing the only mapping to super_admin leaves a
// tenant nobody can administer, and the people who could fix it are exactly
// the people it has just locked out.
func TestTheLastSuperAdminMappingCannotBeRemoved(t *testing.T) {
	f := newFixture(t)
	exec(t, `DELETE FROM tenant_role_map WHERE tenant_id = $1`, tenantA)
	exec(t, `INSERT INTO tenant_role_map (tenant_id, claim_value, role)
	          VALUES ($1, 'MDM-Owners', 'super_admin')`, tenantA)

	rec := postForm(t, f, "a-super", "/identity/roles/remove", url.Values{
		"claim_value": {"MDM-Owners"},
	})
	if !strings.Contains(said(rec), "only group mapped to Super Admin") {
		t.Fatalf("the last admin mapping was removed: %q", said(rec))
	}
	var n int
	queryRow(t, `SELECT count(*) FROM tenant_role_map WHERE role = 'super_admin'`, &n)
	if n != 1 {
		t.Fatal("the mapping is gone")
	}

	// With a second one in place, removing the first is fine.
	exec(t, `INSERT INTO tenant_role_map (tenant_id, claim_value, role)
	          VALUES ($1, 'Security-Leads', 'super_admin')`, tenantA)
	rec = postForm(t, f, "a-super", "/identity/roles/remove", url.Values{
		"claim_value": {"MDM-Owners"},
	})
	if !strings.Contains(said(rec), "Removed") {
		t.Fatalf("got %q", said(rec))
	}
}

func TestAGroupCannotBeMappedToTheOperatorOrADevice(t *testing.T) {
	f := newFixture(t)
	for _, role := range []string{"platform_operator", "device", "god"} {
		rec := postForm(t, f, "a-super", "/identity/roles", url.Values{
			"claim_value": {"Sneaky"}, "role": {role},
		})
		if strings.Contains(said(rec), "Saved") {
			t.Fatalf("a group was mapped to %s", role)
		}
	}
}

// A blank secret on the form keeps the one held. A page that made somebody
// re-enter the secret to change the role claim is a page where the secret
// gets pasted into chat to be found later.
func TestSavingTheProviderWithoutASecretKeepsTheOldOne(t *testing.T) {
	f := newFixture(t)
	exec(t, `INSERT INTO tenant_identity
	           (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim)
	         VALUES ($1, 'https://login.example/v2.0', 'old-client', '\xdeadbeef',
	                 'https://x/signin/callback', 'groups')`, tenantA)

	rec := postForm(t, f, "a-super", "/identity", url.Values{
		"issuer": {"https://login.example/v2.0"}, "client_id": {"new-client"},
		"role_claim": {"roles"}, "client_secret": {""},
	})
	if !strings.Contains(said(rec), "Saved") {
		t.Fatalf("got %q", said(rec))
	}
	var client, claim string
	var sealed []byte
	queryRow(t, `SELECT client_id FROM tenant_identity WHERE tenant_id = $1`, &client, tenantA)
	queryRow(t, `SELECT role_claim FROM tenant_identity WHERE tenant_id = $1`, &claim, tenantA)
	queryRow(t, `SELECT client_secret_sealed FROM tenant_identity WHERE tenant_id = $1`, &sealed, tenantA)
	if client != "new-client" || claim != "roles" {
		t.Fatalf("the change was not saved: %s %s", client, claim)
	}
	if string(sealed) != "\xde\xad\xbe\xef" {
		t.Fatal("a blank secret overwrote the one held")
	}
}

func TestTheRedirectURLIsDerivedNotTyped(t *testing.T) {
	f := newFixture(t)
	rec := postForm(t, f, "a-super", "/identity", url.Values{
		"issuer": {"https://login.example/v2.0"}, "client_id": {"c"},
		"client_secret": {"s"},
		// Somebody trying to point the callback elsewhere.
		"redirect_url": {"https://evil.example/steal"},
	})
	if !strings.Contains(said(rec), "Saved") {
		t.Fatalf("got %q", said(rec))
	}
	var redirect string
	queryRow(t, `SELECT redirect_url FROM tenant_identity WHERE tenant_id = $1`, &redirect, tenantA)
	if !strings.HasSuffix(redirect, hostA+"/signin/callback") {
		t.Fatalf("the redirect URL is %q", redirect)
	}
}

func TestTheSetupPageIsLinkedFromTheNavigation(t *testing.T) {
	f := newFixture(t)
	_, page := getHTML(t, f, hostA, "/", "a-itadmin")
	if !strings.Contains(page, `href="/setup"`) {
		t.Fatal("setup is not in the navigation")
	}
	// And the sign-in settings are offered only to those who may use them.
	if strings.Contains(page, `href="/identity"`) {
		t.Fatal("an IT admin was offered the sign-in settings")
	}
	_, page = getHTML(t, f, hostA, "/", "a-super")
	if !strings.Contains(page, `href="/identity"`) {
		t.Fatal("a super admin was not offered the sign-in settings")
	}
}

// The network step is done when the network has ASKED, not when a token
// exists: a token nobody has used is an integration somebody meant to
// finish, and the feed being asked is the only sign the platform can see.
func TestTheNetworkStepIsDoneOnlyWhenTheNetworkHasAsked(t *testing.T) {
	f := newFixture(t)
	step := func() map[string]any {
		t.Helper()
		_, body := do(t, f, req(t, "GET", hostA, "/api/setup", "a-itadmin"))
		for _, s := range body["Steps"].([]any) {
			if m := s.(map[string]any); m["Key"] == "network" {
				return m
			}
		}
		t.Fatal("no network step")
		return nil
	}
	token, _ := mintToken(t, f, "a-super", "Branch NAC")
	if token == "" {
		t.Fatal("no token")
	}
	if m := step(); m["Done"] != false || !strings.Contains(m["Detail"].(string), "nothing has asked") {
		t.Fatalf("after minting only: %v", m)
	}
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/network/denied", token)); rec.Code != 200 {
		t.Fatalf("feed: %d", rec.Code)
	}
	if m := step(); m["Done"] != true || !strings.Contains(m["Detail"].(string), "Branch NAC last asked") {
		t.Fatalf("after the network asked: %v", m)
	}
}

// The Branding page's email preview is the real renderer with the real
// stamp: the tenant's name, colour and legal footer, as their staff get it.
func TestTheBrandingPageShowsWhatAnEmailLooksLike(t *testing.T) {
	f := newFixture(t)
	var footer, colour string
	queryRow(t, `SELECT legal_footer FROM tenant_branding WHERE tenant_id = $1`, &footer, tenantA)
	queryRow(t, `SELECT brand_colour FROM tenant_branding WHERE tenant_id = $1`, &colour, tenantA)

	rec := raw(t, f, req(t, "GET", hostA, "/branding/email", "a-itadmin"))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("preview: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	for _, want := range []string{"Kalesi Device Care", "background:" + colour, footer, "was reported lost"} {
		if want == "" || !strings.Contains(body, want) {
			t.Fatalf("the preview does not carry %q", want)
		}
	}
	if rec := raw(t, f, req(t, "GET", hostA, "/branding/email", "a-helpdesk")); rec.Code != http.StatusForbidden {
		t.Fatalf("the help desk opened the branding preview: %d", rec.Code)
	}
}
