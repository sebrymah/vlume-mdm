package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"platform/internal/identity/idptest"
)

// The people the platform has met (0040). Not a directory: a row when
// someone signs in, is assigned a device, or is said to have left.

func TestSigningInMakesAPersonThePlatformHasMet(t *testing.T) {
	f := newSignInFixture(t)
	if code, _, in := signInFresh(t, f, okonkwo); code != 200 || !in {
		t.Fatalf("sign-in: %d %v", code, in)
	}
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND subject = $2 AND email = $3 AND name = $4 AND source = 'sign_in'`,
		tenantA, okonkwo.Subject, okonkwo.Email, okonkwo.Name); n != 1 {
		t.Fatalf("%d person rows after a sign-in", n)
	}
	// Again: still one row.
	if code, _, in := signInFresh(t, f, okonkwo); code != 200 || !in {
		t.Fatalf("second sign-in: %d %v", code, in)
	}
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND subject = $2`, tenantA, okonkwo.Subject); n != 1 {
		t.Fatalf("%d person rows after two sign-ins", n)
	}
	// On the page, by name; and the page is not shown to an employee.
	_, page := getHTML(t, f.fixture, hostA, "/people?q=martins", "a-itadmin")
	if !strings.Contains(page, "O. Martins") || !strings.Contains(page, okonkwo.Email) {
		t.Fatalf("the people page does not list the person:\n%s", page)
	}
	rec, _ := getHTML(t, f.fixture, hostA, "/people", "a-employee")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an employee read the people page: %d", rec.Code)
	}
}

// A device assigned by address before the person has ever signed in is
// theirs the moment they do: the address row gains their subject.
func TestADeviceAssignedByAddressIsTheirsAtFirstSignIn(t *testing.T) {
	f := newSignInFixture(t)
	dev := f.devices[tenantA][0]
	assign(t, dev, "O.Martins@kalesi.example")
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'o.martins@kalesi.example' AND subject = ''`, tenantA); n != 1 {
		t.Fatalf("%d address-only rows", n)
	}
	f.idp.SignInAs(okonkwo)
	if resp, body := f.browser.get("http://mdm.kalesi.example/signin"); resp.StatusCode != 200 {
		t.Fatalf("sign-in: %d %s", resp.StatusCode, body)
	}
	// One row, now with the subject.
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'o.martins@kalesi.example'`, tenantA); n != 1 {
		t.Fatalf("%d rows for the address after sign-in, want the one row claimed", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'o.martins@kalesi.example' AND subject = $2`, tenantA, okonkwo.Subject); n != 1 {
		t.Fatal("the address row did not gain the subject")
	}
	_, body := f.browser.get("http://mdm.kalesi.example/api/me/devices")
	if !strings.Contains(body, dev.String()) {
		t.Fatalf("the device assigned by address is not on the person's page: %s", body)
	}
}

// The limit 0009 wrote down, closed: the next hire with a leaver's address
// inherits nothing. The control --break-emailreuse lets the leaver's row
// answer for the address again.
func TestAReusedAddressInheritsNothing(t *testing.T) {
	f := newSignInFixture(t)
	dev := f.devices[tenantA][0]
	trustedCert(t, tenantA, dev)
	assign(t, dev, "kemi@kalesi.example")

	rec, body := do(t, f.fixture, jsonReq(t, "POST", hostA, "/api/people/offboard", "a-itadmin", map[string]any{"email": "kemi@kalesi.example"}))
	if rec.Code != http.StatusAccepted || body["count"] != float64(1) {
		t.Fatalf("offboard: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'kemi@kalesi.example' AND left_at IS NOT NULL`, tenantA); n != 1 {
		t.Fatalf("%d left rows", n)
	}

	// The new Kemi.
	newKemi := idptest.Person{Subject: "9f2c1a40-0000-4000-8000-00000000new1", Email: "kemi@kalesi.example",
		Name: "Kemi Adeleke", Groups: []string{"All-Staff"}}
	f.idp.SignInAs(newKemi)
	if resp, b := f.browser.get("http://mdm.kalesi.example/signin"); resp.StatusCode != 200 {
		t.Fatalf("new hire sign-in: %d %s", resp.StatusCode, b)
	}
	_, mine := f.browser.get("http://mdm.kalesi.example/api/me/devices")
	if strings.Contains(mine, dev.String()) {
		t.Fatalf("the new hire inherited the leaver's device: %s", mine)
	}
	// Two people with that address: one gone, one here.
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'kemi@kalesi.example'`, tenantA); n != 2 {
		t.Fatalf("%d rows for the address", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'kemi@kalesi.example' AND left_at IS NULL AND subject = $2`, tenantA, newKemi.Subject); n != 1 {
		t.Fatal("the new hire is not the active row")
	}
}

// The control --break-leftmark offboards the devices and forgets the
// person.
func TestOffboardingMarksThePersonLeftAndThePageSaysSo(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	trustedCert(t, tenantA, dev)
	assign(t, dev, "kemi@kalesi.example")
	_, page := getHTML(t, f, hostA, "/people", "a-itadmin")
	if !strings.Contains(page, "kemi@kalesi.example") || !strings.Contains(page, "not signed in yet") {
		t.Fatalf("people page before:\n%s", page)
	}
	var personID string
	_, page = getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if i := strings.Index(page, `href="/people/`); i < 0 {
		t.Fatalf("the device page does not link its holder:\n%s", page)
	} else {
		personID = page[i+len(`href="/people/`) : i+len(`href="/people/`)+36]
	}
	_, page = getHTML(t, f, hostA, "/people/"+personID, "a-itadmin")
	if !strings.Contains(page, "HQ-MBP-001") || !strings.Contains(page, "They have left") {
		t.Fatalf("person page:\n%s", page)
	}

	// From the person's page.
	rec := postForm(t, f, "a-itadmin", "/people/offboard", url.Values{"person": {personID}, "reason": {"left"}})
	if !strings.Contains(said(rec), "being offboarded") {
		t.Fatalf("offboard: %q", said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM people WHERE id = $1 AND left_at IS NOT NULL AND left_by = 'o.martins'`, personID); n != 1 {
		t.Fatal("the person was not marked left")
	}
	_, page = getHTML(t, f, hostA, "/people/"+personID, "a-itadmin")
	if !strings.Contains(page, "left ") || strings.Contains(page, "They have left") {
		t.Fatalf("person page after:\n%s", page)
	}
	// A device assigned to that address now is a new person's.
	assign(t, f.devices[tenantA][1], "kemi@kalesi.example")
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'kemi@kalesi.example'`, tenantA); n != 2 {
		t.Fatalf("%d rows; a leaver's address must start a new person", n)
	}
	// The help desk may look but not say someone has left.
	rec = postForm(t, f, "a-helpdesk", "/people/offboard", url.Values{"person": {personID}})
	if !strings.Contains(said(rec), "may not") {
		t.Fatalf("the help desk offboarded a person: %q", said(rec))
	}
}

func TestHRSayingAStrangerHasLeftIsKeptOnce(t *testing.T) {
	f := newFixture(t)
	hrTok, _ := mintScopedToken(t, f, "a-super", "Workday", "hr")
	for i := 0; i < 2; i++ {
		rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/hr/leavers", hrTok, map[string]any{"email": "ghost@kalesi.example"}))
		if rec.Code != http.StatusAccepted || body["count"] != float64(0) {
			t.Fatalf("leaver %d: %d %v", i, rec.Code, body)
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'ghost@kalesi.example' AND source = 'hr' AND left_at IS NOT NULL`, tenantA); n != 1 {
		t.Fatalf("%d rows for a stranger HR named twice", n)
	}
	// And a device assigned to that address afterwards is a new person,
	// not the one HR said had gone.
	assign(t, f.devices[tenantA][0], "ghost@kalesi.example")
	if n := adminCount(t, `SELECT count(*) FROM people WHERE tenant_id = $1 AND email = 'ghost@kalesi.example' AND left_at IS NULL`, tenantA); n != 1 {
		t.Fatal("the leaver's row took the assignment")
	}
}

func TestATenantsPeopleAreItsOwn(t *testing.T) {
	f := newFixture(t)
	assign(t, f.devices[tenantA][0], "kemi@kalesi.example")
	_, page := getHTML(t, f, hostB, "/people", "b-itadmin")
	if strings.Contains(page, "kemi@kalesi.example") {
		t.Fatal("tenant B saw tenant A's person")
	}
}
