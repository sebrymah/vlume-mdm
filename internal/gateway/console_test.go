package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The console is rendered through the same front door as the API, so these
// tests are the same isolation and role assertions seen from the browser.

func getHTML(t *testing.T, f fixture, host, path, bearer string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	r := httptest.NewRequest("GET", "http://"+host+path, nil)
	r.Host = host
	if bearer != "" {
		r.AddCookie(&http.Cookie{Name: "session", Value: f.cookie(t, bearer)})
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	b, _ := io.ReadAll(rec.Body)
	return rec, string(b)
}

// A browser sends a cookie rather than an Authorization header. It is the
// same session value verified the same way, not a second trust path.
func TestConsoleAcceptsASessionCookie(t *testing.T) {
	f := newFixture(t)
	rec, body := getHTML(t, f, hostA, "/", "a-itadmin")
	if rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(body, "Dashboard") {
		t.Fatal("the dashboard did not render")
	}
}

// T4. One deployment, one stylesheet, and the brand arrives as data on every
// request. Tenant A has branded itself; tenant B deliberately has not.
func TestEachTenantSeesItsOwnBrand(t *testing.T) {
	f := newFixture(t)

	_, a := getHTML(t, f, hostA, "/", "a-itadmin")
	if !strings.Contains(a, "Kalesi Device Care") {
		t.Fatal("tenant A's console does not carry tenant A's product name")
	}
	if !strings.Contains(a, "#0F6E66") {
		t.Fatal("tenant A's brand colour did not reach the stylesheet")
	}
	if !strings.Contains(a, "Kalesi Foods Ltd") {
		t.Fatal("tenant A's legal footer is missing")
	}

	_, b := getHTML(t, f, hostB, "/", "b-itadmin")
	if strings.Contains(b, "Kalesi") {
		t.Fatal("tenant A's brand leaked into tenant B's console")
	}
}

// A tenant that has not replaced the placeholder has not gone live, and the
// console says so rather than letting it quietly ship.
func TestUnbrandedTenantIsToldSoLoudly(t *testing.T) {
	f := newFixture(t)

	_, b := getHTML(t, f, hostB, "/", "b-itadmin")
	if !strings.Contains(b, "[YOUR PRODUCT NAME]") {
		t.Fatal("an unbranded tenant is not showing the placeholder")
	}
	if !strings.Contains(b, "has not been branded yet") {
		t.Fatal("an unbranded tenant is not being warned")
	}

	_, a := getHTML(t, f, hostA, "/", "a-itadmin")
	if strings.Contains(a, "has not been branded yet") {
		t.Fatal("a branded tenant is being warned anyway")
	}
}

// T12, as a build gate rather than a promise. The design document said to
// write this in Phase 1 and let it fail the build from the beginning, because
// by Phase 3 a product name is in email templates, PDF footers and error
// strings and taking it out is a different job.
func TestNoForeignBrandAppearsOnAnyTenantSurface(t *testing.T) {
	f := newFixture(t)

	// Words that must never reach a tenant-facing page: another tenant's
	// identity, and any operator or vendor name. The operator list is empty
	// today because the product is deliberately unbranded; when it has a
	// name, that name goes here and this test starts earning its keep.
	operatorWords := []string{"Acme", "Vendor", "Internal Use Only"}

	for _, c := range []struct{ host, bearer, foreign string }{
		{hostA, "a-itadmin", "Arbor"},
		{hostB, "b-itadmin", "Kalesi"},
	} {
		for _, path := range []string{"/", "/devices", "/audit"} {
			rec, body := getHTML(t, f, c.host, path, c.bearer)
			if rec.Code != 200 {
				t.Fatalf("%s%s: got %d", c.host, path, rec.Code)
			}
			if strings.Contains(body, c.foreign) {
				t.Errorf("%s%s carries another tenant's brand %q", c.host, path, c.foreign)
			}
			for _, w := range operatorWords {
				if strings.Contains(body, w) {
					t.Errorf("%s%s carries %q, which is not the tenant's", c.host, path, w)
				}
			}
		}
	}
}

// A section a role may not use is absent, not present and disabled. A
// disabled control still advertises a capability and invites a request for it.
func TestNavigationIsBuiltFromTheRoleMatrix(t *testing.T) {
	f := newFixture(t)

	_, helpdesk := getHTML(t, f, hostA, "/", "a-helpdesk")
	if strings.Contains(helpdesk, `href="/audit"`) {
		t.Error("the helpdesk is being shown a link to the audit log")
	}
	if !strings.Contains(helpdesk, `href="/devices"`) {
		t.Error("the helpdesk cannot reach devices, which it may see")
	}

	_, auditor := getHTML(t, f, hostA, "/", "a-auditor")
	if !strings.Contains(auditor, `href="/audit"`) {
		t.Error("the auditor cannot reach the audit log")
	}

	rec, _ := getHTML(t, f, hostA, "/audit", "a-helpdesk")
	if rec.Code != http.StatusForbidden {
		t.Errorf("the helpdesk reached the audit log directly: got %d", rec.Code)
	}
}

// The same rule as the API: another tenant's device is not found, never
// forbidden, because forbidden would confirm it exists.
func TestConsoleDoesNotRevealAnotherTenantsDevice(t *testing.T) {
	f := newFixture(t)
	bDevice := f.devices[tenantB][0]

	rec, body := getHTML(t, f, hostA, "/devices/"+bDevice.String(), "a-super")
	if rec.Code == http.StatusForbidden {
		t.Fatal("answered 403, which confirms the device exists in another tenant")
	}
	if !strings.Contains(body, "No such device") {
		t.Fatal("the page did not say the device is not there")
	}
	if strings.Contains(body, "HQ-") {
		t.Fatal("another tenant's device name rendered")
	}

	// And the same identifier is found from its own tenant, so the assertion
	// above could not pass on a page that shows nothing to anyone.
	rec, body = getHTML(t, f, hostB, "/devices/"+bDevice.String(), "b-itadmin")
	if rec.Code != 200 || !strings.Contains(body, "HQ-") {
		t.Fatalf("tenant B cannot see its own device: %d", rec.Code)
	}
}

func TestConsoleListsOnlyTheTenantsOwnDevices(t *testing.T) {
	f := newFixture(t)

	_, a := getHTML(t, f, hostA, "/devices", "a-itadmin")
	if n := strings.Count(a, `href="/devices/`); n != 2 {
		t.Fatalf("tenant A's device list has %d rows, want 2", n)
	}

	_, b := getHTML(t, f, hostB, "/devices", "b-itadmin")
	if n := strings.Count(b, `href="/devices/`); n != 3 {
		t.Fatalf("tenant B's device list has %d rows, want 3", n)
	}
}

// A form's "return" field is a path on this site or nothing: a
// protocol-relative address would send the person off the site with a
// message in the query string.
func TestAFormCannotReturnTheBrowserOffTheSite(t *testing.T) {
	f := newFixture(t)
	for _, bad := range []string{"//evil.example/x", "/\\evil.example", "https://evil.example", "/ok\r\nLocation: x"} {
		rec := postForm(t, f, "a-itadmin", "/people/offboard", url.Values{"return": {bad}})
		loc := rec.Header().Get("Location")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/devices?") && !strings.HasPrefix(loc, "/people") {
			t.Fatalf("return %q sent the browser to %q (%d)", bad, loc, rec.Code)
		}
	}
}
