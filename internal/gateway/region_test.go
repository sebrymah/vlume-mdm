package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// T11. A tenant's region is chosen once and kept; a deployment serving
// one region refuses a tenant of another, whatever hostname it uses.

func TestADeploymentServesOnlyTenantsOfItsOwnRegion(t *testing.T) {
	f := newFixture(t)
	f.g.region = "eu-west"
	f.h = f.g.Handler()
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/devices", "a-itadmin")); rec.Code != 200 {
		t.Fatalf("a tenant of this region: %d", rec.Code)
	}
	exec(t, `UPDATE tenants SET region = 'af-south' WHERE id = $1`, tenantA)
	rec, body := do(t, f, req(t, "GET", hostA, "/api/devices", "a-itadmin"))
	if rec.Code != http.StatusForbidden || !strings.Contains(body["error"].(string), "another region") {
		t.Fatalf("a tenant of another region was served: %d %v", rec.Code, body)
	}
	// Tenant B, still in this region, is unaffected.
	if rec, _ := do(t, f, req(t, "GET", hostB, "/api/devices", "b-itadmin")); rec.Code != 200 {
		t.Fatalf("tenant B: %d", rec.Code)
	}
}

func TestSignUpRecordsTheChosenRegion(t *testing.T) {
	f := withSignup(t, newFixture(t))
	f.g.signup.Regions = []string{"eu-west", "af-south"}
	token := askFor(t, f, "ada@region.example", "Region Co", "203.0.113.40")
	public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.40", url.Values{"slug": {"su-region"}})
	rec := public(t, f, "GET", signupHost, "/signup/"+token, "203.0.113.40", nil)
	if !strings.Contains(rec.Body.String(), "Where your data is kept") {
		t.Fatal("the region choice is not offered")
	}
	rec = public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.40", url.Values{
		"issuer": {"https://login.example/v2.0"}, "client_id": {"c"}, "client_secret": {"s"},
		"admin_group": {"Owners"}, "region": {"af-south"},
	})
	if rec.Code != 303 || !strings.HasSuffix(rec.Header().Get("Location"), "/done") {
		t.Fatalf("finish: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if region := adminString(t, `SELECT region FROM tenants WHERE slug = 'su-region'`); region != "af-south" {
		t.Fatalf("the tenant's region is %q", region)
	}
	// A region the operator does not offer falls back to the default.
	token = askFor(t, f, "bola@region.example", "Region Two", "203.0.113.41")
	public(t, f, "POST", signupHost, "/signup/"+token+"/slug", "203.0.113.41", url.Values{"slug": {"su-region2"}})
	public(t, f, "POST", signupHost, "/signup/"+token+"/finish", "203.0.113.41", url.Values{
		"issuer": {"https://login.example/v2.0"}, "client_id": {"c"}, "client_secret": {"s"},
		"admin_group": {"Owners"}, "region": {"mars"},
	})
	if region := adminString(t, `SELECT region FROM tenants WHERE slug = 'su-region2'`); region != "eu-west" {
		t.Fatalf("an unoffered region was recorded: %q", region)
	}
}
