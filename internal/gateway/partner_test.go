package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// T7. A partner manages its own tenants under its brand and sees nothing
// of another partner's, and nothing inside any tenant.

func partnerReq(t *testing.T, f fixture, method, path, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := jsonReq(t, method, signupHost, path, token, body)
	r.RemoteAddr = "203.0.113.77:1"
	return do(t, f, r)
}

func TestAPartnerManagesItsOwnTenantsAndNoOthers(t *testing.T) {
	f := withSignup(t, newFixture(t))
	ctx := context.Background()
	_, tokA, err := f.g.dir.CreatePartner(ctx, "resell-a", "Reseller A", "Fleet Care", "#1F4E79", "Reseller A Ltd", 2)
	if err != nil {
		t.Fatalf("partner A: %v", err)
	}
	_, tokB, err := f.g.dir.CreatePartner(ctx, "resell-b", "Reseller B", "", "", "", 5)
	if err != nil {
		t.Fatalf("partner B: %v", err)
	}
	cleanPartnerTenants := func() {
		adminExec(t, `DELETE FROM tenant_branding WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'pt-%')`)
		adminExec(t, `DELETE FROM tenant_keys WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'pt-%')`)
		adminExec(t, `DELETE FROM tenant_role_map WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'pt-%')`)
		adminExec(t, `DELETE FROM tenant_identity WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'pt-%')`)
		adminExec(t, `DELETE FROM tenant_domains WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'pt-%')`)
		adminExec(t, `DELETE FROM tenants WHERE slug LIKE 'pt-%'`)
	}
	cleanPartnerTenants()
	t.Cleanup(cleanPartnerTenants)

	newTenant := func(slug string) map[string]any {
		return map[string]any{
			"name": "Customer " + slug, "slug": slug, "host": slug + ".partner.example", "plan": "starter",
			"issuer": "https://login.example/v2.0", "client_id": "c", "client_secret": "s", "admin_group": "Owners",
		}
	}
	// No token, a bad token.
	if rec, _ := partnerReq(t, f, "GET", "/partner/tenants", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec, _ := partnerReq(t, f, "GET", "/partner/tenants", "mdm_prt_"+strings.Repeat("A", 43), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a bad token: %d", rec.Code)
	}
	// A creates a tenant: branded with A's brand, counted against A's cap.
	rec, body := partnerReq(t, f, "POST", "/partner/tenants", tokA, newTenant("pt-one"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %v", rec.Code, body)
	}
	if brand := adminString(t, `SELECT b.product_name FROM tenant_branding b JOIN tenants t ON t.id = b.tenant_id WHERE t.slug = 'pt-one'`); brand != "Fleet Care" {
		t.Fatalf("the new tenant's brand is %q, want the partner's", brand)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenants t JOIN partners p ON p.id = t.partner_id WHERE t.slug = 'pt-one' AND p.slug = 'resell-a'`); n != 1 {
		t.Fatal("the tenant is not marked as partner A's")
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_keys k JOIN tenants t ON t.id = k.tenant_id WHERE t.slug = 'pt-one'`); n != 1 {
		t.Fatal("the new tenant has no key")
	}
	partnerReq(t, f, "POST", "/partner/tenants", tokA, newTenant("pt-two"))
	if rec, body := partnerReq(t, f, "POST", "/partner/tenants", tokA, newTenant("pt-three")); rec.Code != http.StatusConflict || !strings.Contains(body["error"].(string), "cap") {
		t.Fatalf("a third tenant over a cap of two: %d %v", rec.Code, body)
	}
	// A lists two; B lists none.
	_, body = partnerReq(t, f, "GET", "/partner/tenants", tokA, nil)
	if n := len(body["tenants"].([]any)); n != 2 {
		t.Fatalf("A lists %d tenants", n)
	}
	_, body = partnerReq(t, f, "GET", "/partner/tenants", tokB, nil)
	if n := len(body["tenants"].([]any)); n != 0 {
		t.Fatalf("B lists %d tenants, A's among them", n)
	}
	// B cannot meter or suspend A's tenant; A can.
	if rec, _ := partnerReq(t, f, "GET", "/partner/tenants/pt-one/usage", tokB, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("B metered A's tenant: %d", rec.Code)
	}
	if rec, _ := partnerReq(t, f, "POST", "/partner/tenants/pt-one/suspend", tokB, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("B suspended A's tenant: %d", rec.Code)
	}
	if rec, body := partnerReq(t, f, "GET", "/partner/tenants/pt-one/usage", tokA, nil); rec.Code != 200 || body["plan"] != "starter" {
		t.Fatalf("A's usage: %d %v", rec.Code, body)
	}
	if rec, _ := partnerReq(t, f, "POST", "/partner/tenants/pt-one/suspend", tokA, nil); rec.Code != 200 {
		t.Fatalf("A suspend: %d", rec.Code)
	}
	if st := adminString(t, `SELECT status FROM tenants WHERE slug = 'pt-one'`); st != "suspended" {
		t.Fatalf("after suspend: %s", st)
	}
	// Neither partner sees the operator's own tenant, kalesi.
	_, body = partnerReq(t, f, "GET", "/partner/tenants", tokA, nil)
	for _, tn := range body["tenants"].([]any) {
		if tn.(map[string]any)["Slug"] == "kalesi" {
			t.Fatal("a partner lists the operator's own tenant")
		}
	}
	// A rotated token: the old one dies.
	newTok, err := f.g.dir.RotatePartnerToken(ctx, "resell-a")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rec, _ := partnerReq(t, f, "GET", "/partner/tenants", tokA, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the old partner token still works: %d", rec.Code)
	}
	if rec, _ := partnerReq(t, f, "GET", "/partner/tenants", newTok, nil); rec.Code != 200 {
		t.Fatalf("the new partner token: %d", rec.Code)
	}
}
