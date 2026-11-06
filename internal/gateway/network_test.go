package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// Network-side revocation. The network holds a token and asks; the tests
// are about what the token can and cannot do, and what the feed says.

var tokenRE = regexp.MustCompile(`mdm_net_[A-Za-z0-9_-]{43}`)

// mintToken is a Super Admin minting one from the console. The token is in
// the page, once, and nowhere else.
func mintToken(t *testing.T, f fixture, bearer, name string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	cookie := f.cookie(t, bearer)
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	vals := url.Values{"name": {name},
		"csrf": {f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)}}
	r := httptest.NewRequest("POST", "http://"+hostA+"/identity/tokens", strings.NewReader(vals.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return tokenRE.FindString(rec.Body.String()), rec
}

func TestTheNetworkAsksWithATokenAndIsToldAllowOrDeny(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	dev := f.devices[tenantA][0]
	const serial = "C02XK4YTQ6NV" // HQ-MBP-001 in tenant A

	token, rec := mintToken(t, f, "a-super", "Head office Wi-Fi")
	if rec.Code != 200 || token == "" {
		t.Fatalf("mint: %d, token %q", rec.Code, token)
	}
	// Stored hashed, shown once.
	if n := adminCount(t, `SELECT count(*) FROM integration_tokens WHERE tenant_id = $1`, tenantA); n != 1 {
		t.Fatalf("%d token rows", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM integration_tokens WHERE position($1::bytea in token_hash) > 0`,
		[]byte(strings.TrimPrefix(token, "mdm_net_")[:16])); n != 0 {
		t.Fatal("the token is stored in the clear")
	}
	_, page := getHTML(t, f, hostA, "/identity", "a-super")
	if strings.Contains(page, token) {
		t.Fatal("the token is shown again on the next page load")
	}
	if !strings.Contains(page, "Head office Wi-Fi") {
		t.Fatal("the integration is not listed")
	}

	// A device that has never reported: deny. Not knowing is not a pass,
	// at the door as everywhere else.
	rec2, body := do(t, f, req(t, "GET", hostA, "/api/network/access/"+serial, token))
	if rec2.Code != 200 || body["access"] != "deny" || body["reason"] != "has never reported" {
		t.Fatalf("never-reported device: %d %v", rec2.Code, body)
	}
	// A clean report: allow.
	if code, b := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_set": true, "disk_encryption": true}); code != 200 || b["state"] != "compliant" {
		t.Fatalf("clean report: %d %v", code, b)
	}
	rec2, body = do(t, f, req(t, "GET", hostA, "/api/network/access/"+serial, token))
	if rec2.Code != 200 || body["access"] != "allow" {
		t.Fatalf("healthy device: %d %v", rec2.Code, body)
	}
	// A clean report that has gone stale is no longer clean.
	exec(t, `UPDATE devices SET last_report_at = now() - interval '10 days' WHERE id = $1`, dev)
	rec2, body = do(t, f, req(t, "GET", hostA, "/api/network/access/"+serial, token))
	if rec2.Code != 200 || body["access"] != "deny" || body["reason"] != "no report for 10 days" {
		t.Fatalf("stale device: %d %v", rec2.Code, body)
	}
	exec(t, `UPDATE devices SET last_report_at = now() WHERE id = $1`, dev)
	// F9 quarantines it: deny, with the reason.
	if code, b := reportAs(t, f, hostA, tenantA, dev, failingReport()); code != 200 || b["enforcement"] != "quarantined" {
		t.Fatalf("quarantine: %d %v", code, b)
	}
	rec2, body = do(t, f, req(t, "GET", hostA, "/api/network/access/"+serial, token))
	if rec2.Code != 200 || body["access"] != "deny" || body["state"] != "quarantined" || body["reason"] == "" {
		t.Fatalf("quarantined device: %d %v", rec2.Code, body)
	}
	// And it is on the block list, with the tenant's other device that
	// has never reported.
	rec2, body = do(t, f, req(t, "GET", hostA, "/api/network/denied", token))
	denied, _ := body["denied"].([]any)
	if rec2.Code != 200 || len(denied) != 2 {
		t.Fatalf("block list: %d %v", rec2.Code, body)
	}
	// A person releases it: still deny, because nothing has been checked
	// since, and the network is told. A clean report then opens the door.
	if rec := postForm(t, f, "a-itadmin", "/devices/"+dev.String()+"/release", url.Values{}); !strings.Contains(said(rec), "Released") {
		t.Fatalf("release: %q", said(rec))
	}
	rec2, body = do(t, f, req(t, "GET", hostA, "/api/network/access/"+serial, token))
	if rec2.Code != 200 || body["access"] != "deny" || body["state"] != "state_unknown" {
		t.Fatalf("released device: %d %v", rec2.Code, body)
	}
	if code, b := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_set": true, "disk_encryption": true}); code != 200 || b["device_state"] != "compliant" {
		t.Fatalf("clean report after release: %d %v", code, b)
	}
	rec2, body = do(t, f, req(t, "GET", hostA, "/api/network/access/"+serial, token))
	if rec2.Code != 200 || body["access"] != "allow" {
		t.Fatalf("released and clean: %d %v", rec2.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'device.released'`, tenantA); n != 1 {
		t.Fatalf("%d release notifications", n)
	}
	// A serial we do not manage, including tenant B's: unknown, not allow.
	for _, s := range []string{"NOT-A-SERIAL", "SN-00000009"} {
		rec2, body = do(t, f, req(t, "GET", hostA, "/api/network/access/"+s, token))
		if rec2.Code != 404 || body["access"] != "unknown" {
			t.Fatalf("%s: %d %v", s, rec2.Code, body)
		}
	}
	// The page shows it has been asking.
	if n := adminCount(t, `SELECT count(*) FROM integration_tokens WHERE tenant_id = $1 AND last_used_at IS NOT NULL`, tenantA); n != 1 {
		t.Fatal("last_used_at was not recorded")
	}
}

func TestATokenReadsTheFeedAndNothingElse(t *testing.T) {
	f := newFixture(t)
	token, _ := mintToken(t, f, "a-super", "VPN")
	if token == "" {
		t.Fatal("no token")
	}
	for _, path := range []string{"/api/devices", "/api/audit", "/api/policies", "/api/enrolments",
		"/api/me/devices", "/api/notifications", "/api/setup"} {
		rec, _ := do(t, f, req(t, "GET", hostA, path, token))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("a network token read %s: %d", path, rec.Code)
		}
	}
	rec, _ := do(t, f, req(t, "POST", hostA, "/api/devices/"+f.devices[tenantA][0].String()+"/lock", token))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a network token locked a device: %d", rec.Code)
	}
	// At another tenant's hostname it is nothing at all.
	rec, _ = do(t, f, req(t, "GET", hostB, "/api/network/denied", token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tenant A's token worked at tenant B: %d", rec.Code)
	}
	// Only a Super Admin mints one.
	for _, bearer := range []string{"a-itadmin", "a-secmgr", "a-helpdesk"} {
		tok, _ := mintToken(t, f, bearer, "Mine")
		if tok != "" {
			t.Fatalf("%s minted a token", bearer)
		}
	}
}

func TestARevokedTokenIsRefusedFromItsNextRequest(t *testing.T) {
	f := newFixture(t)
	token, _ := mintToken(t, f, "a-super", "Old NAC")
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/network/denied", token)); rec.Code != 200 {
		t.Fatalf("before revoke: %d", rec.Code)
	}
	_, page := getHTML(t, f, hostA, "/identity", "a-super")
	m := regexp.MustCompile(`/identity/tokens/([0-9a-f-]{36})/revoke`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no revoke control on the page")
	}
	if rec := postForm(t, f, "a-super", "/identity/tokens/"+m[1]+"/revoke", url.Values{}); !strings.Contains(said(rec), "Revoked") {
		t.Fatalf("revoke: %q", said(rec))
	}
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/network/denied", token)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke: %d", rec.Code)
	}
	// The record stays.
	if n := adminCount(t, `SELECT count(*) FROM integration_tokens WHERE tenant_id = $1 AND revoked_at IS NOT NULL`, tenantA); n != 1 {
		t.Fatal("the revoked token vanished")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action IN ('integration.created','integration.revoked')`, tenantA); n != 2 {
		t.Fatalf("%d integration audit records", n)
	}
}
