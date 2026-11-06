package gateway

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The network's door, asked the way a NAC asks: by MAC address, and in
// the shape Cisco ISE asks in.

func withMACs(rep map[string]any, macs ...string) map[string]any {
	rep["mac_addresses"] = macs
	return rep
}

func basicReq(t *testing.T, host, path, user, pass string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", "http://"+host+path, nil)
	r.Host = host
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	return r
}

func TestTheDoorAnswersByMACInAnyForm(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	dev := f.devices[tenantA][0]
	token, _ := mintToken(t, f, "a-super", "Head office NAC")

	// Unknown before the device reports it.
	rec, body := do(t, f, req(t, "GET", hostA, "/api/network/access/mac/3c22.fbaa.bb01", token))
	if rec.Code != 404 || body["access"] != "unknown" {
		t.Fatalf("unreported MAC: %d %v", rec.Code, body)
	}
	if code, _ := reportAs(t, f, hostA, tenantA, dev, withMACs(map[string]any{"passcode_set": true, "disk_encryption": true},
		"3C:22:FB:AA:BB:01", "ac-de-48-00-11-22", "3C:22:FB:AA:BB:01", "junk")); code != 200 {
		t.Fatalf("report: %d", code)
	}
	for _, form := range []string{"3c:22:fb:aa:bb:01", "3C-22-FB-AA-BB-01", "3c22.fbaa.bb01", "3C22FBAABB01", "ac:de:48:00:11:22"} {
		rec, body = do(t, f, req(t, "GET", hostA, "/api/network/access/mac/"+form, token))
		if rec.Code != 200 || body["access"] != "allow" || body["serial"] != "C02XK4YTQ6NV" {
			t.Fatalf("%s: %d %v", form, rec.Code, body)
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM device_macs WHERE device_id = $1`, dev); n != 2 {
		t.Fatalf("%d addresses stored, want 2 (deduplicated, junk dropped)", n)
	}
	// The page shows them.
	_, page := getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if !strings.Contains(page, "3c:22:fb:aa:bb:01") || !strings.Contains(page, "ac:de:48:00:11:22") {
		t.Fatal("the device page does not show the addresses")
	}
	// Quarantined: deny by MAC, with the reason.
	if code, b := reportAs(t, f, hostA, tenantA, dev, withMACs(failingReport(), "3c:22:fb:aa:bb:01")); code != 200 || b["enforcement"] != "quarantined" {
		t.Fatalf("quarantine: %d %v", code, b)
	}
	rec, body = do(t, f, req(t, "GET", hostA, "/api/network/access/mac/3c:22:fb:aa:bb:01", token))
	if rec.Code != 200 || body["access"] != "deny" || body["state"] != "quarantined" || body["mac"] != "3c:22:fb:aa:bb:01" {
		t.Fatalf("quarantined by MAC: %d %v", rec.Code, body)
	}
	// An address the device stopped reporting is forgotten.
	rec, body = do(t, f, req(t, "GET", hostA, "/api/network/access/mac/ac:de:48:00:11:22", token))
	if rec.Code != 404 {
		t.Fatalf("a dropped address still answers: %d %v", rec.Code, body)
	}
	// Not a MAC at all.
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/network/access/mac/kettle", token)); rec.Code != 400 {
		t.Fatalf("junk: %d", rec.Code)
	}
}

// The control --break-macmove leaves an address with the device that
// reported it first. A dock moved from a quarantined laptop to a clean
// one would then keep the clean one off the network, and the reverse
// would let a quarantined one on.
func TestAnAddressFollowsTheDeviceThatReportsIt(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	first, second := f.devices[tenantA][0], f.devices[tenantA][1]
	token, _ := mintToken(t, f, "a-super", "NAC")
	const dock = "00:e0:4c:68:00:01"

	if code, _ := reportAs(t, f, hostA, tenantA, first, withMACs(map[string]any{"passcode_set": true, "disk_encryption": true}, dock)); code != 200 {
		t.Fatal("first report")
	}
	if code, b := reportAs(t, f, hostA, tenantA, first, withMACs(failingReport(), dock)); code != 200 || b["enforcement"] != "quarantined" {
		t.Fatalf("quarantine first: %d %v", code, b)
	}
	// The dock is plugged into the second laptop, which reports clean.
	if code, b := reportAs(t, f, hostA, tenantA, second, withMACs(map[string]any{"passcode_set": true, "disk_encryption": true}, dock)); code != 200 || b["state"] != "compliant" {
		t.Fatalf("second report: %d %v", code, b)
	}
	rec, body := do(t, f, req(t, "GET", hostA, "/api/network/access/mac/"+dock, token))
	if rec.Code != 200 || body["access"] != "allow" {
		t.Fatalf("the dock's address still answers for the quarantined laptop: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'device.mac_moved'`, tenantA); n != 1 {
		t.Fatalf("%d move audit rows", n)
	}
}

func TestATenantsAddressesAreItsOwn(t *testing.T) {
	f := newFixture(t)
	devA := f.devices[tenantA][0]
	// Tenant B's token, minted straight into B's rows: the fixture has no
	// Super Admin for B, and the console mints only at the caller's own
	// hostname.
	tokenB, hash, err := newIntegrationToken()
	if err != nil {
		t.Fatal(err)
	}
	exec(t, `INSERT INTO integration_tokens (tenant_id, name, token_hash, created_by) VALUES ($1, 'Tenant B NAC', $2, 'test')`, tenantB, hash)
	if code, _ := reportAs(t, f, hostA, tenantA, devA, withMACs(map[string]any{"passcode_set": true}, "3c:22:fb:aa:bb:01")); code != 200 {
		t.Fatal("report")
	}
	// Tenant B's NAC, at tenant B's hostname, asking about A's address.
	rec, body := do(t, f, req(t, "GET", hostB, "/api/network/access/mac/3c:22:fb:aa:bb:01", tokenB))
	if rec.Code != 404 || body["access"] != "unknown" {
		t.Fatalf("tenant B saw tenant A's device: %d %v", rec.Code, body)
	}
}

func TestCiscoISEIsAnsweredInItsOwnShape(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	dev := f.devices[tenantA][0]
	token, _ := mintToken(t, f, "a-super", "ISE")

	// ISE speaks Basic, token as the password.
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, basicReq(t, hostA, "/ciscoise/mdminfo", "ise", token))
	info := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "xml") {
		t.Fatalf("mdminfo: %d %s", rec.Code, info)
	}
	for _, want := range []string{"<name>mdminfo</name>", "<api_version>2</api_version>", "<api_path>/ciscoise/mdmapi</api_path>", "<redirect_url>https://" + hostA + "/me</redirect_url>"} {
		if !strings.Contains(info, want) {
			t.Fatalf("mdminfo lacks %s:\n%s", want, info)
		}
	}
	// The operator's name is nowhere in it; the tenant's is.
	if strings.Contains(info, "Operator") || !strings.Contains(info, "<product_name>") {
		t.Fatalf("mdminfo brand:\n%s", info)
	}

	// A wrong password is refused, token or not in the username.
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, basicReq(t, hostA, "/ciscoise/mdminfo", token, "wrong"))
	if rec.Code != 401 {
		t.Fatalf("a wrong password was accepted: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, basicReq(t, hostA, "/ciscoise/mdminfo", "ise", "mdm_net_not-a-real-token"))
	if rec.Code != 401 {
		t.Fatalf("a made-up token was accepted: %d", rec.Code)
	}

	// A compliant device, by MAC.
	if code, _ := reportAs(t, f, hostA, tenantA, dev, withMACs(map[string]any{"passcode_set": true, "disk_encryption": true, "os_version": "15.2"}, "3c:22:fb:aa:bb:01")); code != 200 {
		t.Fatal("report")
	}
	query := "/ciscoise/mdmapi?ise_api_version=2&querycriteria=macaddress&value=3C-22-FB-AA-BB-01&filter=all"
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, basicReq(t, hostA, query, "ise", token))
	ans := rec.Body.String()
	for _, want := range []string{"<name>attributes</name>", "<macaddress>3c:22:fb:aa:bb:01</macaddress>", "<register_status>true</register_status>",
		"<status>true</status>", "<disk_encryption_on>true</disk_encryption_on>", "<pin_lock_on>true</pin_lock_on>",
		"<serial_number>C02XK4YTQ6NV</serial_number>", "<os_version>15.2</os_version>", "<udid>" + dev.String() + "</udid>"} {
		if rec.Code != 200 || !strings.Contains(ans, want) {
			t.Fatalf("compliant answer lacks %s (%d):\n%s", want, rec.Code, ans)
		}
	}
	if strings.Contains(ans, "<jail_broken>") {
		t.Fatalf("the device did not say whether it is jailbroken, yet the answer does:\n%s", ans)
	}

	// Quarantined: not compliant, with the reason. The control
	// --break-isecompliance says compliant for every registered device.
	if code, b := reportAs(t, f, hostA, tenantA, dev, withMACs(failingReport(), "3c:22:fb:aa:bb:01")); code != 200 || b["enforcement"] != "quarantined" {
		t.Fatalf("quarantine: %d %v", code, b)
	}
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, basicReq(t, hostA, query, "ise", token))
	ans = rec.Body.String()
	if rec.Code != 200 || !strings.Contains(ans, "<status>false</status>") || !strings.Contains(ans, "<failure_reason>") ||
		!strings.Contains(ans, "<pin_lock_on>false</pin_lock_on>") {
		t.Fatalf("quarantined answer (%d):\n%s", rec.Code, ans)
	}

	// An address nobody reported: registered false.
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, basicReq(t, hostA, "/ciscoise/mdmapi?querycriteria=macaddress&value=0011.2233.4455", "ise", token))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<register_status>false</register_status>") {
		t.Fatalf("unknown MAC (%d):\n%s", rec.Code, rec.Body.String())
	}
	// A full-fleet query is said to be elsewhere, not answered empty.
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, basicReq(t, hostA, "/ciscoise/mdmapi?querycriteria=all", "ise", token))
	if rec.Code != 400 {
		t.Fatalf("querycriteria=all: %d", rec.Code)
	}
	// And the bearer path still works for the same token.
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/network/access/mac/3c:22:fb:aa:bb:01", token)); rec.Code != 200 {
		t.Fatalf("bearer: %d", rec.Code)
	}
}
