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

// withMACs adds the addresses to a report. None given is an empty list,
// which says "no addresses"; nil would say "did not say" and leave the
// stored ones alone.
func withMACs(rep map[string]any, macs ...string) map[string]any {
	if macs == nil {
		macs = []string{}
	}
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

// An address moves with the dock: the first laptop stops reporting it,
// the second reports it, and the door answers for the second. The control
// --break-macmove leaves it with the first.
func TestAnAddressFollowsTheDeviceThatReportsIt(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	first, second := f.devices[tenantA][0], f.devices[tenantA][1]
	token, _ := mintToken(t, f, "a-super", "NAC")
	const dock = "00:e0:4c:68:00:01"
	clean := func() map[string]any { return map[string]any{"passcode_set": true, "disk_encryption": true} }

	if code, _ := reportAs(t, f, hostA, tenantA, first, withMACs(clean(), dock)); code != 200 {
		t.Fatal("first report")
	}
	// Unplugged: the first laptop's next report no longer lists it, and
	// the row goes; the second laptop's claim lands on nothing.
	if code, _ := reportAs(t, f, hostA, tenantA, first, withMACs(clean())); code != 200 {
		t.Fatal("first report without the dock")
	}
	if code, _ := reportAs(t, f, hostA, tenantA, second, withMACs(clean(), dock)); code != 200 {
		t.Fatal("second report")
	}
	rec, body := do(t, f, req(t, "GET", hostA, "/api/network/access/mac/"+dock, token))
	if rec.Code != 200 || body["access"] != "allow" || body["serial"] == "C02XK4YTQ6NV" {
		t.Fatalf("the dock's address does not answer for the second laptop: %d %v", rec.Code, body)
	}
	// A holder that has gone quiet for longer than the engine tolerates
	// has let go: the first laptop claims the dock while the second is
	// stale, and gets it.
	exec(t, `UPDATE devices SET last_report_at = now() - interval '10 days' WHERE id = $1`, second)
	if code, _ := reportAs(t, f, hostA, tenantA, first, withMACs(clean(), dock)); code != 200 {
		t.Fatal("first claims it back")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'device.mac_moved'`, tenantA); n != 1 {
		t.Fatalf("%d move audit rows, want 1 (the stale holder's)", n)
	}
	rec, body = do(t, f, req(t, "GET", hostA, "/api/network/access/mac/"+dock, token))
	if rec.Code != 200 || body["serial"] != "C02XK4YTQ6NV" {
		t.Fatalf("after the stale holder let go: %d %v", rec.Code, body)
	}
	// A retired holder has let go too: the first laptop is retired and the
	// second, reporting again, takes the dock.
	exec(t, `UPDATE devices SET state = 'retired' WHERE id = $1`, first)
	if code, _ := reportAs(t, f, hostA, tenantA, second, withMACs(clean(), dock)); code != 200 {
		t.Fatal("second takes it from the retired holder")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'device.mac_moved'`, tenantA); n != 2 {
		t.Fatalf("%d move audit rows, want 2", n)
	}
	rec, body = do(t, f, req(t, "GET", hostA, "/api/network/access/mac/"+dock, token))
	if rec.Code != 200 || body["serial"] == "C02XK4YTQ6NV" {
		t.Fatalf("after the retired holder let go: %d %v", rec.Code, body)
	}
}

// A device's own report cannot take an address a reporting device holds,
// and never one a quarantined device holds: otherwise a quarantined laptop
// could report a clean one's address, or a clean-reporting agent could
// claim the quarantined one's, and the door would answer for the wrong
// machine. The claim is written down instead.
func TestAReportCannotTakeAnAddressAnotherDeviceHolds(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	first, second := f.devices[tenantA][0], f.devices[tenantA][1]
	token, _ := mintToken(t, f, "a-super", "NAC")
	const mac = "3c:22:fb:aa:bb:01"
	clean := func() map[string]any { return map[string]any{"passcode_set": true, "disk_encryption": true} }

	// The second laptop is quarantined holding the address. The first,
	// clean, claims it: refused, and the door still says deny for it.
	if code, b := reportAs(t, f, hostA, tenantA, second, withMACs(failingReport(), mac)); code != 200 || b["enforcement"] != "quarantined" {
		t.Fatalf("quarantine: %d %v", code, b)
	}
	if code, _ := reportAs(t, f, hostA, tenantA, first, withMACs(clean(), mac)); code != 200 {
		t.Fatal("claim")
	}
	rec, body := do(t, f, req(t, "GET", hostA, "/api/network/access/mac/"+mac, token))
	if rec.Code != 200 || body["access"] != "deny" || body["state"] != "quarantined" {
		t.Fatalf("a clean report took a quarantined device's address: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'device.mac_contested'`, tenantA); n != 1 {
		t.Fatalf("%d contested audit rows", n)
	}
	// And the other way: a reporting, clean holder keeps its address from
	// any other device's report.
	const other = "ac:de:48:00:11:22"
	if code, _ := reportAs(t, f, hostA, tenantA, first, withMACs(clean(), other)); code != 200 {
		t.Fatal("first holds another")
	}
	if code, _ := reportAs(t, f, hostA, tenantA, second, withMACs(failingReport(), mac, other)); code != 200 {
		t.Fatal("second claims it")
	}
	rec, body = do(t, f, req(t, "GET", hostA, "/api/network/access/mac/"+other, token))
	if rec.Code != 200 || body["access"] != "allow" {
		t.Fatalf("a report took a reporting device's address: %d %v", rec.Code, body)
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
