package gateway

import (
	"net/http"
	"strings"
	"testing"
)

// F3: who has what. F11: the recovery key, escrowed sealed, revealed on
// the record by the roles that hold key.retrieve.

func TestADeviceReportsItsAppsAndTheFleetCanBeSearched(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	devs := f.devices[tenantA]
	report := func(dev string, apps []map[string]any) {
		t.Helper()
		id := f.devices[tenantA][0]
		if dev == "second" {
			id = devs[1]
		}
		code, body := reportAs(t, f, hostA, tenantA, id, map[string]any{
			"passcode_set": true, "passcode_length": 12, "disk_encryption": true, "apps": apps,
		})
		if code != 200 {
			t.Fatalf("report: %d %v", code, body)
		}
	}
	report("first", []map[string]any{
		{"identifier": "us.zoom.xos", "name": "zoom.us", "version": "6.1.0"},
		{"identifier": "com.apple.Safari", "name": "Safari", "version": "18.0"},
	})
	report("second", []map[string]any{
		{"identifier": "us.zoom.xos", "name": "zoom.us", "version": "5.9.3"},
	})
	rec, body := do(t, f, req(t, "GET", hostA, "/api/devices/"+devs[0].String()+"/apps", "a-helpdesk"))
	if rec.Code != 200 || len(body["apps"].([]any)) != 2 {
		t.Fatalf("apps: %d %v", rec.Code, body)
	}
	rec, body = do(t, f, req(t, "GET", hostA, "/api/apps?name=zoom", "a-auditor"))
	found, _ := body["devices"].([]any)
	if rec.Code != 200 || len(found) != 2 {
		t.Fatalf("search: %d %v", rec.Code, body)
	}
	// A new report replaces the list: Zoom removed from the first device.
	report("first", []map[string]any{{"identifier": "com.apple.Safari", "name": "Safari", "version": "18.1"}})
	_, body = do(t, f, req(t, "GET", hostA, "/api/apps?name=zoom", "a-auditor"))
	if n := len(body["devices"].([]any)); n != 1 {
		t.Fatalf("after the first device dropped Zoom, %d devices still have it", n)
	}
	// Tenant B sees none of it.
	_, body = do(t, f, req(t, "GET", hostB, "/api/apps?name=zoom", "b-itadmin"))
	if n := len(body["devices"].([]any)); n != 0 {
		t.Fatal("tenant B searched tenant A's apps")
	}
	// The pages.
	_, page := getHTML(t, f, hostA, "/apps?q=safari", "a-itadmin")
	if !strings.Contains(page, "Safari") || !strings.Contains(page, "18.1") {
		t.Fatal("the apps page does not show the search")
	}
	_, page = getHTML(t, f, hostA, "/devices/"+devs[0].String(), "a-itadmin")
	if !strings.Contains(page, "Installed apps") || !strings.Contains(page, "com.apple.Safari") {
		t.Fatal("the device page does not list its apps")
	}
}

func TestARecoveryKeyIsEscrowedSealedAndRevealedOnTheRecord(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	cert := trustedCert(t, tenantA, dev)

	// Only a device, about itself.
	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/my/recovery-key", "a-itadmin",
		map[string]any{"kind": "filevault", "key": "AAAA-BBBB"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an administrator escrowed a key: %d", rec.Code)
	}
	r := jsonReq(t, "POST", hostA, "/api/my/recovery-key", "", map[string]any{"kind": "filevault", "key": "ABCD-EFGH-IJKL-MNOP"})
	r.TLS = cert
	if rec, body := do(t, f, r); rec.Code != 200 {
		t.Fatalf("escrow: %d %v", rec.Code, body)
	}
	// Sealed on the row: the key itself is not there.
	if n := adminCount(t, `SELECT count(*) FROM device_recovery_keys WHERE device_id = $1 AND position('ABCD-EFGH' in encode(key_sealed, 'escape')) > 0`, dev); n != 0 {
		t.Fatal("the recovery key is stored in the clear")
	}
	// The help desk and IT may not reveal; Security may, with a reason.
	for _, bearer := range []string{"a-helpdesk", "a-itadmin", "a-auditor"} {
		if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/recovery-key/reveal", bearer,
			map[string]any{"reason": "locked out"})); rec.Code != http.StatusForbidden {
			t.Fatalf("%s revealed a recovery key: %d", bearer, rec.Code)
		}
	}
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/recovery-key/reveal", "a-secmgr",
		map[string]any{})); rec.Code != http.StatusBadRequest {
		t.Fatalf("a reveal without a reason: %d", rec.Code)
	}
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/recovery-key/reveal", "a-secmgr",
		map[string]any{"reason": "Owner locked out, ticket 4412"}))
	if rec.Code != 200 || body["key"] != "ABCD-EFGH-IJKL-MNOP" || body["kind"] != "filevault" {
		t.Fatalf("reveal: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'recovery_key.revealed' AND object_ref LIKE '%ticket 4412%'`, tenantA); n != 1 {
		t.Fatal("the reveal was not audited with its reason")
	}
	if n := adminCount(t, `SELECT count(*) FROM device_recovery_keys WHERE device_id = $1 AND revealed_count = 1`, dev); n != 1 {
		t.Fatal("the reveal was not counted on the row")
	}
	// The console shows the status, and reveals on its own page, once.
	_, page := getHTML(t, f, hostA, "/devices/"+dev.String(), "a-secmgr")
	if !strings.Contains(page, "filevault recovery key is escrowed") || !strings.Contains(page, "Reveal the key") {
		t.Fatal("the device page does not show the escrow")
	}
	_, page = getHTML(t, f, hostA, "/devices/"+dev.String(), "a-helpdesk")
	if strings.Contains(page, "Reveal the key") {
		t.Fatal("the help desk is offered the reveal control")
	}
	// Another device's certificate cannot escrow for this one: the device
	// id comes from the certificate, never the body.
	other := trustedCert(t, tenantA, f.devices[tenantA][1])
	r = jsonReq(t, "POST", hostA, "/api/my/recovery-key", "", map[string]any{"kind": "filevault", "key": "ZZZZ"})
	r.TLS = other
	do(t, f, r)
	rec, body = do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/recovery-key/reveal", "a-secmgr",
		map[string]any{"reason": "check"}))
	if body["key"] != "ABCD-EFGH-IJKL-MNOP" {
		t.Fatalf("another device overwrote this device's key: %v", body)
	}
}
