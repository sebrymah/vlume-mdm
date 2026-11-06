package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// F9: automatic quarantine. The tests are about the three conditions and
// the brake: a policy must ask, the device must have FAILED rather than not
// said, and a mass failure stops the whole thing rather than quarantining
// the fleet.

func quarantiningBaseline(t *testing.T, f fixture) {
	t.Helper()
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Baseline",
		"rules": map[string]any{
			"passcode_required":        true,
			"disk_encryption_required": true,
			"on_failure":               "quarantine",
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("policy: %d %v", code, body)
	}
}

func failingReport() map[string]any {
	return map[string]any{"passcode_set": false, "disk_encryption": true}
}

func TestAPolicyThatAsksForItQuarantinesAFailingDevice(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	dev := f.devices[tenantA][0]

	code, body := reportAs(t, f, hostA, tenantA, dev, failingReport())
	if code != 200 {
		t.Fatalf("report: %d %v", code, body)
	}
	if body["state"] != "not_compliant" || body["enforcement"] != "quarantined" ||
		body["device_state"] != "quarantined" {
		t.Fatalf("the device was told %v", body)
	}
	_, d := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "quarantined" {
		t.Fatalf("device state is %v", d["state"])
	}
	// Who and why are on the row, so the device page can say so.
	if n := adminCount(t, `SELECT count(*) FROM devices WHERE id = $1 AND quarantined_by = 'policy:Baseline v1'
	                        AND quarantine_reason <> '' AND quarantined_at IS NOT NULL`, dev); n != 1 {
		t.Fatal("the quarantine does not say who or why")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'device.quarantined'`, tenantA); n != 1 {
		t.Fatalf("%d quarantine audit records", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'device.quarantined'`, tenantA); n != 1 {
		t.Fatalf("%d quarantine notifications", n)
	}

	// A good report afterwards is judged honestly and releases nothing.
	code, body = reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "disk_encryption": true,
	})
	if code != 200 || body["state"] != "compliant" || body["device_state"] != "quarantined" {
		t.Fatalf("after a good report: %d %v", code, body)
	}

	// Release is a person's act, and a role's. The help desk may not.
	rec := postForm(t, f, "a-helpdesk", "/devices/"+dev.String()+"/release", url.Values{})
	if !strings.Contains(said(rec), "may not") {
		t.Fatalf("the help desk released a device: %q", said(rec))
	}
	rec = postForm(t, f, "a-itadmin", "/devices/"+dev.String()+"/release", url.Values{})
	if !strings.Contains(said(rec), "Released") {
		t.Fatalf("release: %q", said(rec))
	}
	_, d = do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "state_unknown" {
		t.Fatalf("after release the device is %v, want state_unknown", d["state"])
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'device.released'`, tenantA); n != 1 {
		t.Fatalf("%d release audit records", n)
	}
	// Releasing twice is a conflict, not a second release.
	rec2, _ := do(t, f, req(t, "POST", hostA, "/api/devices/"+dev.String()+"/release", "a-itadmin"))
	if rec2.Code != http.StatusConflict {
		t.Fatalf("a second release: %d", rec2.Code)
	}
	// And the next report decides.
	code, body = reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "disk_encryption": true,
	})
	if code != 200 || body["device_state"] != "compliant" {
		t.Fatalf("after release and a good report: %d %v", code, body)
	}
}

func TestNothingIsEnforcedUnlessAPolicyAsks(t *testing.T) {
	f := newFixture(t)
	baseline(t, f) // no on_failure
	dev := f.devices[tenantA][0]

	code, body := reportAs(t, f, hostA, tenantA, dev, failingReport())
	if code != 200 || body["state"] != "not_compliant" {
		t.Fatalf("report: %d %v", code, body)
	}
	if _, acted := body["enforcement"]; acted {
		t.Fatalf("enforcement without a policy asking: %v", body["enforcement"])
	}
	if body["device_state"] != "not_compliant" {
		t.Fatalf("device state is %v", body["device_state"])
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'device.quarantined'`, tenantA); n != 0 {
		t.Fatal("a quarantine was announced with no policy asking")
	}
}

func TestNotKnowingNeverQuarantines(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	dev := f.devices[tenantA][0]

	// A report that says nothing: state_unknown, which is a reason to look,
	// not a reason to act.
	code, body := reportAs(t, f, hostA, tenantA, dev, map[string]any{})
	if code != 200 || body["state"] != "state_unknown" {
		t.Fatalf("report: %d %v", code, body)
	}
	if body["device_state"] != "state_unknown" {
		t.Fatalf("an unknown device was moved to %v", body["device_state"])
	}
}

func TestABadOnFailureIsRefused(t *testing.T) {
	f := newFixture(t)
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name":  "Harsh",
		"rules": map[string]any{"passcode_required": true, "on_failure": "wipe"},
	})
	if code < 400 {
		t.Fatalf("on_failure wipe was accepted: %d %v", code, body)
	}
}

// Standing directive 1: halt rather than continue silently. Sixty devices
// failing at once is a policy change or an agent fault until proven
// otherwise, and quarantining them all would turn a mistake into an outage.
func TestTheBrakeStopsAMassQuarantine(t *testing.T) {
	f := newFixture(t)
	quarantiningBaseline(t, f)
	devs := f.devices[tenantA]

	exec(t, `INSERT INTO devices (tenant_id, name, serial, os_family, state)
	         SELECT $1, 'BULK-' || g, 'SN-BULK-' || g, 'macos', 'not_compliant'
	           FROM generate_series(1, 60) g`, tenantA)

	code, body := reportAs(t, f, hostA, tenantA, devs[0], failingReport())
	if code != 200 {
		t.Fatalf("report: %d %v", code, body)
	}
	if body["enforcement"] != "halted" || body["device_state"] != "not_compliant" {
		t.Fatalf("with 61 of 62 failing, the platform %v", body)
	}
	if n := adminCount(t, `SELECT count(*) FROM devices WHERE tenant_id = $1 AND state = 'quarantined'`, tenantA); n != 0 {
		t.Fatalf("%d devices were quarantined during a mass failure", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'enforcement.halted'`, tenantA); n != 1 {
		t.Fatalf("%d halt audit records", n)
	}
	// Said once for the fleet, not once per failing device.
	code, body = reportAs(t, f, hostA, tenantA, devs[1], failingReport())
	if code != 200 || body["enforcement"] != "halted" {
		t.Fatalf("second report: %d %v", code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'enforcement.halted'`, tenantA); n != 1 {
		t.Fatalf("%d halt notifications for one mass failure", n)
	}
	// Tenant B is untouched by tenant A's trouble: its own device, failing
	// its own quarantining policy, is quarantined.
	recB, bodyB := do(t, f, jsonReq(t, "POST", hostB, "/api/policies", "b-itadmin", map[string]any{
		"name":  "Baseline",
		"rules": map[string]any{"passcode_required": true, "on_failure": "quarantine"},
	}))
	if recB.Code != http.StatusCreated {
		t.Fatalf("tenant B policy: %d %v", recB.Code, bodyB)
	}
	code, body = reportAs(t, f, hostB, tenantB, f.devices[tenantB][0], map[string]any{"passcode_set": false})
	if code != 200 || body["enforcement"] != "quarantined" {
		t.Fatalf("tenant B: %d %v", code, body)
	}
}

// A policy scoped to five iPads in a fleet of two hundred laptops. All five
// failing is 2.4% of the fleet and 100% of what the policy covers. The
// fleet-wide brake would not notice; the scoped one must.
func TestTheBrakeAlsoWatchesTheDevicesAPolicyCovers(t *testing.T) {
	f := newFixture(t)
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Tablets", "os_family": "ios",
		"rules": map[string]any{"passcode_required": true, "on_failure": "quarantine"},
	})
	if code != http.StatusCreated {
		t.Fatalf("policy: %d %v", code, body)
	}
	// 198 healthy laptops, so the fleet is quiet.
	exec(t, `INSERT INTO devices (tenant_id, name, serial, os_family, state, last_report_at)
	         SELECT $1, 'LAP-' || g, 'SN-LAP-' || g, 'macos', 'compliant', now()
	           FROM generate_series(1, 198) g`, tenantA)
	// Five tablets, four already failing, the fifth about to.
	exec(t, `INSERT INTO devices (tenant_id, name, serial, os_family, state)
	         SELECT $1, 'PAD-' || g, 'SN-PAD-' || g, 'ios',
	                CASE WHEN g = 5 THEN 'awaiting_first_boot' ELSE 'not_compliant' END
	           FROM generate_series(1, 5) g`, tenantA)
	fifth := adminUUID(t, `SELECT id FROM devices WHERE tenant_id = $1 AND serial = 'SN-PAD-5'`, tenantA)

	code, body = reportAs(t, f, hostA, tenantA, fifth, map[string]any{"passcode_set": false})
	if code != 200 {
		t.Fatalf("report: %d %v", code, body)
	}
	if body["enforcement"] != "halted" || body["device_state"] != "not_compliant" {
		t.Fatalf("five of five tablets failing: %v", body)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'enforcement.halted'
	                        AND subject LIKE '%5 of 5 devices%'`, tenantA); n != 1 {
		t.Fatal("the halt does not name the population it measured")
	}
	// And a single tablet failing in a healthy set is still quarantined.
	exec(t, `UPDATE devices SET state = 'compliant', last_report_at = now()
	          WHERE tenant_id = $1 AND serial IN ('SN-PAD-1','SN-PAD-2','SN-PAD-3','SN-PAD-4')`, tenantA)
	code, body = reportAs(t, f, hostA, tenantA, fifth, map[string]any{"passcode_set": false})
	if code != 200 || body["enforcement"] != "quarantined" {
		t.Fatalf("one of five tablets failing: %d %v", code, body)
	}
}
