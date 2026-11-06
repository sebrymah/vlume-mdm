package gateway

import (
	"context"
	"strings"
	"testing"
)

// Compliance over time (0041).

// A row per change of verdict, never per report. The control
// --break-historychange writes one on every report.
func TestTheHistoryHoldsEachChangeOfVerdictAndNothingElse(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	dev := f.devices[tenantA][0]
	clean := map[string]any{"passcode_set": true, "disk_encryption": true, "passcode_length": 12}

	for i := 0; i < 3; i++ {
		if code, _ := reportAs(t, f, hostA, tenantA, dev, clean); code != 200 {
			t.Fatalf("report %d: %d", i, code)
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM device_compliance_history WHERE device_id = $1`, dev); n != 1 {
		t.Fatalf("%d history rows after three identical reports, want 1", n)
	}
	// Fails: a row. Fails the same way with a different number: no row.
	if code, _ := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_set": true, "disk_encryption": true, "passcode_length": 6}); code != 200 {
		t.Fatal("failing report")
	}
	if code, _ := reportAs(t, f, hostA, tenantA, dev, map[string]any{"passcode_set": true, "disk_encryption": true, "passcode_length": 7}); code != 200 {
		t.Fatal("failing report 2")
	}
	if n := adminCount(t, `SELECT count(*) FROM device_compliance_history WHERE device_id = $1`, dev); n != 2 {
		t.Fatalf("%d history rows after failing, want 2", n)
	}
	// Put right: a row.
	if code, _ := reportAs(t, f, hostA, tenantA, dev, clean); code != 200 {
		t.Fatal("clean again")
	}
	if n := adminCount(t, `SELECT count(*) FROM device_compliance_history WHERE device_id = $1 AND state = 'compliant'`, dev); n != 2 {
		t.Fatalf("want two compliant rows (first, and put right)")
	}
	rec, body := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String()+"/compliance/history", "a-itadmin"))
	changes, _ := body["changes"].([]any)
	if rec.Code != 200 || len(changes) != 3 {
		t.Fatalf("history api: %d %v", rec.Code, body)
	}
	if newest := changes[0].(map[string]any); newest["state"] != "compliant" {
		t.Fatalf("newest first: %v", newest)
	}
	_, page := getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if !strings.Contains(page, "History") || !strings.Contains(page, "not_compliant") {
		t.Fatal("the device page does not show the history")
	}
	// Another tenant's device has no history to read.
	if rec, _ := do(t, f, req(t, "GET", hostB, "/api/devices/"+dev.String()+"/compliance/history", "b-itadmin")); rec.Code != 404 {
		t.Fatalf("tenant B read tenant A's history: %d", rec.Code)
	}
}

// The snapshot is the dashboard's own counts, once a day, and the trend
// is read back from it. The control --break-trendcount counts something
// else and the numbers part company.
func TestTheDailySnapshotIsTheDashboardsOwnCount(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	devs := f.devices[tenantA]
	if code, _ := reportAs(t, f, hostA, tenantA, devs[0], map[string]any{"passcode_set": true, "disk_encryption": true, "passcode_length": 12}); code != 200 {
		t.Fatal("report")
	}
	if code, _ := reportAs(t, f, hostA, tenantA, devs[1], failingReport()); code != 200 {
		t.Fatal("report")
	}
	s, err := f.g.SnapshotTenant(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	_, counts := do(t, f, req(t, "GET", hostA, "/api/devices", "a-itadmin"))
	_ = counts
	if s.Total != len(devs) || s.Compliant != 1 || s.NotCompliant != 1 {
		t.Fatalf("snapshot %+v, want total %d, 1 compliant, 1 not", s, len(devs))
	}
	// Twice in a day: one row, the later reading.
	if code, _ := reportAs(t, f, hostA, tenantA, devs[1], map[string]any{"passcode_set": true, "disk_encryption": true, "passcode_length": 12}); code != 200 {
		t.Fatal("report")
	}
	if s, err = f.g.SnapshotTenant(context.Background(), tenantA); err != nil || s.Compliant != 2 {
		t.Fatalf("second snapshot: %+v %v", s, err)
	}
	if n := adminCount(t, `SELECT count(*) FROM compliance_snapshots WHERE tenant_id = $1`, tenantA); n != 1 {
		t.Fatalf("%d snapshot rows for one day", n)
	}
	rec, body := do(t, f, req(t, "GET", hostA, "/api/compliance/trend?days=30", "a-itadmin"))
	days, _ := body["days"].([]any)
	if rec.Code != 200 || len(days) != 1 || days[0].(map[string]any)["compliant"] != float64(2) {
		t.Fatalf("trend: %d %v", rec.Code, body)
	}
	// Tenant B took no snapshot and sees none.
	rec, body = do(t, f, req(t, "GET", hostB, "/api/compliance/trend", "b-itadmin"))
	if days, _ := body["days"].([]any); rec.Code != 200 || len(days) != 0 {
		t.Fatalf("tenant B's trend: %d %v", rec.Code, body)
	}
	// One day is not a line yet; the dashboard says so. A second day
	// (written as yesterday) makes it one.
	_, page := getHTML(t, f, hostA, "/", "a-itadmin")
	if !strings.Contains(page, "needs two days") {
		t.Fatal("the dashboard did not explain the missing trend")
	}
	exec(t, `INSERT INTO compliance_snapshots (tenant_id, taken_on, total, compliant, not_compliant, state_unknown, quarantined, never_seen)
	         VALUES ($1, current_date - 1, 3, 1, 1, 1, 0, 0)`, tenantA)
	_, page = getHTML(t, f, hostA, "/", "a-itadmin")
	if !strings.Contains(page, "<path d=\"M") || !strings.Contains(page, "compliant today") {
		t.Fatal("the dashboard did not draw the trend")
	}
}
