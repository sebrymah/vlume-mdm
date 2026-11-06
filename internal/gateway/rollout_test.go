package gateway

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func contextBackground() context.Context { return context.Background() }

func adminConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	return conn
}

// F7: a staged rollout. The live version stays for everyone outside the
// stage; the stage is decided from the device's id, so it widens rather
// than shuffles; a tag is a group; promote and halt are the two exits.

func TestAStageAppliesToItsShareAndTheLiveVersionToTheRest(t *testing.T) {
	f := newFixture(t)
	baseline(t, f) // v1 live: passcode 8
	// Forty more devices, so a percentage means something.
	exec(t, `INSERT INTO devices (tenant_id, name, serial, os_family)
	         SELECT $1, 'ROLL-' || g, 'SN-ROLL-' || g, 'macos' FROM generate_series(1, 40) g`, tenantA)
	// v2 as a 50% stage: passcode 14.
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/policies", "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_required": true, "passcode_min_length": 14},
		"rollout_percent": 50,
	}))
	if rec.Code != http.StatusCreated || !strings.Contains(body["stage"].(string), "50%") {
		t.Fatalf("stage: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE tenant_id = $1 AND name = 'Baseline' AND active`, tenantA); n != 2 {
		t.Fatalf("%d active versions, want the live one and the stage", n)
	}

	// Every device reports a 10-character passcode: under v1 that passes,
	// under v2 it fails. Roughly half fail, and each device's answer is
	// the same the second time.
	ids := adminUUIDs(t, `SELECT id FROM devices WHERE tenant_id = $1 AND os_family = 'macos' ORDER BY name`, tenantA)
	first := map[uuid.UUID]string{}
	failing := 0
	for _, id := range ids {
		_, b := reportAs(t, f, hostA, tenantA, id, map[string]any{"passcode_set": true, "passcode_length": 10, "disk_encryption": true})
		first[id] = b["state"].(string)
		if b["state"] == "not_compliant" {
			failing++
		}
	}
	if failing < len(ids)/4 || failing > len(ids)*3/4 {
		t.Fatalf("%d of %d devices in a 50%% stage", failing, len(ids))
	}
	for _, id := range ids {
		_, b := reportAs(t, f, hostA, tenantA, id, map[string]any{"passcode_set": true, "passcode_length": 10, "disk_encryption": true})
		if b["state"] != first[id] {
			t.Fatalf("device %s moved from %s to %s between reports", id, first[id], b["state"])
		}
	}
	// Widening keeps everyone who was in. Stage v3 at 80%: every device
	// that failed under 50% still fails.
	if rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/policies", "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_required": true, "passcode_min_length": 14},
		"rollout_percent": 80,
	})); rec.Code != http.StatusCreated {
		t.Fatalf("widen: %d %v", rec.Code, body)
	}
	for _, id := range ids {
		if first[id] != "not_compliant" {
			continue
		}
		if _, b := reportAs(t, f, hostA, tenantA, id, map[string]any{"passcode_set": true, "passcode_length": 10, "disk_encryption": true}); b["state"] != "not_compliant" {
			t.Fatalf("device %s left the stage when it widened", id)
		}
	}
	// Promote: everyone, and one live version.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/promote", "a-itadmin", nil)); rec.Code != 200 {
		t.Fatalf("promote: %d", rec.Code)
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE tenant_id = $1 AND name = 'Baseline' AND active`, tenantA); n != 1 {
		t.Fatalf("%d active versions after promote", n)
	}
	for _, id := range ids[:5] {
		if _, b := reportAs(t, f, hostA, tenantA, id, map[string]any{"passcode_set": true, "passcode_length": 10, "disk_encryption": true}); b["state"] != "not_compliant" {
			t.Fatalf("after promote, device %s is %v", id, b["state"])
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action IN ('policy.stage','policy.promote')`, tenantA); n != 3 {
		t.Fatalf("%d stage audit records, want 2 stages and 1 promote", n)
	}
}

func TestATagIsAGroupAndHaltLeavesTheLiveVersionStanding(t *testing.T) {
	f := newFixture(t)
	baseline(t, f)
	devs := f.devices[tenantA]
	// Tag one device "pilot" from the console.
	if rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+devs[0].String()+"/tags", "a-itadmin",
		map[string]any{"tags": []string{" Pilot ", "finance", "pilot"}})); rec.Code != 200 {
		t.Fatalf("tags: %d %v", rec.Code, body)
	}
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+devs[0].String()+"/tags", "a-helpdesk",
		map[string]any{"tags": []string{"pilot"}})); rec.Code != http.StatusForbidden {
		t.Fatalf("the help desk tagged a device: %d", rec.Code)
	}
	// Stage v2 to the tag only (0%).
	if rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/policies", "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_required": true, "passcode_min_length": 14},
		"rollout_tag": "pilot",
	})); rec.Code != http.StatusCreated {
		t.Fatalf("tag stage: %d %v", rec.Code, body)
	}
	report := func(id uuid.UUID) string {
		_, b := reportAs(t, f, hostA, tenantA, id, map[string]any{"passcode_set": true, "passcode_length": 10, "disk_encryption": true})
		return b["state"].(string)
	}
	if report(devs[0]) != "not_compliant" || report(devs[1]) != "compliant" {
		t.Fatal("the tag did not pick the pilot device and only it")
	}
	// The device page says which version it is held to.
	_, page := getHTML(t, f, hostA, "/devices/"+devs[0].String(), "a-itadmin")
	if !strings.Contains(page, "Baseline v2") || !strings.Contains(page, "pilot") {
		t.Fatal("the pilot device's page does not show the stage or the tag")
	}
	// Halt: the pilot goes back to the live version.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/halt", "a-itadmin", nil)); rec.Code != 200 {
		t.Fatalf("halt: %d", rec.Code)
	}
	if report(devs[0]) != "compliant" {
		t.Fatal("after halt the pilot device is still held to the stage")
	}
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/policies/Baseline/halt", "a-itadmin", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("halting twice: %d", rec.Code)
	}
	// A stage with nothing in it is refused.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/policies", "a-itadmin", map[string]any{
		"name": "Baseline", "rules": map[string]any{"passcode_required": true}, "rollout_percent": 150,
	})); rec.Code < 400 {
		t.Fatalf("a 150%% stage was accepted: %d", rec.Code)
	}
}

func adminUUIDs(t *testing.T, sql string, args ...any) []uuid.UUID {
	t.Helper()
	ctx := contextBackground()
	conn := adminConn(t)
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, id)
	}
	return out
}
