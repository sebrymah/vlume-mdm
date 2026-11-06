package gateway

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"platform/internal/android"
)

// T8: the plan's numbers and switches, enforced where they cannot be
// forgotten, and said in words where a person is asking.

func TestThePlansDeviceCapRefusesInWordsAndAtTheRow(t *testing.T) {
	f := newFixture(t)
	// Tenant A has two devices. Cap it at two.
	exec(t, `UPDATE tenants SET device_cap = 2 WHERE id = $1`, tenantA)

	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", "a-itadmin", map[string]any{
		"label": "One more", "ownership": "company", "os_family": "macos",
	}))
	if rec.Code != http.StatusConflict || !strings.Contains(body["error"].(string), "2 of 2 devices") {
		t.Fatalf("an invitation past the cap: %d %v", rec.Code, body)
	}
	// Any writer that forgets to ask is refused by the database.
	if err := execErr(t, `INSERT INTO devices (tenant_id, name, serial, os_family) VALUES ($1, 'Sneaked', 'SN-SNEAK', 'macos')`, tenantA); err == nil || !strings.Contains(err.Error(), "device cap reached") {
		t.Fatalf("the database let a device past the cap: %v", err)
	}
	// A retired device frees its slot.
	exec(t, `UPDATE devices SET state = 'retired' WHERE id = $1`, f.devices[tenantA][1])
	if rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", "a-itadmin", map[string]any{
		"label": "One more", "ownership": "company", "os_family": "macos",
	})); rec.Code != http.StatusCreated {
		t.Fatalf("after retiring one: %d %v", rec.Code, body)
	}
	// And the other tenant is not counted against this one's cap.
	if n := adminCount(t, `SELECT count(*) FROM devices WHERE tenant_id = $1`, tenantB); n != 3 {
		t.Fatalf("tenant B has %d devices", n)
	}
}

func TestFeaturesFollowThePlanUnlessTheOperatorSwitchesThem(t *testing.T) {
	f := newFixture(t)
	// Tenant A is on growth: Android and the network feed are in.
	if tok, _ := mintToken(t, f, "a-super", "NAC"); tok == "" {
		t.Fatal("growth could not mint a network token")
	}
	// The operator switches Android off for this tenant alone.
	exec(t, `UPDATE tenants SET features = '{"android": false, "network_feed": false}'::jsonb WHERE id = $1`, tenantA)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "not part of this tenant's plan") {
		t.Fatalf("Android bound outside the plan: %q", msg)
	}
	if tok, rec := mintToken(t, f, "a-super", "NAC2"); tok != "" || !strings.Contains(said(rec), "not part of this tenant's plan") {
		t.Fatalf("a network token outside the plan: %q", said(rec))
	}
	_, body := do(t, f, req(t, "GET", hostA, "/api/setup", "a-itadmin"))
	for _, s := range body["Steps"].([]any) {
		if m := s.(map[string]any); m["Key"] == "android" {
			if b, _ := m["Blocked"].(string); !strings.Contains(b, "plan") {
				t.Fatalf("the setup step does not say the plan excludes it: %v", m)
			}
		}
	}
	// A starter tenant gets the plan's defaults: no Android.
	exec(t, `UPDATE tenants SET plan = 'starter', features = '{}'::jsonb WHERE id = $1`, tenantA)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "not part of this tenant's plan") {
		t.Fatalf("starter bound Android: %q", msg)
	}
	// Switched on explicitly, over the plan.
	exec(t, `UPDATE tenants SET features = '{"android": true}'::jsonb WHERE id = $1`, tenantA)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("an explicit switch did not open Android: %q", msg)
	}
	_ = url.Values{}
}

func TestAPhonePastTheCapIsSkippedAndSaidOnce(t *testing.T) {
	f := newFixture(t)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}
	ent := adminString(t, `SELECT name FROM android_enterprises WHERE tenant_id = $1`, tenantA)
	for _, serial := range []string{"PHONE-A", "PHONE-B"} {
		tok, err := f.g.android.CreateEnrollmentToken(context.Background(), ent, androidTokenInput(t, f))
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		f.google.Enrol(tok.Value, serial, "Pixel", "15", true, true)
	}
	exec(t, `UPDATE tenants SET device_cap = 3 WHERE id = $1`, tenantA) // two laptops + room for one phone
	rec, body := do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin"))
	if rec.Code != 200 || body["created"] != float64(1) || body["skipped"] != float64(1) {
		t.Fatalf("sync at the cap: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'quota.reached'`, tenantA); n != 1 {
		t.Fatalf("%d quota notifications", n)
	}
	// Again: still skipped, still said once.
	do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin"))
	if n := adminCount(t, `SELECT count(*) FROM notifications WHERE tenant_id = $1 AND topic = 'quota.reached'`, tenantA); n != 1 {
		t.Fatalf("%d quota notifications after a second sync", n)
	}
}

func androidTokenInput(t *testing.T, f fixture) android.TokenInput {
	t.Helper()
	ent := adminString(t, `SELECT name FROM android_enterprises WHERE tenant_id = $1`, tenantA)
	return android.TokenInput{PolicyName: ent + "/policies/default", OneTime: true}
}
