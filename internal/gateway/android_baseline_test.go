package gateway

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"platform/internal/android"
)

// The corporate baseline's Critical controls, end to end against the fake
// Google: a company phone that starts healthy, drifts, and is caught.

// enrolCompany makes a company phone at the fake Google and syncs it, and
// returns the platform's id for it and Google's name for it.
func enrolCompany(t *testing.T, f fixture, serial string) (id, name string) {
	t.Helper()
	rec := postForm(t, f, "a-itadmin", "/android/tokens", url.Values{"label": {serial}, "ownership": {"company"}})
	m := androidTokenRE.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil {
		t.Fatalf("token: %d", rec.Code)
	}
	name = f.google.Enrol(m[1], serial, "Pixel 8a", "15", true, true)
	if name == "" {
		t.Fatal("the fake Google did not accept the token")
	}
	syncAndroid(t, f)
	return adminUUID(t, `SELECT id FROM devices WHERE tenant_id = $1 AND android_name = $2`, tenantA, name).String(), name
}

func syncAndroid(t *testing.T, f fixture) {
	t.Helper()
	if rec, body := do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin")); rec.Code != 200 {
		t.Fatalf("sync: %d %v", rec.Code, body)
	}
}

func verdict(t *testing.T, f fixture, id string) (string, string) {
	t.Helper()
	_, d := do(t, f, req(t, "GET", hostA, "/api/devices/"+id+"/compliance", "a-itadmin"))
	findings, _ := json.Marshal(d["findings"])
	state, _ := d["state"].(string)
	return state, strings.ToLower(string(findings))
}

func addLibrary(t *testing.T, f fixture, key string) {
	t.Helper()
	if rec := postForm(t, f, "a-itadmin", "/policy-library/"+key, url.Values{}); !strings.Contains(said(rec), "Added") {
		t.Fatalf("adding %s: %q", key, said(rec))
	}
}

func daysAgo(n int) string { return time.Now().UTC().AddDate(0, 0, -n).Format("2006-01-02") }

func TestACompanyPhoneThatDriftsFromTheBaselineIsCaught(t *testing.T) {
	f := selfReady(t)
	addLibrary(t, f, "android-tier1")
	id, name := enrolCompany(t, f, "TIER1-PHONE")

	// A healthy phone is compliant.
	if state, why := verdict(t, f, id); state != "compliant" {
		t.Fatalf("a healthy phone: %s %s", state, why)
	}

	// Each drift, one at a time, is caught and named in words.
	for _, c := range []struct {
		what  string
		drift func(*android.Facts)
		said  string
	}{
		{"a security patch 45 days old", func(x *android.Facts) { x.PatchLevel = daysAgo(45) }, "security patch"},
		{"USB debugging switched on", func(x *android.Facts) { x.ADB = yes() }, "debugging"},
		{"developer options switched on", func(x *android.Facts) { x.DevSettings = yes() }, "debugging"},
		{"unknown sources allowed", func(x *android.Facts) { x.UnknownSources = yes() }, "unknown sources"},
		{"Google Play Protect switched off", func(x *android.Facts) { x.VerifyApps = no() }, "play protect"},
	} {
		f.google.Tune(name, func(x *android.Facts) {
			*x = android.Facts{PatchLevel: daysAgo(12), ADB: no(), DevSettings: no(), UnknownSources: no(), VerifyApps: yes(), Posture: "SECURE"}
			c.drift(x)
		})
		syncAndroid(t, f)
		state, why := verdict(t, f, id)
		if state != "not_compliant" || !strings.Contains(why, c.said) {
			t.Errorf("%s: %s, findings %s", c.what, state, why)
		}
	}

	// Put right, it is compliant again.
	f.google.Tune(name, func(x *android.Facts) {
		*x = android.Facts{PatchLevel: daysAgo(3), ADB: no(), DevSettings: no(), UnknownSources: no(), VerifyApps: yes(), Posture: "SECURE"}
	})
	syncAndroid(t, f)
	if state, why := verdict(t, f, id); state != "compliant" {
		t.Fatalf("after putting it right: %s %s", state, why)
	}

	// A phone that stops saying is unknown, never a pass.
	f.google.Tune(name, func(x *android.Facts) { *x = android.Facts{} })
	syncAndroid(t, f)
	if state, _ := verdict(t, f, id); state == "compliant" {
		t.Fatal("a phone that said nothing about its patch, debugging or Play Protect was called compliant")
	}
}

func TestTheIntegrityCheckIsTierTwoAndAnAtRiskPhoneFailsIt(t *testing.T) {
	f := selfReady(t)
	addLibrary(t, f, "android-tier2")
	id, name := enrolCompany(t, f, "TIER2-PHONE")
	if state, why := verdict(t, f, id); state != "compliant" {
		t.Fatalf("a healthy phone under Tier 2: %s %s", state, why)
	}
	for _, posture := range []string{"AT_RISK", "POTENTIAL_RISK"} {
		f.google.Tune(name, func(x *android.Facts) {
			*x = android.Facts{PatchLevel: daysAgo(5), ADB: no(), DevSettings: no(), UnknownSources: no(), VerifyApps: yes(), Posture: posture}
		})
		syncAndroid(t, f)
		if state, why := verdict(t, f, id); state != "not_compliant" || !strings.Contains(why, "integrity") {
			t.Errorf("posture %s: %s %s", posture, state, why)
		}
	}
	// Tier 2's patch window is 14 days: twelve passes, twenty does not.
	f.google.Tune(name, func(x *android.Facts) {
		*x = android.Facts{PatchLevel: daysAgo(20), ADB: no(), DevSettings: no(), UnknownSources: no(), VerifyApps: yes(), Posture: "SECURE"}
	})
	syncAndroid(t, f)
	if state, why := verdict(t, f, id); state != "not_compliant" || !strings.Contains(why, "14 days") {
		t.Errorf("a 20-day-old patch under Tier 2: %s %s", state, why)
	}
}

func TestTheTiersAreDeliveredToGoogleAndEachStrictenTheOneBelow(t *testing.T) {
	f := selfReady(t)
	addLibrary(t, f, "android-tier1")
	m := delivered(t, f, "default")
	if ao, _ := m["advancedSecurityOverrides"].(map[string]any); ao["googlePlayProtectVerifyApps"] != "VERIFY_APPS_ENFORCED" || ao["untrustedAppsPolicy"] != "DISALLOW_INSTALL" {
		t.Fatalf("Tier 1 did not reach Google: %v", m["advancedSecurityOverrides"])
	}
	if m["autoDateAndTimeZone"] != "AUTO_DATE_AND_TIME_ZONE_ENFORCED" || m["debuggingFeaturesAllowed"] != false {
		t.Fatalf("Tier 1 settings missing: %v", m)
	}
	if _, ok := m["usbFileTransferDisabled"]; ok {
		t.Fatal("Tier 1 blocked USB copying, which is a Tier 2 control")
	}
	addLibrary(t, f, "android-tier2")
	m = delivered(t, f, "default")
	if m["usbFileTransferDisabled"] != true || m["backupServiceEnabled"] != false || m["screenCaptureDisabled"] != true {
		t.Fatalf("Tier 2 did not add its controls: %v", m)
	}
	addLibrary(t, f, "android-tier3")
	m = delivered(t, f, "default")
	if m["playStoreMode"] != "WHITELIST" || m["maximumTimeToLock"] != "120000" {
		t.Fatalf("Tier 3 did not take the strictest values: %v", m)
	}
	pr, _ := m["passwordRequirements"].(map[string]any)
	if pr["passwordQuality"] != "ALPHANUMERIC" || pr["passwordMinimumLength"] != float64(10) {
		t.Fatalf("Tier 3 password: %v", pr)
	}
	if as, _ := m["permittedAccessibilityServices"].(map[string]any); len(as["packageNames"].([]any)) != 0 {
		t.Fatalf("Tier 3 did not restrict accessibility to Android's own: %v", m["permittedAccessibilityServices"])
	}
}

// The editor takes the new rules and the new lists, and they reach both the
// stored policy and Google.
func TestTheNewRulesAndListsGoThroughTheGuidedEditor(t *testing.T) {
	f := selfReady(t)
	rec := postForm(t, f, "a-itadmin", "/policies", guided("android", "Custom baseline", "company", map[string]string{
		"rule.security_patch_max_age_days": "21", "rule.debugging_blocked": "1", "rule.unknown_sources_blocked": "1",
		"rule.play_protect_required": "1", "rule.integrity_required": "1",
		"cfg.android.frp_accounts":          "it@kalesi.example\nsecurity@kalesi.example\n",
		"cfg.android.accessibility_allowed": "com.example.reader\n",
		"cfg.android.lock_screen_message":   "Property of Kalesi. If found call 0800 000 0000.",
		"cfg.android.backup_blocked":        "1", "cfg.android.auto_time_required": "1",
	}))
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "Saved") {
		t.Fatalf("saving: %d %q", rec.Code, said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE name = 'Custom baseline' AND active
		AND body::text LIKE '%security_patch_max_age_days%' AND body::text LIKE '%integrity_required%' AND body::text LIKE '%android.frp_accounts%'`); n != 1 {
		t.Fatalf("the rules and lists are not in the stored policy (%d)", n)
	}
	m := delivered(t, f, "default")
	if frp, _ := m["frpAdminEmails"].([]any); len(frp) != 2 {
		t.Fatalf("factory reset protection accounts: %v", m["frpAdminEmails"])
	}
	if as, _ := m["permittedAccessibilityServices"].(map[string]any); len(as["packageNames"].([]any)) != 1 {
		t.Fatalf("accessibility allow-list: %v", m["permittedAccessibilityServices"])
	}
	if ls, _ := m["deviceOwnerLockScreenInfo"].(map[string]any); !strings.Contains(ls["defaultMessage"].(string), "Property of Kalesi") {
		t.Fatalf("lock screen text: %v", m["deviceOwnerLockScreenInfo"])
	}
	// A bad entry in a list is refused where it is typed.
	rec = postForm(t, f, "a-itadmin", "/policies", guided("android", "Bad list", "company", map[string]string{"cfg.android.frp_accounts": "not an email"}))
	if !strings.Contains(said(rec), "not an email address") {
		t.Fatalf("a bad list entry: %q", said(rec))
	}
	// And the editor shows the new rules for Android and not for Windows.
	page := f.asPerson(t, "GET", hostA, "/policies?new=android", tenantA, "o.martins", "it_admin", "o.martins@kalesi.example", nil, desktopUA).Body.String()
	for _, want := range []string{"The security patch is no more than", "USB debugging and developer options are off", "Google Play Protect is on", "Accounts that can recover a reset phone"} {
		if !strings.Contains(page, want) {
			t.Errorf("the Android editor does not offer %q", want)
		}
	}
	win := f.asPerson(t, "GET", hostA, "/policies?new=windows", tenantA, "o.martins", "it_admin", "o.martins@kalesi.example", nil, desktopUA).Body.String()
	if strings.Contains(win, "Google Play Protect is on") {
		t.Error("the Windows editor offers an Android rule")
	}
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }
