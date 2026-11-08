package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"platform/internal/authz"
)

// Policies per operating system, with their own settings (internal/catalog):
// the guided editor, the ready-made library, and what Google is actually
// sent. These go through the real routes with the fake Google behind them.

// delivered is the raw policy last sent to Google under a name, as a map.
func delivered(t *testing.T, f fixture, suffix string) map[string]any {
	t.Helper()
	for path, raw := range f.google.PolicyBodies {
		if strings.HasSuffix(path, "/policies/"+suffix) {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatalf("no policy %q was delivered to Google; have %v", suffix, keys(f.google.PolicyBodies))
	return nil
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func guided(os, name, ownership string, kv map[string]string) url.Values {
	v := url.Values{"guided": {"1"}, "os_family": {os}, "name": {name}, "ownership": {ownership}}
	for k, val := range kv {
		v.Set(k, val)
	}
	return v
}

func TestAnAndroidPolicyIsBuiltFromAndroidsOwnSettingsAndGoesToGoogle(t *testing.T) {
	f := selfReady(t)
	rec := postForm(t, f, "a-itadmin", "/policies", guided("android", "Field phones", "company", map[string]string{
		"cfg.android.camera_disabled":     "1",
		"cfg.android.wallpaper_locked":    "1",
		"cfg.android.password_min_length": "10",
		"cfg.android.screen_lock_seconds": "120",
		"cfg.android.play_store_mode":     "WHITELIST",
		"cfg.android.short_message":       "Call IT on 0800",
		"cfg.android.apps":                "com.example.crm required\ncom.example.news available\ncom.example.game blocked",
		"rule.passcode_required":          "1",
	}))
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "Saved") {
		t.Fatalf("saving: %d %q", rec.Code, said(rec))
	}
	m := delivered(t, f, "default")
	if m["cameraDisabled"] != true || m["setWallpaperDisabled"] != true || m["playStoreMode"] != "WHITELIST" ||
		m["maximumTimeToLock"] != "120000" {
		t.Fatalf("Google was not sent the settings: %v", m)
	}
	if pr, _ := m["passwordRequirements"].(map[string]any); pr["passwordMinimumLength"] != float64(10) {
		t.Fatalf("passwordRequirements: %v", m["passwordRequirements"])
	}
	if sm, _ := m["shortSupportMessage"].(map[string]any); sm["defaultMessage"] != "Call IT on 0800" {
		t.Fatalf("support message: %v", m["shortSupportMessage"])
	}
	apps, _ := m["applications"].([]any)
	got := map[string]string{}
	for _, a := range apps {
		am := a.(map[string]any)
		got[am["packageName"].(string)] = am["installType"].(string)
	}
	if got["com.example.crm"] != "FORCE_INSTALLED" || got["com.example.news"] != "AVAILABLE" || got["com.example.game"] != "BLOCKED" {
		t.Fatalf("apps: %v", got)
	}
	// And it is stored as a policy for Android only.
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE name = 'Field phones' AND scope_os_family = 'android' AND scope_ownership = 'company' AND active AND body::text LIKE '%android.camera_disabled%'`); n != 1 {
		t.Fatalf("the policy is not stored with its system and settings (%d)", n)
	}
}

func TestAPolicyIsForOneSystemAndItsSettingsMustFit(t *testing.T) {
	f := selfReady(t)
	// The body of a policy sent as JSON, as before, is held to the same rules.
	for name, tc := range map[string]struct {
		os, ownership, body, said string
	}{
		"android settings on a windows policy":       {"windows", "", `{"config":{"android.camera_disabled":true}}`, "android settings"},
		"settings with no system":                    {"", "", `{"config":{"android.camera_disabled":true}}`, "choose which system"},
		"two systems in one policy":                  {"android", "", `{"config":{"android.camera_disabled":true,"windows.camera_blocked":true}}`, "mixes"},
		"a company setting on a personal policy":     {"android", "personal", `{"config":{"android.wallpaper_locked":true}}`, "company-owned"},
		"a work-profile setting on a company policy": {"android", "company", `{"config":{"android.block_copy_to_personal":true}}`, "personal devices"},
		"a setting nobody has heard of":              {"android", "", `{"config":{"android.camera_blocked":true}}`, "unknown setting"},
		"a number out of range":                      {"android", "", `{"config":{"android.password_min_length":2}}`, "between"},
	} {
		rec := postForm(t, f, "a-itadmin", "/policies", url.Values{"name": {"Bad"}, "os_family": {tc.os}, "ownership": {tc.ownership}, "rules": {tc.body}})
		if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "was not saved") || !strings.Contains(said(rec), tc.said) {
			t.Errorf("%s: %d %q", name, rec.Code, said(rec))
		}
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE name = 'Bad'`); n != 0 {
		t.Fatalf("%d bad policies were saved", n)
	}
	// An app with no instruction is refused rather than guessed at.
	rec := postForm(t, f, "a-itadmin", "/policies", guided("android", "Apps", "", map[string]string{"cfg.android.apps": "com.example.crm"}))
	if !strings.Contains(said(rec), "required, available or blocked") {
		t.Fatalf("an app with no instruction: %q", said(rec))
	}
}

func TestACompanyPhoneAndAWorkProfileAreGivenDifferentPolicies(t *testing.T) {
	f := selfReady(t)
	postForm(t, f, "a-itadmin", "/policies", guided("android", "Everyone", "", map[string]string{
		"cfg.android.camera_disabled":        "1", // reaches both
		"cfg.android.wallpaper_locked":       "1", // company phones only
		"cfg.android.block_copy_to_personal": "1", // work profiles only
		"cfg.android.usb_transfer_blocked":   "1", // company phones only
	}))
	company, personal := delivered(t, f, "default"), delivered(t, f, "personal")
	if company["cameraDisabled"] != true || personal["cameraDisabled"] != true {
		t.Fatal("a setting for all phones did not reach both policies")
	}
	if company["setWallpaperDisabled"] != true || company["usbFileTransferDisabled"] != true {
		t.Fatalf("the company policy is missing company settings: %v", company)
	}
	if _, ok := personal["setWallpaperDisabled"]; ok {
		t.Fatal("a work profile was sent a company-only setting")
	}
	if _, ok := personal["usbFileTransferDisabled"]; ok {
		t.Fatal("a work profile was sent a company-only setting")
	}
	if _, ok := company["crossProfilePolicies"]; ok {
		t.Fatal("a company phone was sent a work-profile-only setting")
	}
	if cp, _ := personal["crossProfilePolicies"].(map[string]any); cp["crossProfileCopyPaste"] != "COPY_FROM_WORK_TO_PERSONAL_DISALLOWED" {
		t.Fatalf("the work profile is missing its own setting: %v", personal["crossProfilePolicies"])
	}
}

func TestTwoPoliciesGiveGoogleTheStricterOfEachSetting(t *testing.T) {
	f := selfReady(t)
	postForm(t, f, "a-itadmin", "/policies", guided("android", "Loose", "", map[string]string{
		"cfg.android.password_min_length": "8", "cfg.android.screen_lock_seconds": "600", "cfg.android.apps": "com.example.a available"}))
	postForm(t, f, "a-itadmin", "/policies", guided("android", "Strict", "", map[string]string{
		"cfg.android.password_min_length": "14", "cfg.android.screen_lock_seconds": "60", "cfg.android.apps": "com.example.a blocked\ncom.example.b required"}))
	m := delivered(t, f, "default")
	if pr, _ := m["passwordRequirements"].(map[string]any); pr["passwordMinimumLength"] != float64(14) {
		t.Fatalf("the longer passcode did not win: %v", m["passwordRequirements"])
	}
	if m["maximumTimeToLock"] != "60000" {
		t.Fatalf("the shorter lock did not win: %v", m["maximumTimeToLock"])
	}
	got := map[string]string{}
	for _, a := range m["applications"].([]any) {
		am := a.(map[string]any)
		got[am["packageName"].(string)] = am["installType"].(string)
	}
	if got["com.example.a"] != "BLOCKED" || got["com.example.b"] != "FORCE_INSTALLED" {
		t.Fatalf("apps did not merge to the stricter: %v", got)
	}
}

func TestAReadyMadePolicyIsOneClickAndOnlyOnce(t *testing.T) {
	f := selfReady(t)
	rec := postForm(t, f, "a-itadmin", "/policy-library/android-company-locked", url.Values{})
	if rec.Code != http.StatusSeeOther || !strings.Contains(said(rec), "Added") {
		t.Fatalf("adding: %d %q", rec.Code, said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE name = 'Android: company phone, locked down' AND scope_os_family = 'android' AND active`); n != 1 {
		t.Fatal("the ready-made policy was not saved as a policy")
	}
	m := delivered(t, f, "default")
	if m["factoryResetDisabled"] != true || m["setWallpaperDisabled"] != true {
		t.Fatalf("a ready-made policy was not delivered to Google: %v", m)
	}
	// Twice is refused, and nothing is duplicated.
	if rec := postForm(t, f, "a-itadmin", "/policy-library/android-company-locked", url.Values{}); !strings.Contains(said(rec), "already added") {
		t.Fatalf("adding twice: %q", said(rec))
	}
	if n := adminCount(t, `SELECT count(*) FROM policies WHERE name = 'Android: company phone, locked down'`); n != 1 {
		t.Fatalf("%d copies", n)
	}
	if rec := postForm(t, f, "a-itadmin", "/policy-library/nonsense", url.Values{}); !strings.Contains(said(rec), "no ready-made policy") {
		t.Fatalf("an unknown key: %q", said(rec))
	}
	// Only a role that may change policy can add one.
	for _, who := range []string{"a-employee", "a-helpdesk", "a-auditor"} {
		if rec := postForm(t, f, who, "/policy-library/windows-baseline", url.Values{}); !strings.Contains(said(rec), "may not do that") {
			t.Fatalf("%s added a policy: %q", who, said(rec))
		}
	}
	// A Windows one saves too, with nothing to deliver.
	if rec := postForm(t, f, "a-itadmin", "/policy-library/windows-baseline", url.Values{}); !strings.Contains(said(rec), "Added") {
		t.Fatalf("a Windows policy: %q", said(rec))
	}
}

func TestThePoliciesPageIsSeparatedByOperatingSystem(t *testing.T) {
	f := selfReady(t)
	page := func(q string) string {
		rec := f.asPerson(t, "GET", hostA, "/policies"+q, tenantA, "o.martins", authz.ITAdmin, "o.martins@kalesi.example", nil, desktopUA)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", q, rec.Code)
		}
		return rec.Body.String()
	}
	all := page("")
	for _, want := range []string{"Android: secure baseline", "Windows: secure baseline", "Add this policy", "New Android policy", "New Windows policy"} {
		if !strings.Contains(all, want) {
			t.Errorf("the policies page does not offer %q", want)
		}
	}
	android := page("?os=android")
	if !strings.Contains(android, "Android: secure baseline") || strings.Contains(android, "Windows: secure baseline") {
		t.Error("filtering to Android did not separate the systems")
	}
	windows := page("?os=windows")
	if strings.Contains(windows, "Android: secure baseline") || !strings.Contains(windows, "Windows: secure baseline") {
		t.Error("filtering to Windows did not separate the systems")
	}
	// The editor for each system offers that system's own settings.
	a := page("?new=android")
	for _, want := range []string{"Block the camera", "Lock the wallpaper", "Apps to push, offer or block", "Password and lock screen", "Personal phones (work profile)"} {
		if !strings.Contains(a, want) {
			t.Errorf("the Android editor does not offer %q", want)
		}
	}
	if strings.Contains(a, "BitLocker") {
		t.Error("the Android editor offers a Windows setting")
	}
	w := page("?new=windows")
	for _, want := range []string{"Encrypt the disk (BitLocker)", "Desktop background picture", "Keep the firewall on", "cannot be enrolled here yet"} {
		if !strings.Contains(w, want) {
			t.Errorf("the Windows editor does not offer %q", want)
		}
	}
	if strings.Contains(w, "Block the camera</strong> <span") && strings.Contains(w, "company phones only") {
		t.Error("the Windows editor offers an Android setting")
	}
	// Changing a policy opens it with its values filled in.
	postForm(t, f, "a-itadmin", "/policies", guided("android", "Edit me", "", map[string]string{"cfg.android.password_min_length": "11", "cfg.android.camera_disabled": "1"}))
	edit := page("?edit=Edit+me")
	if !strings.Contains(edit, `value="11"`) || !strings.Contains(edit, "readonly") {
		t.Errorf("editing did not fill the form in:\n%.200s", edit)
	}
}

func TestADeviceShowsWhatItIsToldToDo(t *testing.T) {
	f := selfReady(t)
	dev := f.devices[tenantA][0]
	exec(t, `UPDATE devices SET os_family = 'windows' WHERE id = $1`, dev)
	postForm(t, f, "a-itadmin", "/policy-library/windows-baseline", url.Values{})
	rec := f.asPerson(t, "GET", hostA, "/devices/"+dev.String(), tenantA, "o.martins", authz.ITAdmin, "o.martins@kalesi.example", nil, desktopUA)
	body := rec.Body.String()
	for _, want := range []string{"What this device is told to do", "Encrypt the disk (BitLocker)", "Windows: secure baseline", "not built"} {
		if !strings.Contains(body, want) {
			t.Errorf("the device page does not say %q", want)
		}
	}
}

func TestEveryPolicyIsStillAnOrdinaryPolicyToTheAPI(t *testing.T) {
	f := selfReady(t)
	code, body := savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Via API", "os_family": "android",
		"rules": map[string]any{"passcode_required": true, "config": map[string]any{"android.camera_disabled": true}},
	})
	if code != http.StatusCreated {
		t.Fatalf("saving over the API: %d %v", code, body)
	}
	if delivered(t, f, "default")["cameraDisabled"] != true {
		t.Fatal("a policy saved over the API did not reach Google")
	}
	code, body = savePolicy(t, f, "a-itadmin", map[string]any{
		"name": "Bad API", "os_family": "windows",
		"rules": map[string]any{"config": map[string]any{"android.camera_disabled": true}},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("a mismatched policy over the API: %d %v", code, body)
	}
}

// A work-profile phone is enrolled onto the personal policy and a company
// phone onto the company one. Without this a policy scoped to personal phones
// would be saved, shown, and given to nobody.
func TestAPhoneIsEnrolledOntoThePolicyForItsKind(t *testing.T) {
	f := selfReady(t)
	ent := adminString(t, `SELECT name FROM android_enterprises WHERE tenant_id = $1`, tenantA)
	for _, tc := range []struct{ ownership, want string }{{"personal", "/policies/personal"}, {"company", "/policies/default"}} {
		rec := postForm(t, f, "a-itadmin", "/android/tokens", url.Values{"label": {tc.ownership + " phone"}, "ownership": {tc.ownership}})
		m := androidTokenRE.FindStringSubmatch(rec.Body.String())
		if rec.Code != 200 || m == nil {
			t.Fatalf("%s token: %d", tc.ownership, rec.Code)
		}
		f.google.Enrol(m[1], "SER-"+tc.ownership, "Pixel", "15", true, true)
	}
	devices, err := f.g.android.ListDevices(context.Background(), ent)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range devices {
		got[d.Serial] = d.PolicyName
	}
	for ownership, want := range map[string]string{"personal": "/policies/personal", "company": "/policies/default"} {
		if !strings.HasSuffix(got["SER-"+ownership], want) {
			t.Errorf("a %s phone was enrolled onto %q, want …%s", ownership, got["SER-"+ownership], want)
		}
	}
}
