package android

import (
	"encoding/json"
	"strings"
	"testing"

	"platform/internal/catalog"
	"platform/internal/policy"
)

func sent(t *testing.T, rules policy.Rules, cfg catalog.Values) map[string]any {
	t.Helper()
	p, _ := TranslateWith(rules, cfg)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func at(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// Every Android setting ends up at the field the catalogue says. A path that
// is wrong, or a setting whose value is never sent, is a setting that does
// nothing, which for a security setting is a lie.
func TestEveryAndroidSettingIsSentWhereTheCatalogueSaysItIs(t *testing.T) {
	for _, s := range catalog.ForOS("android") {
		var v any
		switch s.Kind {
		case catalog.Bool:
			v = true
		case catalog.Int:
			v = s.Min
		case catalog.Choice:
			v = s.Options[len(s.Options)-1].Value
		case catalog.Text:
			v = "com.example.vpn"
		case catalog.Apps:
			v = []catalog.AppRule{{Package: "com.example.crm", Install: "required"}}
		}
		m := sent(t, nil, catalog.Values{s.Key: v})
		if _, ok := at(m, s.Path); !ok {
			t.Errorf("%s: nothing was sent at %s\n%v", s.Key, s.Path, m)
		}
	}
}

func TestAnOffSwitchSendsNothing(t *testing.T) {
	m := sent(t, nil, catalog.Values{"android.camera_disabled": false, "android.wallpaper_locked": false})
	for _, k := range []string{"cameraDisabled", "setWallpaperDisabled"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s was sent although the switch was off", k)
		}
	}
}

func TestSettingsAreTranslatedToGooglesWordsAndUnits(t *testing.T) {
	m := sent(t, nil, catalog.Values{
		"android.screen_lock_seconds": 120, "android.password_expiry_days": 90,
		"android.untrusted_apps_blocked": true, "android.debugging_blocked": true,
		"android.block_copy_to_personal": true, "android.always_on_vpn_app": "com.example.vpn",
		"android.always_on_vpn_lockdown": true, "android.short_message": "Call IT",
		"android.apps": []catalog.AppRule{{Package: "com.example.a", Install: "required"}, {Package: "com.example.b", Install: "available"}, {Package: "com.example.c", Install: "blocked"}},
	})
	checks := map[string]any{
		"maximumTimeToLock": "120000",
		"passwordRequirements.passwordExpirationTimeout": "7776000s",
		"advancedSecurityOverrides.untrustedAppsPolicy":  "DISALLOW_INSTALL",
		"debuggingFeaturesAllowed":                       false,
		"crossProfilePolicies.crossProfileCopyPaste":     "COPY_FROM_WORK_TO_PERSONAL_DISALLOWED",
		"alwaysOnVpnPackage.packageName":                 "com.example.vpn",
		"alwaysOnVpnPackage.lockdownEnabled":             true,
		"shortSupportMessage.defaultMessage":             "Call IT",
	}
	for path, want := range checks {
		if got, ok := at(m, path); !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", path, got, ok, want)
		}
	}
	apps, _ := m["applications"].([]any)
	if len(apps) != 3 {
		t.Fatalf("applications: %v", m["applications"])
	}
	want := map[string]string{"com.example.a": "FORCE_INSTALLED", "com.example.b": "AVAILABLE", "com.example.c": "BLOCKED"}
	for _, a := range apps {
		am := a.(map[string]any)
		if want[am["packageName"].(string)] != am["installType"] {
			t.Errorf("%v", am)
		}
	}
}

// The rules a policy judges by and the settings it applies are one footing:
// the phone is never handed a looser value than the one it is judged against.
func TestRulesAndSettingsMergeStrictest(t *testing.T) {
	rules := policy.Rules{
		policy.PasscodeMinLength:    {Kind: policy.PasscodeMinLength, Num: 8},
		policy.ScreenLockTimeoutMax: {Kind: policy.ScreenLockTimeoutMax, Num: 300},
	}
	looser := sent(t, rules, catalog.Values{"android.password_min_length": 6, "android.screen_lock_seconds": 600})
	stricter := sent(t, rules, catalog.Values{"android.password_min_length": 12, "android.screen_lock_seconds": 60})
	for path, want := range map[string]any{
		"passwordRequirements.passwordMinimumLength": float64(8), "maximumTimeToLock": "300000"} {
		if got, _ := at(looser, path); got != want {
			t.Errorf("looser setting: %s = %v, want %v (the rule is stricter)", path, got, want)
		}
	}
	for path, want := range map[string]any{
		"passwordRequirements.passwordMinimumLength": float64(12), "maximumTimeToLock": "60000"} {
		if got, _ := at(stricter, path); got != want {
			t.Errorf("stricter setting: %s = %v, want %v", path, got, want)
		}
	}
	// Both halves of passwordRequirements survive the merge.
	both := sent(t, rules, catalog.Values{"android.password_history": 5})
	if _, ok := at(both, "passwordRequirements.passwordMinimumLength"); !ok {
		t.Error("the rule's minimum length was lost")
	}
	if got, _ := at(both, "passwordRequirements.passwordHistoryLength"); got != float64(5) {
		t.Error("the setting's history length was lost")
	}
}

// The ready-made Android policies produce a body Google can be given.
func TestTheAndroidLibraryTranslates(t *testing.T) {
	n := 0
	for _, tpl := range policy.LibraryFor("android") {
		rules, set, err := policy.ParseBody(tpl.Key, []byte(tpl.Body))
		if err != nil {
			t.Fatalf("%s: %v", tpl.Key, err)
		}
		m := sent(t, rules, set.Config)
		if _, ok := m["statusReportingSettings"]; !ok || len(m) < 3 {
			t.Errorf("%s: translated to almost nothing: %v", tpl.Key, m)
		}
		n++
	}
	if n < 5 {
		t.Fatalf("only %d Android policies in the library", n)
	}
}

// The lock a phone is asked for does not depend on the order the rules
// happen to be read in. A length rule asks for a PIN and a passcode rule for
// any lock; both together must always give the PIN. Go reads a map in a new
// random order each time, so one run proves little and two hundred do.
func TestTheLockQualityDoesNotDependOnTheOrderOfTheRules(t *testing.T) {
	rules := policy.Rules{
		policy.PasscodeRequired:       {Kind: policy.PasscodeRequired, Bool: true},
		policy.PasscodeMinLength:      {Kind: policy.PasscodeMinLength, Num: 8},
		policy.DiskEncryptionRequired: {Kind: policy.DiskEncryptionRequired, Bool: true},
		policy.ScreenLockTimeoutMax:   {Kind: policy.ScreenLockTimeoutMax, Num: 300},
	}
	for i := 0; i < 200; i++ {
		m := sent(t, rules, nil)
		if got, _ := at(m, "passwordRequirements.passwordQuality"); got != "NUMERIC" {
			t.Fatalf("run %d: the lock quality was %v, want NUMERIC", i, got)
		}
	}
	// A passcode rule alone asks for any lock.
	only := policy.Rules{policy.PasscodeRequired: {Kind: policy.PasscodeRequired, Bool: true}}
	if got, _ := at(sent(t, only, nil), "passwordRequirements.passwordQuality"); got != "SOMETHING" {
		t.Fatalf("a passcode rule alone gave %v", got)
	}
	// And a setting that asks for more than a rule is not weakened by it.
	if got, _ := at(sent(t, rules, catalog.Values{"android.password_quality": "COMPLEX"}), "passwordRequirements.passwordQuality"); got != "COMPLEX" {
		t.Fatalf("a stricter setting was weakened to %v", got)
	}
}
