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
		case catalog.List:
			v = []string{"com.example.svc"}
			if s.Key == "android.update_freezes" {
				v = []string{"10-20 to 12-31"} // a list whose entries must be periods
			}
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

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

// What Google says about a phone becomes what the engine judges from, and
// anything Google did not say stays unsaid.
func TestWhatGoogleReportsBecomesTheEnginesReport(t *testing.T) {
	d := Device{PatchLevel: "2026-10-05", ADBEnabled: no(), DevSettingsEnabled: yes(),
		VerifyApps: yes(), UnknownSources: no(), Posture: "SECURE"}
	rep := ReportFrom(d, Policy{})
	if rep.PatchLevel != "2026-10-05" || rep.PlayProtectEnabled == nil || !*rep.PlayProtectEnabled ||
		rep.UnknownSourcesEnabled == nil || *rep.UnknownSourcesEnabled || rep.IntegrityOK == nil || !*rep.IntegrityOK {
		t.Fatalf("%+v", rep)
	}
	// Developer options on is debugging on, whatever the USB switch says.
	if rep.DebuggingEnabled == nil || !*rep.DebuggingEnabled {
		t.Fatal("developer options were on and debugging was read as off")
	}
	// Both off is off.
	rep = ReportFrom(Device{ADBEnabled: no(), DevSettingsEnabled: no()}, Policy{})
	if rep.DebuggingEnabled == nil || *rep.DebuggingEnabled {
		t.Fatal("both off was read as on")
	}
	// An at-risk posture is a failed integrity check; no posture is no answer.
	for posture, want := range map[string]*bool{"AT_RISK": no(), "POTENTIAL_RISK": no(), "": nil, "POSTURE_UNSPECIFIED": nil} {
		got := ReportFrom(Device{Posture: posture}, Policy{}).IntegrityOK
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("posture %q read as %v", posture, got)
		}
	}
	// Nothing said stays unsaid: not false, not off, not fine.
	empty := ReportFrom(Device{}, Policy{})
	if empty.DebuggingEnabled != nil || empty.UnknownSourcesEnabled != nil || empty.PlayProtectEnabled != nil ||
		empty.IntegrityOK != nil || empty.PatchLevel != "" {
		t.Fatalf("a phone that said nothing was read as having said something: %+v", empty)
	}
}

// Three of the new rules are delivered as well as judged, so a phone is told to
// stay the way it is held to. The other two are judged only, and say so.
func TestTheNewRulesAreDeliveredOrNamedAsJudgedOnly(t *testing.T) {
	rules := policy.Rules{
		policy.DebuggingBlocked:      {Kind: policy.DebuggingBlocked, Bool: true},
		policy.UnknownSourcesBlocked: {Kind: policy.UnknownSourcesBlocked, Bool: true},
		policy.PlayProtectRequired:   {Kind: policy.PlayProtectRequired, Bool: true},
		policy.SecurityPatchMaxAge:   {Kind: policy.SecurityPatchMaxAge, Num: 30},
		policy.IntegrityRequired:     {Kind: policy.IntegrityRequired, Bool: true},
	}
	p, judged := TranslateWith(rules, nil)
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if got, _ := at(m, "debuggingFeaturesAllowed"); got != false {
		t.Errorf("debugging was not switched off: %v", got)
	}
	if got, _ := at(m, "advancedSecurityOverrides.untrustedAppsPolicy"); got != "DISALLOW_INSTALL" {
		t.Errorf("unknown sources were not blocked: %v", got)
	}
	if got, _ := at(m, "advancedSecurityOverrides.googlePlayProtectVerifyApps"); got != "VERIFY_APPS_ENFORCED" {
		t.Errorf("Play Protect was not enforced: %v", got)
	}
	if strings.Join(judged, ",") != "integrity_required,security_patch_max_age_days" {
		t.Errorf("the judged-only rules are %v", judged)
	}
}

// Both accessibility settings write one Google field. Which one wins is
// decided in one place, so it is the same every time; Go reads a map in a new
// random order on each run, so two hundred runs.
func TestAccessibilityServicesAreSettledTheSameWayEveryTime(t *testing.T) {
	both := catalog.Values{"android.accessibility_system_only": true, "android.accessibility_allowed": []string{"com.example.reader"}}
	listOnly := catalog.Values{"android.accessibility_allowed": []string{"com.example.reader"}}
	for i := 0; i < 200; i++ {
		got, ok := at(sent(t, nil, both), "permittedAccessibilityServices.packageNames")
		if !ok || len(got.([]any)) != 0 {
			t.Fatalf("run %d: system-only did not win over the list: %v", i, got)
		}
	}
	got, _ := at(sent(t, nil, listOnly), "permittedAccessibilityServices.packageNames")
	if l := got.([]any); len(l) != 1 || l[0] != "com.example.reader" {
		t.Fatalf("the list alone: %v", got)
	}
	// And with neither, nothing is sent, so nothing is restricted.
	if _, ok := at(sent(t, nil, catalog.Values{}), "permittedAccessibilityServices"); ok {
		t.Fatal("accessibility was restricted although no policy asked")
	}
}

// One of the two debugging switches unsaid is not "off". The rule is that both
// are off, so a phone that reports only one as off has not shown it.
func TestDebuggingIsOnlyOffWhenBothSwitchesSayOff(t *testing.T) {
	for name, tc := range map[string]struct {
		adb, dev *bool
		want     *bool
	}{
		"both off":            {no(), no(), no()},
		"adb on":              {yes(), no(), yes()},
		"dev options on":      {no(), yes(), yes()},
		"adb on, dev unsaid":  {yes(), nil, yes()},
		"dev on, adb unsaid":  {nil, yes(), yes()},
		"adb off, dev unsaid": {no(), nil, nil},
		"dev off, adb unsaid": {nil, no(), nil},
		"neither said":        {nil, nil, nil},
	} {
		got := ReportFrom(Device{ADBEnabled: tc.adb, DevSettingsEnabled: tc.dev}, Policy{}).DebuggingEnabled
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: read as %v, want %v", name, got, tc.want)
		}
	}
}

func TestTheLockScreenSwitchesMakeOneListInAFixedOrder(t *testing.T) {
	all := catalog.Values{"android.keyguard_trust_agents_blocked": true, "android.keyguard_biometrics_blocked": true,
		"android.keyguard_notifications_hidden": true}
	for i := 0; i < 200; i++ {
		got, ok := at(sent(t, nil, all), "keyguardDisabledFeatures")
		l, _ := got.([]any)
		if !ok || len(l) != 3 || l[0] != "BIOMETRICS" || l[1] != "UNREDACTED_NOTIFICATIONS" || l[2] != "TRUST_AGENTS" {
			t.Fatalf("run %d: three switches did not make three entries in order: %v", i, got)
		}
	}
	got, _ := at(sent(t, nil, catalog.Values{"android.keyguard_trust_agents_blocked": true}), "keyguardDisabledFeatures")
	if l, _ := got.([]any); len(l) != 1 || l[0] != "TRUST_AGENTS" {
		t.Fatalf("one switch: %v", got)
	}
	if _, ok := at(sent(t, nil, catalog.Values{"android.camera_disabled": true}), "keyguardDisabledFeatures"); ok {
		t.Fatal("the lock screen was restricted although no policy asked")
	}
}

// Two policies that each allow networks the other does not allow nothing. It
// must never become "no list", which would allow every network, and Google
// refuses an empty list, so the answer is a list no network can match.
func TestTwoDisjointWifiListsAllowNoNetworkAtAll(t *testing.T) {
	a := catalog.Values{"android.wifi_allowed_networks": []string{"Office"}}
	b := catalog.Values{"android.wifi_allowed_networks": []string{"Depot"}}
	for _, merged := range []catalog.Values{catalog.Merge(a, b), catalog.Merge(b, a)} {
		m := sent(t, nil, merged)
		typ, _ := at(m, "deviceConnectivityManagement.wifiSsidPolicy.wifiSsidPolicyType")
		ssids, _ := at(m, "deviceConnectivityManagement.wifiSsidPolicy.wifiSsids")
		l, _ := ssids.([]any)
		if typ != "WIFI_SSID_ALLOWLIST" || len(l) != 1 || l[0].(map[string]any)["wifiSsid"] != catalog.NoWifiAllowed {
			t.Fatalf("disjoint lists did not become an allow-list of nothing: %v", m["deviceConnectivityManagement"])
		}
	}
	m := sent(t, nil, catalog.Merge(a, catalog.Values{"android.wifi_allowed_networks": []string{"Depot", "Office"}}))
	ssids, _ := at(m, "deviceConnectivityManagement.wifiSsidPolicy.wifiSsids")
	if l, _ := ssids.([]any); len(l) != 1 || l[0].(map[string]any)["wifiSsid"] != "Office" {
		t.Fatalf("the network both allow was not the one left: %v", ssids)
	}
}

func TestAFreezeIsSentAsGoogleWantsItAndNeverWithoutAnUpdateType(t *testing.T) {
	freeze := catalog.Values{"android.update_freezes": []string{"10-20 to 12-31"}}
	m := sent(t, nil, freeze)
	got, _ := at(m, "systemUpdate.freezePeriods")
	l, _ := got.([]any)
	if len(l) != 1 {
		t.Fatalf("the freeze was not sent: %v", m["systemUpdate"])
	}
	p := l[0].(map[string]any)
	s, e := p["startDate"].(map[string]any), p["endDate"].(map[string]any)
	if s["month"] != float64(10) || s["day"] != float64(20) || e["month"] != float64(12) || e["day"] != float64(31) {
		t.Fatalf("the dates are wrong: %v", p)
	}
	if typ, _ := at(m, "systemUpdate.type"); typ != "AUTOMATIC" {
		t.Fatalf("a freeze with no update type chosen must make updates automatic, got %v", typ)
	}
	// A type the policies chose is kept.
	m = sent(t, nil, catalog.Merge(freeze, catalog.Values{"android.system_updates": "POSTPONE"}))
	if typ, _ := at(m, "systemUpdate.type"); typ != "POSTPONE" {
		t.Fatalf("the chosen update type was replaced: %v", typ)
	}
}

func TestTheOtherNewSettingsAreSentInGooglesWords(t *testing.T) {
	m := sent(t, nil, catalog.Values{
		"android.minimum_android": "33", "android.microphone_disabled": true, "android.usb_data_blocked": true,
		"android.kiosk_launcher": true, "android.two_g_blocked": true, "android.data_roaming_blocked": true})
	for path, want := range map[string]any{
		"minimumApiLevel":                              float64(33), // a number, not "33"
		"microphoneAccess":                             "MICROPHONE_ACCESS_DISABLED",
		"deviceConnectivityManagement.usbDataAccess":   "DISALLOW_USB_DATA_TRANSFER",
		"kioskCustomLauncherEnabled":                   true,
		"deviceRadioState.cellularTwoGState":           "CELLULAR_TWO_G_DISABLED",
		"dataRoamingDisabled":                          true,
	} {
		if got, ok := at(m, path); !ok || got != want {
			t.Errorf("%s: got %v, want %v", path, got, want)
		}
	}
}

func TestTheOldestAndroidIsTheNewestOfThoseAsked(t *testing.T) {
	a := catalog.Values{"android.minimum_android": "29"}
	b := catalog.Values{"android.minimum_android": "34"}
	for _, merged := range []catalog.Values{catalog.Merge(a, b), catalog.Merge(b, a)} {
		if got, _ := at(sent(t, nil, merged), "minimumApiLevel"); got != float64(34) {
			t.Fatalf("the higher minimum did not win: %v", got)
		}
	}
}
