package android

import (
	"encoding/json"
	"sort"

	"platform/internal/catalog"
	"platform/internal/policy"
)

// Policy is the body delivered to Google: the subset of the Android
// Management API's policy resource this platform drives. Field names are
// Google's, so the JSON is the API's.
type Policy struct {
	PasswordRequirements *PasswordRequirements `json:"passwordRequirements,omitempty"`
	MaximumTimeToLock    string                `json:"maximumTimeToLock,omitempty"` // milliseconds, as a string
	EncryptionPolicy     string                `json:"encryptionPolicy,omitempty"`
	// StatusReportingSettings asks Google to report the facts the engine
	// judges from. Without them a device says nothing and is unknown.
	StatusReportingSettings StatusReporting `json:"statusReportingSettings"`

	// Extra is every other setting the policy carries (internal/catalog):
	// camera, apps, wallpaper, USB and the rest. It is written into the same
	// JSON object as the fields above, deep-merged, so a nested field such as
	// passwordRequirements keeps both what the rules gave it and what the
	// settings did.
	Extra map[string]any `json:"-"`
}

// MarshalJSON writes the typed fields and Extra as one object.
func (p Policy) MarshalJSON() ([]byte, error) {
	type plain Policy
	b, err := json.Marshal(plain(p))
	if err != nil || len(p.Extra) == 0 {
		return b, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	deepMerge(m, p.Extra)
	return json.Marshal(m)
}

func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
}

type PasswordRequirements struct {
	PasswordMinimumLength int    `json:"passwordMinimumLength,omitempty"`
	PasswordQuality       string `json:"passwordQuality,omitempty"`
}

type StatusReporting struct {
	DeviceSettingsEnabled     bool `json:"deviceSettingsEnabled"`
	SoftwareInfoEnabled       bool `json:"softwareInfoEnabled"`
	HardwareStatusEnabled     bool `json:"hardwareStatusEnabled"`
	ApplicationReportsEnabled bool `json:"applicationReportsEnabled"`
}

// Translate turns the effective rules for Android devices into the policy
// Google enforces on them, and names every rule it could NOT deliver.
//
// A rule that cannot be delivered is not dropped silently: it is still
// judged on sync, from what Google reports, and the person saving the
// policy is told which rules are judged rather than enforced. A policy that
// quietly enforced less than it said would be the same lie as a rule name
// nobody understood.
func Translate(rules policy.Rules) (Policy, []string) { return TranslateWith(rules, nil) }

// TranslateWith is Translate with the settings the policies carry beside
// their rules (internal/catalog).
//
// The rules and the settings are put on one footing before anything is sent:
// each deliverable rule is turned into the setting that says the same thing,
// and the two sets are merged, strictest wins. A rule that asks for a
// passcode of eight and a setting that asks for twelve gives twelve; a
// setting of six under a rule of eight gives eight, so the phone is never
// handed a looser value than the one it is judged against.
func TranslateWith(rules policy.Rules, cfg catalog.Values) (Policy, []string) {
	out := Policy{StatusReportingSettings: StatusReporting{
		DeviceSettingsEnabled: true, SoftwareInfoEnabled: true, HardwareStatusEnabled: true,
		ApplicationReportsEnabled: true,
	}}
	var undelivered []string
	fromRules := catalog.Values{}
	for kind, r := range rules {
		switch kind {
		case policy.PasscodeRequired:
			// The quality is worked out below, once, from both rules. Setting
			// it here would make the answer depend on which rule the map
			// happens to hand over first.
		case policy.PasscodeMinLength:
			fromRules["android.password_min_length"] = r.Num
		case policy.DiskEncryptionRequired:
			if r.Bool {
				fromRules["android.encryption_required"] = true
			}
		// These three are judged from what Google reports AND delivered, so a
		// phone is both held to the rule and told to stay that way.
		case policy.DebuggingBlocked:
			if r.Bool {
				fromRules["android.debugging_blocked"] = true
			}
		case policy.UnknownSourcesBlocked:
			if r.Bool {
				fromRules["android.untrusted_apps_blocked"] = true
			}
		case policy.PlayProtectRequired:
			if r.Bool {
				fromRules["android.play_protect_required"] = true
			}
		case policy.ScreenLockTimeoutMax:
			fromRules["android.screen_lock_seconds"] = r.Num
		default:
			// os_version_min: Google has no "require at least" setting;
			// the version is reported and judged. firewall_required and
			// jailbreak_blocked: Android has no firewall, and root
			// detection is reported through Play Integrity rather than
			// set by policy. All three are judged on sync.
			undelivered = append(undelivered, string(kind))
		}
	}
	// A minimum length only means something for a quality that has a length,
	// so a length rule asks for a PIN; a passcode rule alone asks for any lock.
	// Decided from the rules themselves, never from the order they are read in:
	// a stronger answer must not be overwritten by a weaker one.
	if _, ok := rules[policy.PasscodeMinLength]; ok {
		fromRules["android.password_quality"] = "NUMERIC"
	} else if r, ok := rules[policy.PasscodeRequired]; ok && r.Bool {
		fromRules["android.password_quality"] = "SOMETHING"
	}
	merged := catalog.Merge(fromRules, cfg)

	// The four settings the engine judges from are typed fields, because
	// ReportFrom reads them back.
	if v, ok := merged["android.password_quality"].(string); ok {
		out.passwords().PasswordQuality = v
	}
	if v, ok := merged["android.password_min_length"].(int); ok {
		out.passwords().PasswordMinimumLength = v
	}
	if v, ok := merged["android.screen_lock_seconds"].(int); ok {
		out.MaximumTimeToLock = itoa(int64(v) * 1000)
	}
	if v, _ := merged["android.encryption_required"].(bool); v {
		out.EncryptionPolicy = "ENABLED_WITH_PASSWORD"
	}

	// Everything else goes where the catalogue says.
	typed := map[string]bool{"android.password_quality": true, "android.password_min_length": true,
		"android.screen_lock_seconds": true, "android.encryption_required": true,
		// Both settings write the same field, so they are settled below, in one
		// place, rather than by whichever the map hands over first.
		"android.accessibility_system_only": true, "android.accessibility_allowed": true}
	for key, v := range merged {
		if typed[key] {
			continue
		}
		s, ok := catalog.Lookup(key)
		if !ok || s.OS != "android" {
			continue
		}
		if s.Kind == catalog.Apps {
			out.addApps(v.([]catalog.AppRule))
			continue
		}
		sent, include := s.Send(v)
		if !include {
			continue
		}
		out.set(s.Path, sent)
	}
	// Only Android's own accessibility services, or only the ones listed. The
	// stricter wins, and which one is decided here and not by map order.
	if v, _ := merged["android.accessibility_system_only"].(bool); v {
		out.set("permittedAccessibilityServices.packageNames", []string{})
	} else if list, ok := merged["android.accessibility_allowed"].([]string); ok {
		out.set("permittedAccessibilityServices.packageNames", list)
	}
	sort.Strings(undelivered)
	return out, undelivered
}

func (p *Policy) passwords() *PasswordRequirements {
	if p.PasswordRequirements == nil {
		p.PasswordRequirements = &PasswordRequirements{}
	}
	return p.PasswordRequirements
}

// set writes a value at a dotted path in Extra.
func (p *Policy) set(path string, v any) {
	if p.Extra == nil {
		p.Extra = map[string]any{}
	}
	m := p.Extra
	parts := splitPath(path)
	for _, part := range parts[:len(parts)-1] {
		next, ok := m[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[part] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = v
}

func splitPath(path string) []string {
	var out []string
	cur := ""
	for _, c := range path {
		if c == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	return append(out, cur)
}

// addApps turns the apps a policy lists into Google's applications array.
func (p *Policy) addApps(list []catalog.AppRule) {
	install := map[string]string{"required": "FORCE_INSTALLED", "available": "AVAILABLE", "blocked": "BLOCKED"}
	apps := make([]map[string]any, 0, len(list))
	for _, a := range list {
		apps = append(apps, map[string]any{"packageName": a.Package, "installType": install[a.Install]})
	}
	if len(apps) > 0 {
		p.set("applications", apps)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ReportFrom builds the engine's report from what Google says about a
// device. Anything Google did not say is left nil, exactly as the agent
// leaves unsaid what it cannot determine.
//
// Two inferences, stated. Google never reports a passcode's length or the
// screen-lock timeout, but it does report whether the device is compliant
// with the policy WE delivered, and that policy carries the minimum length
// and the maximum timeout. A device Google calls compliant has a passcode
// at least that long and locks at least that soon, because Google would
// not let it keep otherwise. A device Google calls non-compliant says
// nothing about either, and both fields stay unknown.
//
// Rooting is Google's verified-boot check, reported under that name.
func ReportFrom(d Device, delivered Policy) policy.Report {
	rep := policy.Report{OSVersion: d.AndroidVersion, Apps: d.Apps}
	rep.PasscodeSet = d.Secure
	rep.DiskEncryption = d.Encrypted
	// What Google says about the phone's settings and security. Each stays
	// unsaid when Google did not say it.
	rep.PatchLevel = d.PatchLevel
	rep.UnknownSourcesEnabled = d.UnknownSources
	rep.PlayProtectEnabled = d.VerifyApps
	// The rule is that USB debugging AND developer options are off. Either one
	// on is debugging on. Both reported off is off. Anything less, one off and
	// the other unsaid, is not a pass: it stays unsaid, and the rule comes out
	// unknown.
	switch {
	case (d.ADBEnabled != nil && *d.ADBEnabled) || (d.DevSettingsEnabled != nil && *d.DevSettingsEnabled):
		on := true
		rep.DebuggingEnabled = &on
	case d.ADBEnabled != nil && d.DevSettingsEnabled != nil:
		off := false
		rep.DebuggingEnabled = &off
	}
	switch d.Posture {
	case "SECURE":
		ok := true
		rep.IntegrityOK = &ok
	case "AT_RISK", "POTENTIAL_RISK":
		ok := false
		rep.IntegrityOK = &ok
	}
	if d.VerifiedBoot != nil {
		rooted := !*d.VerifiedBoot
		rep.Jailbroken = &rooted
	}
	if d.Compliant {
		if d.Secure != nil && *d.Secure && delivered.PasswordRequirements != nil &&
			delivered.PasswordRequirements.PasswordMinimumLength > 0 {
			n := delivered.PasswordRequirements.PasswordMinimumLength
			rep.PasscodeLength = &n
		}
		if ms := atoi(delivered.MaximumTimeToLock); ms > 0 {
			secs := int(ms / 1000)
			rep.ScreenLockTimeout = &secs
		}
	}
	return rep
}

func atoi(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
