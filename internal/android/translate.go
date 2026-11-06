package android

import (
	"sort"

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
func Translate(rules policy.Rules) (Policy, []string) {
	out := Policy{StatusReportingSettings: StatusReporting{
		DeviceSettingsEnabled: true, SoftwareInfoEnabled: true, HardwareStatusEnabled: true,
		ApplicationReportsEnabled: true,
	}}
	var undelivered []string
	for kind, r := range rules {
		switch kind {
		case policy.PasscodeRequired:
			if r.Bool {
				if out.PasswordRequirements == nil {
					out.PasswordRequirements = &PasswordRequirements{}
				}
				if out.PasswordRequirements.PasswordQuality == "" {
					out.PasswordRequirements.PasswordQuality = "SOMETHING"
				}
			}
		case policy.PasscodeMinLength:
			if out.PasswordRequirements == nil {
				out.PasswordRequirements = &PasswordRequirements{}
			}
			out.PasswordRequirements.PasswordMinimumLength = r.Num
			// A minimum length only means something for a quality that
			// has a length.
			out.PasswordRequirements.PasswordQuality = "NUMERIC"
		case policy.DiskEncryptionRequired:
			if r.Bool {
				out.EncryptionPolicy = "ENABLED_WITH_PASSWORD"
			}
		case policy.ScreenLockTimeoutMax:
			out.MaximumTimeToLock = itoa(int64(r.Num) * 1000)
		default:
			// os_version_min: Google has no "require at least" setting;
			// the version is reported and judged. firewall_required and
			// jailbreak_blocked: Android has no firewall, and root
			// detection is reported through Play Integrity rather than
			// set by policy. All three are judged on sync.
			undelivered = append(undelivered, string(kind))
		}
	}
	sort.Strings(undelivered)
	return out, undelivered
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
