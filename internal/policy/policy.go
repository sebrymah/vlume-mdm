// Package policy decides what a tenant requires of a device and whether that
// device meets it.
//
// Three decisions shape everything here, and each is a position worth
// arguing rather than an implementation detail.
//
// RULES ARE A FIXED CATALOGUE, NOT AN EXPRESSION LANGUAGE. Every rule a
// tenant can write is one of the kinds below, with a typed value. The
// alternative — letting policies carry expressions — looks more powerful and
// costs three things: a sandbox to defend, an unanswerable question ("what
// does this policy actually require?") that can only be resolved by running
// it, and the merge below becomes undecidable.
//
// THE STRICTEST VALUE WINS. When several policies apply to one device their
// requirements are merged by taking the most demanding of each. Not the
// newest, not the highest priority, not the last one assigned. This is the
// classic place MDM products go wrong: an administrator assigns a loose
// policy to a group and silently relaxes a strict one that was already
// there. Merging strictly makes that impossible and makes the result
// independent of the order policies are read in, which is the property that
// stops this being a source of "it was compliant yesterday" tickets.
//
// NOT KNOWING IS NOT PASSING. A device that does not report on a rule fails
// to demonstrate it. It is not compliant; it is unknown, which is its own
// state and is never counted as a pass. A stale report is the same thing
// with a different cause.
package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"platform/internal/catalog"
)

// MaxReportAge is how long a report stays good for.
//
// A managed device checks in at least daily, so a week is already several
// missed check-ins. It is a constant rather than a tenant setting because a
// tenant that can raise it can make a silent device look compliant, which is
// the one thing this value exists to prevent. Making it configurable is a
// decision to take deliberately, not by leaving a field on a form.
const MaxReportAge = 7 * 24 * time.Hour

type Kind string

const (
	PasscodeRequired       Kind = "passcode_required"
	PasscodeMinLength      Kind = "passcode_min_length"
	DiskEncryptionRequired Kind = "disk_encryption_required"
	ScreenLockTimeoutMax   Kind = "screen_lock_timeout_max"
	OSVersionMin           Kind = "os_version_min"
	FirewallRequired       Kind = "firewall_required"
	JailbreakBlocked       Kind = "jailbreak_blocked"

	// What a phone can say about itself that a laptop's agent cannot, read from
	// what Google reports (internal/android). Each is judged exactly as the
	// seven above are: a device that does not say is unknown, never a pass.
	SecurityPatchMaxAge   Kind = "security_patch_max_age_days"
	DebuggingBlocked      Kind = "debugging_blocked"
	UnknownSourcesBlocked Kind = "unknown_sources_blocked"
	PlayProtectRequired   Kind = "play_protect_required"
	IntegrityRequired     Kind = "integrity_required"
)

type valueKind int

const (
	boolean valueKind = iota
	count
	seconds
	version
)

// mergeRule says which way "stricter" runs for this kind.
type mergeRule int

const (
	// requiringItIsStricter: true beats false.
	requiringItIsStricter mergeRule = iota
	// higherIsStricter: a longer passcode, a newer OS.
	higherIsStricter
	// lowerIsStricter: a shorter screen-lock timeout.
	lowerIsStricter
)

type spec struct {
	value valueKind
	merge mergeRule
	// asks renders the requirement the way it is shown to a person. The
	// finding a device administrator reads is built from this, so it is
	// written as a sentence rather than a field name.
	asks func(Requirement) string
}

// catalogue is the whole vocabulary. Adding to it is a deliberate act: a new
// kind needs a value type, a direction for "stricter", a sentence, and a
// check in Evaluate. Four places, on purpose, because a rule that merges but
// is never evaluated would be a requirement that silently does nothing.
var catalogue = map[Kind]spec{
	PasscodeRequired: {boolean, requiringItIsStricter, func(Requirement) string {
		return "a passcode must be set"
	}},
	PasscodeMinLength: {count, higherIsStricter, func(r Requirement) string {
		return fmt.Sprintf("the passcode must be at least %d characters", r.Num)
	}},
	DiskEncryptionRequired: {boolean, requiringItIsStricter, func(Requirement) string {
		return "the disk must be encrypted"
	}},
	ScreenLockTimeoutMax: {seconds, lowerIsStricter, func(r Requirement) string {
		return fmt.Sprintf("the screen must lock within %d seconds", r.Num)
	}},
	OSVersionMin: {version, higherIsStricter, func(r Requirement) string {
		return "the operating system must be at least version " + r.Text
	}},
	FirewallRequired: {boolean, requiringItIsStricter, func(Requirement) string {
		return "the firewall must be on"
	}},
	JailbreakBlocked: {boolean, requiringItIsStricter, func(Requirement) string {
		return "the device must not be jailbroken or rooted"
	}},
	SecurityPatchMaxAge: {count, lowerIsStricter, func(r Requirement) string {
		return fmt.Sprintf("the security patch must be no more than %d days old", r.Num)
	}},
	DebuggingBlocked: {boolean, requiringItIsStricter, func(Requirement) string {
		return "USB debugging and developer options must be off"
	}},
	UnknownSourcesBlocked: {boolean, requiringItIsStricter, func(Requirement) string {
		return "installing apps from unknown sources must be off"
	}},
	PlayProtectRequired: {boolean, requiringItIsStricter, func(Requirement) string {
		return "Google Play Protect must be on"
	}},
	IntegrityRequired: {boolean, requiringItIsStricter, func(Requirement) string {
		return "the device must pass its integrity check"
	}},
}

// Kinds returns the catalogue in a fixed order, for the console's policy
// editor and for a test that asserts every kind is evaluated.
func Kinds() []Kind {
	out := make([]Kind, 0, len(catalogue))
	for k := range catalogue {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Requirement is one rule with its value and where it came from.
type Requirement struct {
	Kind Kind   `json:"kind"`
	Bool bool   `json:"bool,omitempty"`
	Num  int    `json:"num,omitempty"`
	Text string `json:"text,omitempty"`
	// From names the policy and version that asked for this. A finding that
	// cannot say which policy it came from is one an administrator cannot
	// act on, so provenance is carried through the merge rather than
	// reconstructed afterwards.
	From string `json:"from"`
	// Fix says the policy that asked for this also asked the device to put
	// a failure right by itself (the remediate key). It travels with the
	// requirement through the merge, so when two policies ask for the same
	// rule the device changes a setting only on the say-so of the one whose
	// value won.
	Fix bool `json:"fix,omitempty"`
}

func (r Requirement) Says() string {
	s, ok := catalogue[r.Kind]
	if !ok {
		return string(r.Kind)
	}
	return s.asks(r)
}

// Rules is the effective requirement set for one device.
type Rules map[Kind]Requirement

// ---------------------------------------------------------------- parsing

var (
	ErrUnknownRule = fmt.Errorf("policy: unknown rule")
	ErrBadValue    = fmt.Errorf("policy: wrong value for rule")
)

// Parse reads a policy body.
//
// An unknown rule name is an ERROR, not something to skip. A policy that
// says passcode_minimum_length because someone typed it from memory would
// otherwise be saved, displayed as a policy, and require nothing at all.
// Silently ignoring a key in a security policy means the policy lies, and
// the lie only surfaces during an incident.
func Parse(from string, body []byte) (Rules, error) {
	rules, _, err := ParseBody(from, body)
	return rules, err
}

// OnFailureKey is one of the two keys in a policy body that are not rules:
// what happens to a device that fails. "none" (the default) or "quarantine".
const OnFailureKey = "on_failure"

// RemediateKey is the other: true asks the device to put a failure right
// by itself where it can (turn the firewall on, start disk encryption, set
// the password length policy, shorten the screen lock). It is a separate
// key from on_failure because the two are different decisions: one is what
// the server does to a failing device, the other is whether the device may
// change its own settings. A tenant that only wants to observe must never
// find its fleet's settings changed. The default is false.
const RemediateKey = "remediate"

const (
	FailNone       = "none"
	FailQuarantine = "quarantine"
)

// ConfigKey is the third reserved key in a policy body: the settings the
// policy applies to a device, from the catalogue for its operating system
// (internal/catalog). The rules judge a device; the config changes it.
const ConfigKey = "config"

// Settings is what a policy body says beyond its rules.
type Settings struct {
	OnFailure string
	Remediate bool
	// Config is what the policy sets on a device, checked against the
	// catalogue. Which system it is for is checked when the policy is saved,
	// because the body does not say.
	Config catalog.Values
}

// ParseBody reads a policy body: the rules, and what failing them means.
func ParseBody(from string, body []byte) (Rules, Settings, error) {
	set := Settings{OnFailure: FailNone}
	if len(body) == 0 {
		return Rules{}, set, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, Settings{}, fmt.Errorf("policy: the policy body is not an object: %w", err)
	}

	if v, ok := raw[OnFailureKey]; ok {
		if err := json.Unmarshal(v, &set.OnFailure); err != nil ||
			(set.OnFailure != FailNone && set.OnFailure != FailQuarantine) {
			return nil, Settings{}, fmt.Errorf("%w: %s is \"none\" or \"quarantine\"", ErrBadValue, OnFailureKey)
		}
		delete(raw, OnFailureKey)
	}
	if v, ok := raw[RemediateKey]; ok {
		if err := json.Unmarshal(v, &set.Remediate); err != nil {
			return nil, Settings{}, fmt.Errorf("%w: %s takes true or false", ErrBadValue, RemediateKey)
		}
		delete(raw, RemediateKey)
	}

	if v, ok := raw[ConfigKey]; ok {
		var cfgRaw map[string]json.RawMessage
		if err := json.Unmarshal(v, &cfgRaw); err != nil {
			return nil, Settings{}, fmt.Errorf("%w: %s is an object of settings", ErrBadValue, ConfigKey)
		}
		cfg, err := catalog.Parse(cfgRaw)
		if err != nil {
			return nil, Settings{}, fmt.Errorf("policy: %w", err)
		}
		set.Config = cfg
		delete(raw, ConfigKey)
	}

	out := Rules{}
	for name, value := range raw {
		kind := Kind(name)
		s, ok := catalogue[kind]
		if !ok {
			return nil, Settings{}, fmt.Errorf("%w: %q. The rules this platform understands are: %s",
				ErrUnknownRule, name, joinKinds())
		}
		r := Requirement{Kind: kind, From: from}
		switch s.value {
		case boolean:
			if err := json.Unmarshal(value, &r.Bool); err != nil {
				return nil, Settings{}, fmt.Errorf("%w: %s takes true or false", ErrBadValue, name)
			}
		case count, seconds:
			if err := json.Unmarshal(value, &r.Num); err != nil {
				return nil, Settings{}, fmt.Errorf("%w: %s takes a whole number", ErrBadValue, name)
			}
			if r.Num <= 0 {
				return nil, Settings{}, fmt.Errorf("%w: %s must be greater than zero", ErrBadValue, name)
			}
		case version:
			if err := json.Unmarshal(value, &r.Text); err != nil {
				return nil, Settings{}, fmt.Errorf("%w: %s takes a version like \"15.1\"", ErrBadValue, name)
			}
			if !looksLikeVersion(r.Text) {
				return nil, Settings{}, fmt.Errorf("%w: %q is not a version like \"15.1\"", ErrBadValue, r.Text)
			}
		}
		out[kind] = r
	}
	return out, set, nil
}

func joinKinds() string {
	ks := Kinds()
	s := make([]string, len(ks))
	for i, k := range ks {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

// ---------------------------------------------------------------- merging

// Merge combines the policies that apply to one device, taking the strictest
// value for each rule.
//
// The result does not depend on the order the sets arrive in. That is the
// property being bought: the same device with the same policies always gets
// the same requirements, whatever order the rows came back in and whatever
// order they were created.
func Merge(sets ...Rules) Rules {
	out := Rules{}
	for _, set := range sets {
		for kind, want := range set {
			held, seen := out[kind]
			if !seen {
				out[kind] = want
				continue
			}
			out[kind] = stricter(held, want)
		}
	}
	return out
}

func stricter(a, b Requirement) Requirement {
	s, ok := catalogue[a.Kind]
	if !ok {
		return a
	}
	switch s.merge {
	case requiringItIsStricter:
		if b.Bool && !a.Bool {
			return b
		}
		if a.Bool && !b.Bool {
			return a
		}
	case higherIsStricter:
		if s.value == version {
			if compareVersions(b.Text, a.Text) > 0 {
				return b
			}
			return a
		}
		if b.Num > a.Num {
			return b
		}
	case lowerIsStricter:
		if b.Num < a.Num {
			return b
		}
	}
	// Equal. Keep the one already held so that the result is stable, and
	// name both sources so a person can see the rule is asked for twice.
	// Either asking the device to put it right is enough: the value is the
	// same, so there is no policy whose number is being imposed unasked.
	if a.From != b.From && !strings.Contains(a.From, b.From) {
		a.From = a.From + " and " + b.From
	}
	a.Fix = a.Fix || b.Fix
	return a
}

// Describe lists the effective requirements in a fixed order, for the device
// page and for an administrator asking what a laptop actually has to do.
func (r Rules) Describe() []string {
	out := []string{}
	for _, k := range Kinds() {
		req, ok := r[k]
		if !ok {
			continue
		}
		// A rule set to false is not a requirement. It is the absence of
		// one, and listing "a passcode need not be set" as a requirement
		// would be noise.
		if catalogue[k].value == boolean && !req.Bool {
			continue
		}
		out = append(out, req.Says()+" (from "+req.From+")")
	}
	return out
}

// ---------------------------------------------------------------- the scope

// Scope is who a policy applies to. An empty field means any.
type Scope struct {
	OSFamily  string
	Ownership string
}

func (s Scope) Matches(osFamily, ownership string) bool {
	if s.OSFamily != "" && s.OSFamily != osFamily {
		return false
	}
	if s.Ownership != "" && s.Ownership != ownership {
		return false
	}
	return true
}

func (s Scope) Describe() string {
	switch {
	case s.OSFamily == "" && s.Ownership == "":
		return "every device"
	case s.Ownership == "":
		return "every " + s.OSFamily + " device"
	case s.OSFamily == "":
		return "every " + s.Ownership + "-owned device"
	default:
		return "every " + s.Ownership + "-owned " + s.OSFamily + " device"
	}
}

// ------------------------------------------------------------- evaluating

// Report is what a device says about itself.
//
// Every field a rule reads is a POINTER, so "did not say" is a different
// value from "said false". Without that, a device that omits the disk
// encryption field looks exactly like one that reported an unencrypted disk,
// and an agent with a bug would quietly mark a fleet non-compliant, or a
// missing field would read as a pass. Both are worse than saying we do not
// know.
// App is one installed application, as the device reports it (F3).
type App struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
}

type Report struct {
	// Apps is the installed-app inventory. Nil means the device did not
	// say; an empty list means it said "none". The engine judges nothing
	// from it; it is kept for the people who ask who has what.
	Apps []App `json:"apps,omitempty"`
	// MACAddresses are the hardware addresses of the device's network
	// interfaces, for the network's door, which knows a device by the
	// address it authenticated with. Nil means the device did not say.
	MACAddresses      []string `json:"mac_addresses,omitempty"`
	PasscodeSet       *bool    `json:"passcode_set,omitempty"`
	PasscodeLength    *int     `json:"passcode_length,omitempty"`
	DiskEncryption    *bool    `json:"disk_encryption,omitempty"`
	ScreenLockTimeout *int     `json:"screen_lock_timeout,omitempty"`
	OSVersion         string   `json:"os_version,omitempty"`
	Firewall          *bool    `json:"firewall,omitempty"`
	Jailbroken        *bool    `json:"jailbroken,omitempty"`

	// What an Android phone reports through Google. PatchLevel is the date of
	// its security patch, "2026-10-05". The others are pointers for the same
	// reason as the rest: not said is not false.
	PatchLevel            string `json:"security_patch_level,omitempty"`
	DebuggingEnabled      *bool  `json:"debugging_enabled,omitempty"`
	UnknownSourcesEnabled *bool  `json:"unknown_sources_enabled,omitempty"`
	PlayProtectEnabled    *bool  `json:"play_protect_enabled,omitempty"`
	IntegrityOK           *bool  `json:"integrity_ok,omitempty"`
}

type Finding struct {
	Kind Kind   `json:"kind"`
	Rule string `json:"rule"` // what was required
	Saw  string `json:"saw"`  // what the device said
	From string `json:"from"` // which policy asked
	// Unknown separates "this failed" from "this could not be checked".
	// They are both reasons a device is not compliant and they need
	// different words in front of a person: one is a device to fix, the
	// other is an agent to look at.
	Unknown bool `json:"unknown,omitempty"`
	// Num is the number the rule asks for, where it asks for one: the
	// passcode length or the lock timeout. The device needs the number,
	// not the sentence, to put the setting right.
	Num int `json:"num,omitempty"`
	// Fix says the policy asked the device to put this right by itself.
	// Never set on an Unknown finding: a setting the agent could not read
	// is not one it should change.
	Fix bool `json:"fix,omitempty"`
}

// found builds the finding for a requirement a device did not meet, or
// could not answer. One place, so every finding carries the number and
// the mark the same way.
func found(req Requirement, saw string, unknown bool) Finding {
	return Finding{
		Kind:    req.Kind,
		Rule:    req.Says(),
		Saw:     saw,
		From:    req.From,
		Unknown: unknown,
		Num:     req.Num,
		Fix:     req.Fix && !unknown,
	}
}

const (
	Compliant    = "compliant"
	NotCompliant = "not_compliant"
	Unknown      = "state_unknown"
)

type Verdict struct {
	State    string
	Findings []Finding
}

// Evaluate decides one device against its effective rules.
//
// Order of conclusions, which matters: a rule that FAILED outranks a rule
// that could not be checked. A device with one broken requirement and one
// missing field is not compliant, not unknown, because we already know
// enough to act.
func Evaluate(rules Rules, rep Report, reportedAt, now time.Time) Verdict {
	// A stale report is not evidence of anything. Checking it here, at read
	// time, rather than with something that sweeps and marks rows later, is
	// the difference between a rule and a timer: this fires the moment
	// anyone looks.
	if now.Sub(reportedAt) > MaxReportAge {
		return Verdict{State: Unknown, Findings: []Finding{{
			Rule:    maxAgeWords(),
			Saw:     "last reported " + reportedAt.UTC().Format("2 Jan 2006"),
			From:    "this platform",
			Unknown: true,
		}}}
	}

	findings := []Finding{}
	failed, unknown := false, false
	note := func(f Finding) {
		findings = append(findings, f)
		if f.Unknown {
			unknown = true
		} else {
			failed = true
		}
	}

	for _, kind := range Kinds() {
		req, wanted := rules[kind]
		if !wanted {
			continue
		}
		switch kind {
		case PasscodeRequired:
			if !req.Bool {
				continue
			}
			checkBool(note, req, rep.PasscodeSet, "no passcode is set")
		case DiskEncryptionRequired:
			if !req.Bool {
				continue
			}
			checkBool(note, req, rep.DiskEncryption, "the disk is not encrypted")
		case FirewallRequired:
			if !req.Bool {
				continue
			}
			checkBool(note, req, rep.Firewall, "the firewall is off")
		case JailbreakBlocked:
			if !req.Bool {
				continue
			}
			// The sense is inverted: the rule is satisfied when the device
			// reports NOT jailbroken.
			switch {
			case rep.Jailbroken == nil:
				note(found(req, "the device did not say", true))
			case *rep.Jailbroken:
				note(found(req, "the device is jailbroken or rooted", false))
			}
		case PasscodeMinLength:
			switch {
			case rep.PasscodeLength == nil:
				note(found(req, "the device did not say", true))
			case *rep.PasscodeLength < req.Num:
				note(found(req,
					fmt.Sprintf("the passcode is %d characters", *rep.PasscodeLength),
					false))
			}
		case ScreenLockTimeoutMax:
			// Zero is "never": the convention every platform uses for a
			// lock that is switched off (an idle time of 0 on a Mac, an
			// inactivity timeout of 0 on Windows). It fails rather than
			// passing as "within 0 seconds".
			switch {
			case rep.ScreenLockTimeout == nil:
				note(found(req, "the device did not say", true))
			case *rep.ScreenLockTimeout <= 0:
				note(found(req, "the screen never locks", false))
			case *rep.ScreenLockTimeout > req.Num:
				note(found(req,
					fmt.Sprintf("it locks after %d seconds", *rep.ScreenLockTimeout),
					false))
			}
		case OSVersionMin:
			switch {
			case rep.OSVersion == "":
				note(found(req, "the device did not say", true))
			case compareVersions(rep.OSVersion, req.Text) < 0:
				note(found(req, "it is on "+rep.OSVersion, false))
			}
		case SecurityPatchMaxAge:
			patched, ok := parsePatchLevel(rep.PatchLevel)
			switch {
			case rep.PatchLevel == "":
				note(found(req, "the device did not say", true))
			case !ok:
				// A date we cannot read is not a pass.
				note(found(req, fmt.Sprintf("its patch level, %q, is not a date this platform can read", rep.PatchLevel), true))
			case patched.After(now.Add(48 * time.Hour)):
				// No phone has a patch from the future. A date that far ahead is
				// a wrong clock or a made-up report, and a negative age must never
				// read as "newer than any limit". Two days of slack for clock skew.
				note(found(req, fmt.Sprintf("its patch level, %s, is in the future, which a real phone cannot have", rep.PatchLevel), true))
			default:
				// Whole days, so a patch exactly as old as the limit passes and
				// one a day older does not.
				if age := int(now.Sub(patched).Hours() / 24); age > req.Num {
					note(found(req, fmt.Sprintf("its security patch is %d days old (%s)", age, rep.PatchLevel), false))
				}
			}
		case DebuggingBlocked:
			if !req.Bool {
				continue
			}
			checkOff(note, req, rep.DebuggingEnabled, "USB debugging or developer options are on")
		case UnknownSourcesBlocked:
			if !req.Bool {
				continue
			}
			checkOff(note, req, rep.UnknownSourcesEnabled, "installing from unknown sources is allowed")
		case PlayProtectRequired:
			if !req.Bool {
				continue
			}
			checkBool(note, req, rep.PlayProtectEnabled, "Google Play Protect is off")
		case IntegrityRequired:
			if !req.Bool {
				continue
			}
			checkBool(note, req, rep.IntegrityOK, "the device failed its integrity check")
		}
	}

	switch {
	case failed:
		return Verdict{State: NotCompliant, Findings: findings}
	case unknown:
		return Verdict{State: Unknown, Findings: findings}
	default:
		return Verdict{State: Compliant, Findings: []Finding{}}
	}
}

// checkOff is checkBool turned round: the rule is met when the device says a
// thing is OFF, and unmet when it says it is on.
func checkOff(note func(Finding), req Requirement, got *bool, failure string) {
	switch {
	case got == nil:
		note(found(req, "the device did not say", true))
	case *got:
		note(found(req, failure, false))
	}
}

// parsePatchLevel reads the date Android gives for a security patch, which is
// "2026-10-05" and sometimes only "2026-10".
func parsePatchLevel(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02", "2006-01"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func checkBool(note func(Finding), req Requirement, got *bool, failure string) {
	switch {
	case got == nil:
		note(found(req, "the device did not say", true))
	case !*got:
		note(found(req, failure, false))
	}
}

// ---------------------------------------------------------------- versions

// compareVersions orders dotted numeric versions the way people mean them.
//
// Not string comparison: "15.10" is newer than "15.2", and comparing as text
// gets that backwards, which would mark an up-to-date fleet non-compliant
// the first time a vendor shipped a tenth point release.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := segment(as, i), segment(bs, i)
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// segment treats a missing or unparseable part as zero, so "15.1" and
// "15.1.0" are the same version and a build suffix does not make a device
// look older than it is.
func segment(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n := 0
	for _, c := range parts[i] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(strings.TrimRight(part, "abcdefghijklmnopqrstuvwxyz")); err != nil {
			return false
		}
	}
	return true
}
