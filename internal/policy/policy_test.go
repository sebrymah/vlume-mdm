package policy

import (
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func b(v bool) *bool { return &v }
func i(v int) *int   { return &v }

func rules(t *testing.T, from, body string) Rules {
	t.Helper()
	r, err := Parse(from, []byte(body))
	if err != nil {
		t.Fatalf("parse %s: %v", from, err)
	}
	return r
}

// ---------------------------------------------------------------- parsing

// The most important parsing decision. A policy saying passcode_minimum_length
// because someone typed it from memory would otherwise save, display as a
// policy, and require nothing at all. The lie only surfaces during an
// incident.
func TestAnUnknownRuleNameIsRefusedRatherThanIgnored(t *testing.T) {
	for _, body := range []string{
		`{"passcode_minimum_length": 8}`,
		`{"require_passcode": true}`,
		`{"passcode_required": true, "encrypt_disk": true}`,
		`{"PASSCODE_REQUIRED": true}`,
	} {
		_, err := Parse("Baseline v1", []byte(body))
		if !errors.Is(err, ErrUnknownRule) {
			t.Fatalf("%s: got %v, want ErrUnknownRule", body, err)
		}
		// The message has to name the rules that do exist, or the person who
		// typed it has nothing to go on.
		if !strings.Contains(err.Error(), "passcode_min_length") {
			t.Fatalf("unhelpful message: %v", err)
		}
	}
}

func TestAValueOfTheWrongShapeIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"passcode_required": "yes"}`,
		`{"passcode_min_length": "eight"}`,
		`{"passcode_min_length": 0}`,
		`{"passcode_min_length": -4}`,
		`{"screen_lock_timeout_max": true}`,
		`{"os_version_min": 15}`,
		`{"os_version_min": "sequoia"}`,
	} {
		if _, err := Parse("Baseline v1", []byte(body)); !errors.Is(err, ErrBadValue) {
			t.Fatalf("%s: got %v, want ErrBadValue", body, err)
		}
	}
}

func TestAnEmptyPolicyParsesToNoRequirements(t *testing.T) {
	for _, body := range []string{"", "{}"} {
		r, err := Parse("Empty v1", []byte(body))
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if len(r) != 0 {
			t.Fatalf("%q: got %d rules", body, len(r))
		}
	}
}

func TestEveryRuleInTheCatalogueParses(t *testing.T) {
	// If a kind is added to the catalogue without a sample here, this fails,
	// which is the reminder to think about its value type.
	samples := map[Kind]string{
		PasscodeRequired:       `{"passcode_required": true}`,
		PasscodeMinLength:      `{"passcode_min_length": 8}`,
		DiskEncryptionRequired: `{"disk_encryption_required": true}`,
		ScreenLockTimeoutMax:   `{"screen_lock_timeout_max": 300}`,
		OSVersionMin:           `{"os_version_min": "15.1"}`,
		FirewallRequired:       `{"firewall_required": true}`,
		JailbreakBlocked:       `{"jailbreak_blocked": true}`,
		SecurityPatchMaxAge:    `{"security_patch_max_age_days": 30}`,
		DebuggingBlocked:       `{"debugging_blocked": true}`,
		UnknownSourcesBlocked:  `{"unknown_sources_blocked": true}`,
		PlayProtectRequired:    `{"play_protect_required": true}`,
		IntegrityRequired:      `{"integrity_required": true}`,
	}
	for _, k := range Kinds() {
		body, ok := samples[k]
		if !ok {
			t.Fatalf("%s is in the catalogue with no sample in this test", k)
		}
		r, err := Parse("x", []byte(body))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if _, got := r[k]; !got {
			t.Fatalf("%s did not parse into its own kind", k)
		}
		if r[k].Says() == "" || r[k].Says() == string(k) {
			t.Fatalf("%s has no sentence to show a person", k)
		}
	}
}

// ---------------------------------------------------------------- merging

// The classic MDM failure: an administrator assigns a looser policy to a
// group and silently relaxes a stricter one that was already there.
func TestALooserPolicyCannotRelaxAStricterOne(t *testing.T) {
	strict := rules(t, "Strict v1", `{"passcode_min_length": 12,
		"screen_lock_timeout_max": 60, "disk_encryption_required": true,
		"os_version_min": "15.2"}`)
	loose := rules(t, "Loose v1", `{"passcode_min_length": 4,
		"screen_lock_timeout_max": 900, "disk_encryption_required": false,
		"os_version_min": "13.0"}`)

	got := Merge(strict, loose)
	if got[PasscodeMinLength].Num != 12 {
		t.Fatalf("passcode length relaxed to %d", got[PasscodeMinLength].Num)
	}
	if got[ScreenLockTimeoutMax].Num != 60 {
		t.Fatalf("lock timeout relaxed to %d", got[ScreenLockTimeoutMax].Num)
	}
	if !got[DiskEncryptionRequired].Bool {
		t.Fatal("disk encryption was switched off by a looser policy")
	}
	if got[OSVersionMin].Text != "15.2" {
		t.Fatalf("os version relaxed to %s", got[OSVersionMin].Text)
	}
}

// The property the strict merge buys: the same device with the same policies
// always gets the same requirements, whatever order the rows came back in.
func TestTheMergeDoesNotDependOnOrder(t *testing.T) {
	sets := []Rules{
		rules(t, "A v1", `{"passcode_min_length": 6, "firewall_required": true}`),
		rules(t, "B v2", `{"passcode_min_length": 10, "screen_lock_timeout_max": 120}`),
		rules(t, "C v1", `{"screen_lock_timeout_max": 60, "os_version_min": "14.0"}`),
		rules(t, "D v3", `{"os_version_min": "15.1", "disk_encryption_required": true}`),
		rules(t, "E v1", `{"passcode_min_length": 8, "firewall_required": false}`),
	}
	want := Merge(sets...)

	rng := rand.New(rand.NewSource(1))
	for run := 0; run < 200; run++ {
		shuffled := append([]Rules(nil), sets...)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})
		got := Merge(shuffled...)
		if len(got) != len(want) {
			t.Fatalf("run %d: %d rules, want %d", run, len(got), len(want))
		}
		for kind, w := range want {
			g := got[kind]
			if g.Bool != w.Bool || g.Num != w.Num || g.Text != w.Text {
				t.Fatalf("run %d: %s is %+v, want %+v", run, kind, g, w)
			}
		}
	}
}

func TestMergingNothingGivesNothing(t *testing.T) {
	if got := Merge(); len(got) != 0 {
		t.Fatalf("got %d rules from no policies", len(got))
	}
	if got := Merge(Rules{}, Rules{}); len(got) != 0 {
		t.Fatalf("got %d rules from two empty policies", len(got))
	}
}

// A requirement has to carry which policy asked for it, or the finding an
// administrator reads cannot be acted on.
func TestARequirementRemembersWhichPolicyAskedForIt(t *testing.T) {
	got := Merge(
		rules(t, "Baseline v1", `{"passcode_min_length": 6}`),
		rules(t, "Finance v2", `{"passcode_min_length": 14}`),
	)
	if got[PasscodeMinLength].From != "Finance v2" {
		t.Fatalf("the winning rule came from %q", got[PasscodeMinLength].From)
	}
	// When two policies ask for the same thing, both are named: an
	// administrator retiring one needs to know the other still requires it.
	both := Merge(
		rules(t, "Baseline v1", `{"disk_encryption_required": true}`),
		rules(t, "Finance v2", `{"disk_encryption_required": true}`),
	)
	from := both[DiskEncryptionRequired].From
	if !strings.Contains(from, "Baseline v1") || !strings.Contains(from, "Finance v2") {
		t.Fatalf("only %q was credited", from)
	}
}

// A rule set to false is the absence of a requirement, not a requirement.
func TestDescribeLeavesOutTheRulesThatAskForNothing(t *testing.T) {
	got := Merge(rules(t, "A v1",
		`{"passcode_required": false, "firewall_required": true}`)).Describe()
	if len(got) != 1 || !strings.Contains(got[0], "firewall") {
		t.Fatalf("got %v", got)
	}
}

// ---------------------------------------------------------------- versions

// String comparison gets this backwards, which would mark an up-to-date
// fleet non-compliant the first time a vendor shipped a tenth point release.
func TestVersionsCompareNumericallyNotAlphabetically(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"15.10", "15.2", 1},
		{"15.2", "15.10", -1},
		{"15.1", "15.1.0", 0},
		{"15.1.1", "15.1", 1},
		{"9.0", "10.0", -1},
		{"14", "14.0.0", 0},
		{"15.1.2", "15.1.2", 0},
		{"26.0", "15.9", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Fatalf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestTheStricterVersionWinsTheMerge(t *testing.T) {
	got := Merge(
		rules(t, "A v1", `{"os_version_min": "15.2"}`),
		rules(t, "B v1", `{"os_version_min": "15.10"}`),
	)
	if got[OSVersionMin].Text != "15.10" {
		t.Fatalf("got %s, want 15.10", got[OSVersionMin].Text)
	}
}

// --------------------------------------------------------------- evaluating

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func TestADeviceThatMeetsEverythingIsCompliant(t *testing.T) {
	r := Merge(rules(t, "Baseline v1", `{"passcode_required": true,
		"passcode_min_length": 8, "disk_encryption_required": true,
		"screen_lock_timeout_max": 300, "os_version_min": "15.0",
		"firewall_required": true, "jailbreak_blocked": true}`))

	got := Evaluate(r, Report{
		PasscodeSet: b(true), PasscodeLength: i(12), DiskEncryption: b(true),
		ScreenLockTimeout: i(60), OSVersion: "15.2", Firewall: b(true),
		Jailbroken: b(false),
	}, now, now)

	if got.State != Compliant {
		t.Fatalf("got %s with findings %+v", got.State, got.Findings)
	}
	if len(got.Findings) != 0 {
		t.Fatalf("a compliant device has findings: %+v", got.Findings)
	}
}

// The rule that stops an agent bug from reading as a pass.
func TestNotSayingIsNeverAPass(t *testing.T) {
	r := Merge(rules(t, "Baseline v1", `{"disk_encryption_required": true}`))

	got := Evaluate(r, Report{}, now, now)
	if got.State != Unknown {
		t.Fatalf("a silent device is %s, want state_unknown", got.State)
	}
	if len(got.Findings) != 1 || !got.Findings[0].Unknown {
		t.Fatalf("got %+v", got.Findings)
	}
	// And a device that says false is a different thing: it failed, it did
	// not fail to answer. The two need different words in front of a person.
	got = Evaluate(r, Report{DiskEncryption: b(false)}, now, now)
	if got.State != NotCompliant {
		t.Fatalf("an unencrypted device is %s", got.State)
	}
	if got.Findings[0].Unknown {
		t.Fatal("a reported failure was recorded as not knowing")
	}
}

// A device we already know is failing is not "unknown" because some other
// field was missing. We know enough to act.
func TestAFailureOutranksAMissingField(t *testing.T) {
	r := Merge(rules(t, "Baseline v1",
		`{"disk_encryption_required": true, "firewall_required": true}`))

	got := Evaluate(r, Report{DiskEncryption: b(false)}, now, now)
	if got.State != NotCompliant {
		t.Fatalf("got %s, want not_compliant", got.State)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("both the failure and the silence should be reported: %+v", got.Findings)
	}
}

func TestAStaleReportIsNotEvidenceOfAnything(t *testing.T) {
	r := Merge(rules(t, "Baseline v1", `{"disk_encryption_required": true}`))
	perfect := Report{DiskEncryption: b(true)}

	fresh := Evaluate(r, perfect, now.Add(-MaxReportAge+time.Hour), now)
	if fresh.State != Compliant {
		t.Fatalf("a report inside the window is %s", fresh.State)
	}
	stale := Evaluate(r, perfect, now.Add(-MaxReportAge-time.Hour), now)
	if stale.State != Unknown {
		t.Fatalf("a report older than the window is %s, want state_unknown", stale.State)
	}
	if len(stale.Findings) != 1 || !stale.Findings[0].Unknown {
		t.Fatalf("got %+v", stale.Findings)
	}
}

func TestNoPolicyMeansNothingToFail(t *testing.T) {
	got := Evaluate(Rules{}, Report{}, now, now)
	if got.State != Compliant {
		t.Fatalf("got %s with no rules at all", got.State)
	}
}

func TestEachRuleCatchesItsOwnFailure(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		report Report
		saw    string
	}{
		{"no passcode", `{"passcode_required": true}`,
			Report{PasscodeSet: b(false)}, "no passcode is set"},
		{"passcode too short", `{"passcode_min_length": 8}`,
			Report{PasscodeLength: i(4)}, "4 characters"},
		{"disk not encrypted", `{"disk_encryption_required": true}`,
			Report{DiskEncryption: b(false)}, "not encrypted"},
		{"locks too late", `{"screen_lock_timeout_max": 300}`,
			Report{ScreenLockTimeout: i(900)}, "900 seconds"},
		{"os too old", `{"os_version_min": "15.0"}`,
			Report{OSVersion: "14.6"}, "14.6"},
		{"firewall off", `{"firewall_required": true}`,
			Report{Firewall: b(false)}, "firewall is off"},
		{"jailbroken", `{"jailbreak_blocked": true}`,
			Report{Jailbroken: b(true)}, "jailbroken"},
	}
	for _, c := range cases {
		got := Evaluate(Merge(rules(t, "Baseline v1", c.policy)), c.report, now, now)
		if got.State != NotCompliant {
			t.Fatalf("%s: got %s", c.name, got.State)
		}
		if len(got.Findings) != 1 {
			t.Fatalf("%s: got %d findings", c.name, len(got.Findings))
		}
		if !strings.Contains(got.Findings[0].Saw, c.saw) {
			t.Fatalf("%s: the finding says %q, expected it to mention %q",
				c.name, got.Findings[0].Saw, c.saw)
		}
		if got.Findings[0].From != "Baseline v1" {
			t.Fatalf("%s: finding came from %q", c.name, got.Findings[0].From)
		}
	}
}

func TestEachRuleAlsoPassesWhenItIsMet(t *testing.T) {
	cases := []struct {
		policy string
		report Report
	}{
		{`{"passcode_required": true}`, Report{PasscodeSet: b(true)}},
		{`{"passcode_min_length": 8}`, Report{PasscodeLength: i(8)}},
		{`{"disk_encryption_required": true}`, Report{DiskEncryption: b(true)}},
		{`{"screen_lock_timeout_max": 300}`, Report{ScreenLockTimeout: i(300)}},
		{`{"os_version_min": "15.0"}`, Report{OSVersion: "15.0"}},
		{`{"firewall_required": true}`, Report{Firewall: b(true)}},
		{`{"jailbreak_blocked": true}`, Report{Jailbroken: b(false)}},
	}
	for _, c := range cases {
		got := Evaluate(Merge(rules(t, "Baseline v1", c.policy)), c.report, now, now)
		if got.State != Compliant {
			t.Fatalf("%s with %+v: got %s (%+v)", c.policy, c.report, got.State, got.Findings)
		}
	}
	// The boundaries above are deliberate: exactly the minimum length and
	// exactly the maximum timeout both pass. An off-by-one here would fail
	// a correctly configured fleet.
}

// A rule set to false must not be evaluated as a requirement at all.
func TestARuleSetToFalseRequiresNothing(t *testing.T) {
	r := Merge(rules(t, "A v1", `{"passcode_required": false}`))
	got := Evaluate(r, Report{}, now, now)
	if got.State != Compliant {
		t.Fatalf("got %s, want compliant: %+v", got.State, got.Findings)
	}
}

// ---------------------------------------------------------------- the scope

func TestScopeMatchesTheDevicesItNames(t *testing.T) {
	cases := []struct {
		scope     Scope
		osFamily  string
		ownership string
		want      bool
	}{
		{Scope{}, "macos", "company", true},
		{Scope{}, "windows", "personal", true},
		{Scope{OSFamily: "macos"}, "macos", "company", true},
		{Scope{OSFamily: "macos"}, "windows", "company", false},
		{Scope{Ownership: "personal"}, "macos", "personal", true},
		{Scope{Ownership: "personal"}, "macos", "company", false},
		{Scope{OSFamily: "ios", Ownership: "personal"}, "ios", "personal", true},
		{Scope{OSFamily: "ios", Ownership: "personal"}, "ios", "company", false},
		{Scope{OSFamily: "ios", Ownership: "personal"}, "macos", "personal", false},
	}
	for _, c := range cases {
		if got := c.scope.Matches(c.osFamily, c.ownership); got != c.want {
			t.Fatalf("%+v against %s/%s: got %v", c.scope, c.osFamily, c.ownership, got)
		}
	}
}

func TestScopeSaysWhoItIsForInWords(t *testing.T) {
	for scope, want := range map[Scope]string{
		{}:                                      "every device",
		{OSFamily: "macos"}:                     "every macos device",
		{Ownership: "personal"}:                 "every personal-owned device",
		{OSFamily: "ios", Ownership: "company"}: "every company-owned ios device",
	} {
		if got := scope.Describe(); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// ---------------------------------------------- what an Android phone says

// The security patch window is judged in whole days from the date Android
// reports: exactly as old as the limit passes, a day older fails, a device that
// says nothing is unknown, and a date nobody can read is not a pass.
func TestTheSecurityPatchWindowIsJudgedInWholeDays(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	r := rules(t, "Window", `{"security_patch_max_age_days": 30}`)
	cases := []struct {
		level string
		state string
	}{
		{"2026-10-09", Compliant},    // 30 days old: the limit itself passes
		{"2026-10-08", NotCompliant}, // 31 days
		{"2026-11-08", Compliant},
		{"2026-10", NotCompliant}, // a month only reads as its first day: 38 days
		{"", Unknown},
		{"last Tuesday", Unknown},
	}
	for _, c := range cases {
		v := Evaluate(r, Report{PatchLevel: c.level}, now, now)
		if v.State != c.state {
			t.Errorf("patch level %q: %s, want %s (%v)", c.level, v.State, c.state, v.Findings)
		}
	}
	// And a looser policy cannot relax a stricter one.
	merged := Merge(rules(t, "A", `{"security_patch_max_age_days": 30}`), rules(t, "B", `{"security_patch_max_age_days": 7}`))
	if merged[SecurityPatchMaxAge].Num != 7 {
		t.Fatalf("the merge kept %d days", merged[SecurityPatchMaxAge].Num)
	}
}

// Debugging and unknown sources are rules about things being OFF, so the sense
// is turned round: the device passes when it says off, fails when it says on,
// and is unknown when it says nothing.
func TestRulesAboutThingsBeingOffAreJudgedTheRightWayRound(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		body string
		set  func(*bool) Report
	}{
		{`{"debugging_blocked": true}`, func(v *bool) Report { return Report{DebuggingEnabled: v} }},
		{`{"unknown_sources_blocked": true}`, func(v *bool) Report { return Report{UnknownSourcesEnabled: v} }},
	} {
		r := rules(t, "Off", tc.body)
		for _, c := range []struct {
			v     *bool
			state string
		}{{b(false), Compliant}, {b(true), NotCompliant}, {nil, Unknown}} {
			if got := Evaluate(r, tc.set(c.v), now, now).State; got != c.state {
				t.Errorf("%s with %v: %s, want %s", tc.body, c.v, got, c.state)
			}
		}
	}
}

// Play Protect and the integrity check are rules about things being ON.
func TestPlayProtectAndIntegrityAreJudgedLikeAnyRequiredSwitch(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		body string
		set  func(*bool) Report
	}{
		{`{"play_protect_required": true}`, func(v *bool) Report { return Report{PlayProtectEnabled: v} }},
		{`{"integrity_required": true}`, func(v *bool) Report { return Report{IntegrityOK: v} }},
	} {
		r := rules(t, "On", tc.body)
		for _, c := range []struct {
			v     *bool
			state string
		}{{b(true), Compliant}, {b(false), NotCompliant}, {nil, Unknown}} {
			if got := Evaluate(r, tc.set(c.v), now, now).State; got != c.state {
				t.Errorf("%s with %v: %s, want %s", tc.body, c.v, got, c.state)
			}
		}
	}
	// A rule set to false asks for nothing.
	if got := Evaluate(rules(t, "x", `{"debugging_blocked": false, "play_protect_required": false}`), Report{}, now, now).State; got != Compliant {
		t.Fatalf("a rule set to false was held against the device: %s", got)
	}
}

// A failure outranks a gap: a phone with debugging on and no patch date is
// not compliant and not unknown, because we already know enough to act.
func TestAKnownFailureOutranksAMissingFieldOnAPhone(t *testing.T) {
	now := time.Now()
	r := rules(t, "Both", `{"debugging_blocked": true, "security_patch_max_age_days": 30}`)
	if got := Evaluate(r, Report{DebuggingEnabled: b(true)}, now, now).State; got != NotCompliant {
		t.Fatalf("got %s", got)
	}
}

// A patch dated in the future is not newer than any limit, it is not believable.
// It is unknown, which is never a pass; a day or two ahead is clock skew and
// is let through.
func TestAFuturePatchDateIsNotAPass(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	r := rules(t, "Window", `{"security_patch_max_age_days": 30}`)
	for _, c := range []struct {
		level, state string
	}{
		{"2030-01-01", Unknown},
		{"2026-12-01", Unknown},
		{"2026-11-09", Compliant}, // tomorrow: clock skew
		{"2026-11-10", Compliant}, // within two days
		{"2026-11-12", Unknown},   // four days ahead
	} {
		if got := Evaluate(r, Report{PatchLevel: c.level}, now, now).State; got != c.state {
			t.Errorf("patch level %s: %s, want %s", c.level, got, c.state)
		}
	}
}
