package policy

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------- the remediate key

func TestAPolicyMayAskTheDeviceToPutFailuresRight(t *testing.T) {
	_, set, err := ParseBody("Laptops v1", []byte(`{"firewall_required": true, "remediate": true}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !set.Remediate {
		t.Fatal("remediate: true was not read")
	}
	if set.OnFailure != FailNone {
		t.Fatalf("on_failure defaulted to %q", set.OnFailure)
	}

	// Off unless said. A tenant that only wants to observe must never
	// find its fleet's settings changed because of a default.
	_, set, err = ParseBody("Laptops v1", []byte(`{"firewall_required": true}`))
	if err != nil || set.Remediate {
		t.Fatalf("remediate defaulted on: %+v %v", set, err)
	}

	// And it takes true or false, nothing else.
	if _, _, err := ParseBody("Laptops v1", []byte(`{"firewall_required": true, "remediate": "yes"}`)); err == nil ||
		!strings.Contains(err.Error(), "remediate takes true or false") {
		t.Fatalf("a bad remediate value was accepted: %v", err)
	}
}

// The mark travels with the requirement that wins the merge. A policy that
// did not ask for remediation must never have its number imposed on a
// device by another policy that did.
func TestTheFixMarkTravelsWithTheWinningRequirement(t *testing.T) {
	asks := Policy{Name: "Strict", Version: 1, Remediate: true}
	quiet := Policy{Name: "Quiet", Version: 1}

	asks.Rules = rules(t, asks.Label(), `{"passcode_min_length": 12, "firewall_required": true}`)
	quiet.Rules = rules(t, quiet.Label(), `{"passcode_min_length": 8}`)
	got := Merge(quiet.rulesToMerge(), asks.rulesToMerge())
	if r := got[PasscodeMinLength]; r.Num != 12 || !r.Fix {
		t.Fatalf("the remediating policy's longer passcode should win and carry the mark: %+v", r)
	}
	if r := got[FirewallRequired]; !r.Fix {
		t.Fatalf("a rule only the remediating policy asks for is not marked: %+v", r)
	}

	// The other way round: the quiet policy's stricter number wins, and the
	// device is NOT asked to impose it.
	asks.Rules = rules(t, asks.Label(), `{"passcode_min_length": 8}`)
	quiet.Rules = rules(t, quiet.Label(), `{"passcode_min_length": 12}`)
	got = Merge(asks.rulesToMerge(), quiet.rulesToMerge())
	if r := got[PasscodeMinLength]; r.Num != 12 || r.Fix {
		t.Fatalf("the quiet policy's number won but the device was asked to impose it: %+v", r)
	}

	// Equal numbers: the value is the same whichever asked, so either
	// asking is enough.
	quiet.Rules = rules(t, quiet.Label(), `{"passcode_min_length": 8}`)
	got = Merge(quiet.rulesToMerge(), asks.rulesToMerge())
	if r := got[PasscodeMinLength]; r.Num != 8 || !r.Fix {
		t.Fatalf("equal values: %+v", r)
	}
}

func TestAFindingCarriesTheNumberAndTheMark(t *testing.T) {
	p := Policy{Name: "Strict", Version: 1, Remediate: true}
	p.Rules = rules(t, p.Label(), `{"passcode_min_length": 12, "screen_lock_timeout_max": 300, "firewall_required": true}`)
	r := Merge(p.rulesToMerge())

	got := Evaluate(r, Report{PasscodeLength: i(6), ScreenLockTimeout: i(900)}, now, now)
	if got.State != NotCompliant {
		t.Fatalf("got %s", got.State)
	}
	byKind := map[Kind]Finding{}
	for _, f := range got.Findings {
		byKind[f.Kind] = f
	}
	if f := byKind[PasscodeMinLength]; f.Num != 12 || !f.Fix || f.Unknown {
		t.Fatalf("passcode finding: %+v", f)
	}
	if f := byKind[ScreenLockTimeoutMax]; f.Num != 300 || !f.Fix {
		t.Fatalf("lock finding: %+v", f)
	}
	// The firewall was not reported. A setting the agent could not read is
	// not one it should change, so the mark is withheld.
	if f := byKind[FirewallRequired]; !f.Unknown || f.Fix {
		t.Fatalf("an unknown finding was marked for the device to act on: %+v", f)
	}
}

// The control --break-remediate marks every failure regardless of what the
// policy said. This is the test that notices.
func TestAPolicyThatDoesNotAskLeavesTheDeviceAlone(t *testing.T) {
	p := Policy{Name: "Quiet", Version: 1}
	p.Rules = rules(t, p.Label(), `{"passcode_min_length": 12, "firewall_required": true, "disk_encryption_required": true}`)
	got := Evaluate(Merge(p.rulesToMerge()), Report{
		PasscodeLength: i(6), Firewall: b(false), DiskEncryption: b(false),
	}, now, now)
	if got.State != NotCompliant || len(got.Findings) != 3 {
		t.Fatalf("got %s with %+v", got.State, got.Findings)
	}
	for _, f := range got.Findings {
		if f.Fix {
			t.Fatalf("a policy that never asked for remediation marked a finding for the device to act on: %+v", f)
		}
	}
}

// Zero is "never locks". It is the convention every platform uses for a
// lock that is switched off, and it has to fail rather than pass as
// "within 0 seconds".
func TestAScreenThatNeverLocksFails(t *testing.T) {
	r := Merge(rules(t, "Baseline v1", `{"screen_lock_timeout_max": 300}`))
	got := Evaluate(r, Report{ScreenLockTimeout: i(0)}, now, now)
	if got.State != NotCompliant || len(got.Findings) != 1 || got.Findings[0].Saw != "the screen never locks" {
		t.Fatalf("got %s with %+v", got.State, got.Findings)
	}
}
