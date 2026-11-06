package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"platform/internal/policy"
)

// A runner that answers from a table and writes down what it was asked.
// The table is keyed by the whole command line, so a test asserts the
// exact tool and arguments, and a command that is not in the table is a
// tool that is missing from the machine.
type fakeRun struct {
	out   map[string]string
	fail  map[string]error
	calls []string
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	if err, bad := f.fail[key]; bad {
		return "", err
	}
	out, ok := f.out[key]
	if !ok {
		return "", fmt.Errorf("fake: no such tool or answer for %q", key)
	}
	return out, nil
}

func (f *fakeRun) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// The text below is what the real tools print, so the readers are held to
// the real thing rather than to a shape this build imagined.

const (
	macConsole = statCmd + " -f %Su /dev/console"
	macUID     = idCmd + " -u kemi"
	macIdle    = launchctl + " asuser 501 " + sudo + " -u kemi " + defaults + " -currentHost read com.apple.screensaver idleTime"
	macLock    = launchctl + " asuser 501 " + sudo + " -u kemi " + sysadminctl + " -screenLock status"
	macAuth    = dscl + " . -read /Users/kemi AuthenticationAuthority"
)

func aMac() *fakeRun {
	return &fakeRun{out: map[string]string{
		fdesetup + " status":                 "FileVault is On.\n",
		socketfilterfw + " --getglobalstate": "Firewall is enabled. (State = 1)\n",
		csrutil + " status":                  "System Integrity Protection status: enabled.\n",
		pwpolicy + " -getaccountpolicies": `Getting global account policies
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>policyCategoryPasswordContent</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '.{12,}'</string>
			<key>policyIdentifier</key>
			<string>Password must be at least 12 characters</string>
		</dict>
	</array>
</dict>
</plist>
`,
		macConsole: "kemi\n",
		macUID:     "501\n",
		macAuth:    "AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2> ;Kerberosv5;;kemi@LKDC:SHA1.3F2;LKDC:SHA1.3F2; ;SecureToken;\n",
		macIdle:    "300\n",
		macLock:    "2026-11-05 09:12:01.114 sysadminctl[8121:40212] screenLock delay is 5 seconds\n",
	}}
}

func TestAMacReportsWhatItsOwnToolsSay(t *testing.T) {
	f := aMac()
	r := nativeState(context.Background(), "darwin", f.run)

	want := map[string]any{
		"disk encryption": true, "firewall": true, "jailbroken": false,
		"passcode length": 12, "passcode set": true, "screen lock": 305,
	}
	got := map[string]any{}
	if r.DiskEncryption != nil {
		got["disk encryption"] = *r.DiskEncryption
	}
	if r.Firewall != nil {
		got["firewall"] = *r.Firewall
	}
	if r.Jailbroken != nil {
		got["jailbroken"] = *r.Jailbroken
	}
	if r.PasscodeLength != nil {
		got["passcode length"] = *r.PasscodeLength
	}
	if r.PasscodeSet != nil {
		got["passcode set"] = *r.PasscodeSet
	}
	if r.ScreenLockTimeout != nil {
		got["screen lock"] = *r.ScreenLockTimeout
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("read %v, want %v", got, want)
	}
}

func TestAMacWithEverythingOffSaysSo(t *testing.T) {
	f := aMac()
	f.out[fdesetup+" status"] = "FileVault is Off.\n"
	f.out[socketfilterfw+" --getglobalstate"] = "Firewall is disabled. (State = 0)\n"
	f.out[csrutil+" status"] = "System Integrity Protection status: disabled.\n"
	f.out[pwpolicy+" -getaccountpolicies"] = "Getting global account policies\nNo global account policies.\n"
	f.out[macLock] = "screenLock is off\n"
	r := nativeState(context.Background(), "darwin", f.run)
	if r.DiskEncryption == nil || *r.DiskEncryption || r.Firewall == nil || *r.Firewall ||
		r.Jailbroken == nil || !*r.Jailbroken {
		t.Fatalf("off was not read as off: %+v", r)
	}
	if r.PasscodeLength == nil || *r.PasscodeLength != 0 {
		t.Fatalf("no policy should read as an enforced minimum of zero: %v", r.PasscodeLength)
	}
	if r.ScreenLockTimeout == nil || *r.ScreenLockTimeout != 0 {
		t.Fatalf("a lock that is off should read as never (0): %v", r.ScreenLockTimeout)
	}
}

// Every tool missing: everything unsaid. Not false, not a default.
func TestWhatCannotBeReadStaysUnsaid(t *testing.T) {
	for _, goos := range []string{"darwin", "windows", "linux"} {
		f := &fakeRun{}
		r := nativeState(context.Background(), goos, f.run)
		if r.DiskEncryption != nil || r.Firewall != nil || r.Jailbroken != nil ||
			r.PasscodeSet != nil || r.ScreenLockTimeout != nil {
			t.Fatalf("%s: a missing tool produced an answer: %+v", goos, r)
		}
		// Linux reads the password length from a file this test host may
		// or may not have; the others go through tools.
		if goos != "linux" && r.PasscodeLength != nil {
			t.Fatalf("%s: a missing tool produced a passcode length: %v", goos, *r.PasscodeLength)
		}
	}
}

func TestAMacsScreenLockIsIdleTimePlusDelay(t *testing.T) {
	cases := []struct {
		idle, lock string
		want       int
		known      bool
	}{
		{"300\n", "screenLock delay is 5 seconds\n", 305, true},
		{"300\n", "screenLock delay is immediate\n", 300, true},
		{"600\n", "screenLock delay is 1 minute\n", 660, true},
		// Not set: the system default of twenty minutes is what the
		// machine does.
		{"2026-11-05 The domain/default pair of (com.apple.screensaver, idleTime) does not exist\n",
			"screenLock delay is immediate\n", 1200, true},
		{"0\n", "screenLock delay is immediate\n", 0, true},
		{"300\n", "screenLock is off\n", 0, true},
		{"300\n", "usage: sysadminctl\n", 0, false},
	}
	for _, c := range cases {
		got, known := darwinScreenLock(c.idle, c.lock)
		if got != c.want || known != c.known {
			t.Fatalf("idle %q lock %q: got %d %v, want %d %v", c.idle, c.lock, got, known, c.want, c.known)
		}
	}
}

func aWindowsPC() *fakeRun {
	return &fakeRun{out: map[string]string{
		manageBDE + " -status C:": `BitLocker Drive Encryption: Configuration Tool version 10.0.22621
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

Volume C: [Windows]
[OS Volume]

    Size:                 475.69 GB
    BitLocker Version:    2.0
    Conversion Status:    Fully Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 128
    Protection Status:    Protection On
    Lock Status:          Unlocked
    Identification Field: Unknown
    Key Protectors:
        TPM
        Numerical Password
`,
		netCmd + " accounts": `Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              10
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
`,
		regCmd + " query " + policyKey + " /v InactivityTimeoutSecs": `
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    InactivityTimeoutSecs    REG_DWORD    0x384

`,
		netsh + " advfirewall show allprofiles state": `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Ok.
`,
	}}
}

func TestAWindowsPCReportsWhatItsOwnToolsSay(t *testing.T) {
	f := aWindowsPC()
	r := nativeState(context.Background(), "windows", f.run)
	if r.DiskEncryption == nil || !*r.DiskEncryption {
		t.Fatalf("BitLocker on was not read: %v", r.DiskEncryption)
	}
	if r.PasscodeLength == nil || *r.PasscodeLength != 10 || r.PasscodeSet == nil || !*r.PasscodeSet {
		t.Fatalf("password policy: length %v set %v", r.PasscodeLength, r.PasscodeSet)
	}
	if r.ScreenLockTimeout == nil || *r.ScreenLockTimeout != 900 {
		t.Fatalf("inactivity timeout 0x384 should read as 900: %v", r.ScreenLockTimeout)
	}
	if r.Firewall == nil || !*r.Firewall {
		t.Fatalf("firewall: %v", r.Firewall)
	}
}

func TestAWindowsFirewallOffOnOneProfileIsOff(t *testing.T) {
	f := aWindowsPC()
	f.out[netsh+" advfirewall show allprofiles state"] = strings.Replace(
		f.out[netsh+" advfirewall show allprofiles state"], "State                                 ON\nOk.", "State                                 OFF\nOk.", 1)
	r := nativeState(context.Background(), "windows", f.run)
	if r.Firewall == nil || *r.Firewall {
		t.Fatalf("a public profile that is off should read as off: %v", r.Firewall)
	}
	// And no password policy is an enforced minimum of zero, with the
	// passcode itself unsaid: the policy allows none, which is not the
	// same as knowing there is none.
	f.out[netCmd+" accounts"] = strings.Replace(f.out[netCmd+" accounts"], "length:                              10", "length:                              0", 1)
	r = nativeState(context.Background(), "windows", f.run)
	if r.PasscodeLength == nil || *r.PasscodeLength != 0 || r.PasscodeSet != nil {
		t.Fatalf("length %v set %v", r.PasscodeLength, r.PasscodeSet)
	}
}

// ---------------------------------------------------------------- acting

func finding(kind policy.Kind, num int) policy.Finding {
	return policy.Finding{
		Kind: kind, Num: num, Fix: true,
		// Sentences from the server. If any of this ever reached a
		// command line the test below would see it.
		Rule: "the firewall must be on; rm -rf /", Saw: "$(reboot)", From: "Laptops v1 `id`",
	}
}

func TestAMacPutsTheFirewallOn(t *testing.T) {
	f := aMac()
	f.out[socketfilterfw+" --setglobalstate on"] = "Firewall is enabled. (State = 1)\n"
	n := Native{OS: "darwin", Run: f.run, Dir: t.TempDir()}
	if err := n.Remediate(context.Background(), finding(policy.FirewallRequired, 0)); err != nil {
		t.Fatalf("remediate: %v", err)
	}
	if !f.called(socketfilterfw + " --setglobalstate on") {
		t.Fatalf("the firewall was not switched on: %v", f.calls)
	}
}

func TestOnlyTheCheckedNumberReachesACommandLine(t *testing.T) {
	f := aWindowsPC()
	f.out[netCmd+" accounts /minpwlen:12"] = "The command completed successfully.\n"
	f.out[regCmd+" add "+policyKey+" /v InactivityTimeoutSecs /t REG_DWORD /d 300 /f"] = "The operation completed successfully.\n"
	n := Native{OS: "windows", Run: f.run, Dir: t.TempDir()}
	ctx := context.Background()
	if err := n.Remediate(ctx, finding(policy.PasscodeMinLength, 12)); err != nil {
		t.Fatalf("passcode: %v", err)
	}
	if err := n.Remediate(ctx, finding(policy.ScreenLockTimeoutMax, 300)); err != nil {
		t.Fatalf("lock: %v", err)
	}
	for _, c := range f.calls {
		for _, junk := range []string{"rm -rf", "reboot", "`id`", "Laptops"} {
			if strings.Contains(c, junk) {
				t.Fatalf("a sentence from the server reached a command line: %q", c)
			}
		}
	}
	if !f.called(netCmd+" accounts /minpwlen:12") || !f.called(regCmd+" add "+policyKey+" /v InactivityTimeoutSecs /t REG_DWORD /d 300 /f") {
		t.Fatalf("calls: %v", f.calls)
	}
}

// The control --break-nativebounds lets any number through. This is the
// test that notices.
func TestAnAbsurdNumberIsRefusedBeforeAnythingRuns(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		f := &fakeRun{out: map[string]string{}}
		n := Native{OS: goos, Run: f.run, Dir: t.TempDir()}
		ctx := context.Background()
		for _, c := range []struct {
			kind policy.Kind
			num  int
		}{
			{policy.PasscodeMinLength, 0}, {policy.PasscodeMinLength, -5}, {policy.PasscodeMinLength, 500},
			{policy.ScreenLockTimeoutMax, 0}, {policy.ScreenLockTimeoutMax, 100000},
		} {
			err := n.Remediate(ctx, finding(c.kind, c.num))
			if err == nil || !strings.Contains(err.Error(), "refusing") {
				t.Fatalf("%s %s %d was not refused: %v", goos, c.kind, c.num, err)
			}
		}
		if len(f.calls) != 0 {
			t.Fatalf("%s: something ran for a refused number: %v", goos, f.calls)
		}
	}
}

func TestAMacWritesThePasswordPolicyItHandsToPwpolicy(t *testing.T) {
	f := aMac()
	dir := t.TempDir()
	path := filepath.Join(dir, "passcode-policy.plist")
	f.out[pwpolicy+" -setaccountpolicies "+path] = "Setting global account policies\n"
	n := Native{OS: "darwin", Run: f.run, Dir: dir}
	if err := n.Remediate(context.Background(), finding(policy.PasscodeMinLength, 14)); err != nil {
		t.Fatalf("remediate: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the policy file was not written: %v", err)
	}
	if !strings.Contains(string(b), "matches '.{14,}'") || !strings.Contains(string(b), "<integer>14</integer>") {
		t.Fatalf("policy file:\n%s", b)
	}
	// And the reader reads back what the writer wrote, so the next report
	// says 14.
	if got, known := parsePWPolicyMinLength("Getting global account policies\n" + string(b)); !known || got != 14 {
		t.Fatalf("read back %d %v", got, known)
	}
}

func TestFileVaultIsDeferredToTheNextLoginAndNotAskedTwice(t *testing.T) {
	f := aMac()
	dir := t.TempDir()
	escrow := filepath.Join(dir, "recovery-key")
	f.out[fdesetup+" status"] = "FileVault is Off.\n"
	f.out[fdesetup+" enable -defer "+escrow+" -forceatlogin 0 -dontaskatlogout"] = "Deferred enablement is active.\n"
	n := Native{OS: "darwin", Run: f.run, Dir: dir, RecoveryKeyFile: escrow}
	ctx := context.Background()

	err := n.Remediate(ctx, finding(policy.DiskEncryptionRequired, 0))
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("want deferred, got %v", err)
	}
	if !f.called(fdesetup + " enable -defer " + escrow) {
		t.Fatalf("fdesetup was not asked: %v", f.calls)
	}

	// Next cycle: still off, deferral active. Not asked again.
	f.out[fdesetup+" status"] = "FileVault is Off.\nDeferred enablement appears to be active for user 'kemi'.\n"
	f.calls = nil
	err = n.Remediate(ctx, finding(policy.DiskEncryptionRequired, 0))
	if !errors.Is(err, ErrDeferred) || f.called(fdesetup+" enable") {
		t.Fatalf("asked twice: %v %v", err, f.calls)
	}

	// When the login happens, fdesetup writes the key where we said. The
	// agent's escrow reads it out of the plist.
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>EnabledDate</key><string>2026-11-05 09:30:11 +0100</string>
	<key>HardwareUUID</key><string>5A1B-...</string>
	<key>RecoveryKey</key><string>ABCD-EFGH-IJKL-MNOP-QRST-UVWX</string>
	<key>SerialNumber</key><string>C02XK4YTQ6NV</string>
</dict></plist>
`
	if got := recoveryKeyIn(plist); got != "ABCD-EFGH-IJKL-MNOP-QRST-UVWX" {
		t.Fatalf("read %q from the deferral plist", got)
	}
	// The plist before the login holds no key, and must not be escrowed
	// as if it were one. A bare key is still read as itself.
	if got := recoveryKeyIn(`<?xml version="1.0"?><plist version="1.0"><dict><key>EnabledDate</key><string>x</string></dict></plist>`); got != "" {
		t.Fatalf("a plist with no key was read as %q", got)
	}
	if got := recoveryKeyIn("  123456-654321-111111-222222-333333-444444-555555-666666\n"); !strings.HasPrefix(got, "123456-") {
		t.Fatalf("a bare key was read as %q", got)
	}
}

func TestAWindowsPCTurnsBitLockerOnAndLeavesTheKeyForEscrow(t *testing.T) {
	f := aWindowsPC()
	dir := t.TempDir()
	escrow := filepath.Join(dir, "recovery-key")
	f.out[manageBDE+" -status C:"] = strings.NewReplacer(
		"Fully Encrypted", "Fully Decrypted", "Protection On", "Protection Off").Replace(f.out[manageBDE+" -status C:"])
	f.out[manageBDE+" -on C: -RecoveryPassword -SkipHardwareTest"] = "Encryption is now in progress.\n"
	f.out[manageBDE+" -protectors -get C: -Type RecoveryPassword"] = `Volume C: [Windows]
All Key Protectors

    Numerical Password:
      ID: {7F2E4C1A-0000-4F1B-9B8E-1234567890AB}
      Password:
        123456-654321-111111-222222-333333-444444-555555-666666
`
	n := Native{OS: "windows", Run: f.run, Dir: dir, RecoveryKeyFile: escrow}
	err := n.Remediate(context.Background(), finding(policy.DiskEncryptionRequired, 0))
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("want deferred, got %v", err)
	}
	b, rerr := os.ReadFile(escrow)
	if rerr != nil || strings.TrimSpace(string(b)) != "123456-654321-111111-222222-333333-444444-555555-666666" {
		t.Fatalf("the recovery password was not left for escrow: %q %v", b, rerr)
	}

	// Mid-encryption on the next cycle: not asked again.
	f.out[manageBDE+" -status C:"] = strings.Replace(f.out[manageBDE+" -status C:"], "Fully Decrypted", "Encryption in Progress", 1)
	f.calls = nil
	if err := n.Remediate(context.Background(), finding(policy.DiskEncryptionRequired, 0)); !errors.Is(err, ErrDeferred) || f.called(manageBDE+" -on") {
		t.Fatalf("asked twice: %v %v", err, f.calls)
	}
}

func TestWhatAMachineCannotPutRightIsSaidByName(t *testing.T) {
	f := &fakeRun{out: map[string]string{}}
	n := Native{OS: "darwin", Run: f.run, Dir: t.TempDir()}
	for _, kind := range []policy.Kind{policy.PasscodeRequired, policy.OSVersionMin, policy.JailbreakBlocked} {
		err := n.Remediate(context.Background(), finding(kind, 0))
		if err == nil || errors.Is(err, ErrDeferred) {
			t.Fatalf("%s was 'put right': %v", kind, err)
		}
	}
	// Linux: the firewall yes, encryption no.
	n = Native{OS: "linux", Run: f.run, Dir: t.TempDir()}
	if err := n.Remediate(context.Background(), finding(policy.DiskEncryptionRequired, 0)); err == nil ||
		!strings.Contains(err.Error(), "reinstall") {
		t.Fatalf("linux encryption: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("something ran: %v", f.calls)
	}
}

func TestALockIsNativeAndAWipeStillNeedsAHelper(t *testing.T) {
	f := aMac()
	f.out[launchctl+" asuser 501 "+sudo+" -u kemi "+cgsession+" -suspend"] = ""
	n := Native{OS: "darwin", Run: f.run}
	ctx := context.Background()
	if err := n.Do(ctx, "lock"); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if !f.called(launchctl + " asuser 501 " + sudo + " -u kemi " + cgsession + " -suspend") {
		t.Fatalf("the console session was not suspended: %v", f.calls)
	}

	// Nobody at the keyboard: no session to lock, said rather than faked.
	f.out[macConsole] = "root\n"
	if err := n.Do(ctx, "lock"); err == nil || !strings.Contains(err.Error(), "nobody is logged in") {
		t.Fatalf("locked an empty console: %v", err)
	}

	// A wipe goes to the fallback, and with none it is refused by name.
	err := n.Do(ctx, "wipe_full")
	if err == nil || !strings.Contains(err.Error(), "helper") {
		t.Fatalf("a wipe without a helper: %v", err)
	}
	rec := &RecordingEnforcer{}
	n.Fallback = rec
	if err := n.Do(ctx, "wipe_full"); err != nil || len(rec.Done) != 1 || rec.Done[0] != "wipe_full" {
		t.Fatalf("the fallback was not asked: %v %v", err, rec.Done)
	}
	if f.called(fdesetup+" ") && strings.Contains(strings.Join(f.calls, " "), "wipe") {
		t.Fatalf("a native tool was asked to wipe: %v", f.calls)
	}
}

func TestAWindowsLockDisconnectsTheConsoleSession(t *testing.T) {
	f := aWindowsPC()
	f.out[querySess+" session"] = ` SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           kemi                      1  Active
 rdp-tcp                                 65536  Listen
`
	f.out[tsdiscon+" 1"] = ""
	n := Native{OS: "windows", Run: f.run}
	if err := n.Do(context.Background(), "lock"); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if !f.called(tsdiscon + " 1") {
		t.Fatalf("session 1 was not disconnected: %v", f.calls)
	}
}
