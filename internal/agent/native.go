package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"platform/internal/policy"
)

// This file is the one place in the agent that knows what a Mac, a Windows
// PC or a Linux machine is: which of the platform's own tools say whether
// the disk is encrypted or the firewall is on, and which of them put it
// right. Everything above it deals in policy.Report and policy.Finding.
//
// Two rules hold throughout.
//
// Nothing the server sends reaches a command line except a NUMBER, and
// that number is checked against a range first. The findings carry
// sentences (the rule, what the device said) and those are never used
// here: the only values that become arguments are the passcode length and
// the lock timeout, as integers, bounded.
//
// Every reader is a pure function over the tool's text, so it can be held
// to on any platform with the text a real machine produced. The Runner is
// what makes that possible: the real one runs the tool, the test one
// answers from a table.

// Runner runs one program and returns what it printed, standard output and
// standard error together.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

func execRunner(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// ------------------------------------------------------------------ reading

// nativeState is what the platform's own tools say about the settings the
// policy engine judges. Every field is nil until a tool is found, runs,
// and says something this build recognises; the server reads nil as "did
// not say" and never as a pass.
func nativeState(ctx context.Context, goos string, run Runner) policy.Report {
	switch goos {
	case "darwin":
		return darwinState(ctx, run)
	case "windows":
		return windowsState(ctx, run)
	case "linux":
		return linuxState(ctx, run)
	}
	return policy.Report{}
}

// The macOS tools. Paths in full: the agent runs from launchd with no
// PATH worth trusting, and a relative name would be looked up in it.
const (
	fdesetup       = "/usr/bin/fdesetup"
	socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	csrutil        = "/usr/bin/csrutil"
	pwpolicy       = "/usr/bin/pwpolicy"
	dscl           = "/usr/bin/dscl"
	defaults       = "/usr/bin/defaults"
	sysadminctl    = "/usr/sbin/sysadminctl"
	launchctl      = "/bin/launchctl"
	sudo           = "/usr/bin/sudo"
	statCmd        = "/usr/bin/stat"
	idCmd          = "/usr/bin/id"
	cgsession      = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"
)

func darwinState(ctx context.Context, run Runner) policy.Report {
	var r policy.Report
	if out, err := run(ctx, fdesetup, "status"); err == nil {
		if on, _, known := parseFDESetup(out); known {
			r.DiskEncryption = &on
		}
	}
	if out, err := run(ctx, socketfilterfw, "--getglobalstate"); err == nil {
		if on, known := parseSocketFilterFW(out); known {
			r.Firewall = &on
		}
	}
	if out, err := run(ctx, csrutil, "status"); err == nil {
		if enabled, known := parseCSRUtil(out); known {
			// A Mac with System Integrity Protection switched off is the
			// nearest thing to a rooted phone: the platform's own
			// safeguards are down.
			off := !enabled
			r.Jailbroken = &off
		}
	}
	if out, err := run(ctx, pwpolicy, "-getaccountpolicies"); err == nil {
		if n, known := parsePWPolicyMinLength(out); known {
			r.PasscodeLength = &n
		}
	}
	user, uid := consoleUser(ctx, run)
	if user != "" {
		if out, err := run(ctx, dscl, ".", "-read", "/Users/"+user, "AuthenticationAuthority"); err == nil {
			// Only ever "yes". A record that cannot be read, or has no
			// password hash, stays unsaid rather than becoming "no".
			if strings.Contains(out, ";ShadowHash;") {
				set := true
				r.PasscodeSet = &set
			}
		}
		// The screen lock is the person's setting, not the machine's, so
		// it is read as them.
		idle, _ := asUser(ctx, run, user, uid, defaults, "-currentHost", "read", "com.apple.screensaver", "idleTime")
		lock, err := asUser(ctx, run, user, uid, sysadminctl, "-screenLock", "status")
		if err == nil {
			if t, known := darwinScreenLock(idle, lock); known {
				r.ScreenLockTimeout = &t
			}
		}
	}
	return r
}

// parseFDESetup reads `fdesetup status`: whether FileVault is on, and
// whether a deferred enablement is waiting for the next login.
func parseFDESetup(out string) (on, deferred, known bool) {
	switch {
	case strings.Contains(out, "FileVault is On"):
		on = true
	case strings.Contains(out, "FileVault is Off"):
		on = false
	default:
		return false, false, false
	}
	deferred = strings.Contains(out, "Deferred enablement appears to be active")
	return on, deferred, true
}

// parseSocketFilterFW reads `socketfilterfw --getglobalstate`, which says
// "Firewall is enabled. (State = 1)" or "Firewall is disabled. (State = 0)".
func parseSocketFilterFW(out string) (on, known bool) {
	switch {
	case strings.Contains(out, "(State = 1)") || strings.Contains(out, "(State = 2)"):
		return true, true
	case strings.Contains(out, "(State = 0)"):
		return false, true
	}
	return false, false
}

// parseCSRUtil reads `csrutil status`.
func parseCSRUtil(out string) (enabled, known bool) {
	switch {
	case strings.Contains(out, "status: enabled"):
		return true, true
	case strings.Contains(out, "status: disabled"):
		return false, true
	}
	return false, false
}

var minLengthRE = regexp.MustCompile(`\.\{(\d+),`)

// parsePWPolicyMinLength reads `pwpolicy -getaccountpolicies`. The policy
// is a plist whose password-content rule is a regular expression; the
// minimum length is the `.{N,}` in it. The number is the ENFORCED minimum,
// which is what a password policy is: nobody's actual password is read.
// No policy at all is an enforced minimum of zero, said out loud.
func parsePWPolicyMinLength(out string) (n int, known bool) {
	if strings.Contains(out, "No global account policies") {
		return 0, true
	}
	if !strings.Contains(out, "<plist") {
		return 0, false
	}
	best := 0
	for _, m := range minLengthRE.FindAllStringSubmatch(out, -1) {
		if v, err := strconv.Atoi(m[1]); err == nil && v > best {
			best = v
		}
	}
	return best, true
}

var (
	lockDelayRE = regexp.MustCompile(`screenLock delay is (\d+) (second|minute|hour)`)
	numberRE    = regexp.MustCompile(`^\s*(\d+)\s*$`)
)

// darwinScreenLock turns the screensaver idle time and the lock delay into
// one number: how long a Mac left alone takes to ask for a password. Zero
// means never. An idle time that is not set is the system default of
// twenty minutes, which is what the machine does, rather than unknown.
func darwinScreenLock(idleOut, lockOut string) (seconds int, known bool) {
	if strings.Contains(lockOut, "screenLock is off") {
		return 0, true
	}
	delay := -1
	if strings.Contains(lockOut, "screenLock delay is immediate") {
		delay = 0
	} else if m := lockDelayRE.FindStringSubmatch(lockOut); m != nil {
		v, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "minute":
			v *= 60
		case "hour":
			v *= 3600
		}
		delay = v
	}
	if delay < 0 {
		return 0, false
	}
	idle := 1200
	if m := numberRE.FindStringSubmatch(idleOut); m != nil {
		idle, _ = strconv.Atoi(m[1])
	}
	if idle == 0 {
		return 0, true
	}
	return idle + delay, true
}

// consoleUser is who is at the Mac's keyboard: the owner of /dev/console.
// Nobody, or root, means there is no session to read or lock.
func consoleUser(ctx context.Context, run Runner) (name, uid string) {
	out, err := run(ctx, statCmd, "-f", "%Su", "/dev/console")
	if err != nil {
		return "", ""
	}
	name = strings.TrimSpace(out)
	if name == "" || name == "root" || name == "_windowserver" || name == "loginwindow" {
		return "", ""
	}
	out, err = run(ctx, idCmd, "-u", name)
	if err != nil {
		return "", ""
	}
	uid = strings.TrimSpace(out)
	if _, err := strconv.Atoi(uid); err != nil {
		return "", ""
	}
	return name, uid
}

// asUser runs a tool as the person at the keyboard, inside their session,
// which is what a per-user setting needs. The agent is root, so this is a
// step down rather than up.
func asUser(ctx context.Context, run Runner, user, uid, prog string, args ...string) (string, error) {
	full := append([]string{"asuser", uid, sudo, "-u", user, prog}, args...)
	return run(ctx, launchctl, full...)
}

// The Windows tools.
const (
	manageBDE = "manage-bde"
	netCmd    = "net"
	regCmd    = "reg"
	netsh     = "netsh"
	querySess = "query"
	tsdiscon  = "tsdiscon"
	policyKey = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
)

func windowsState(ctx context.Context, run Runner) policy.Report {
	var r policy.Report
	if out, err := run(ctx, manageBDE, "-status", "C:"); err == nil {
		if on, _, known := parseManageBDE(out); known {
			r.DiskEncryption = &on
		}
	}
	if out, err := run(ctx, netCmd, "accounts"); err == nil {
		if n, known := parseNetAccountsMinLength(out); known {
			r.PasscodeLength = &n
			if n > 0 {
				// A policy that requires at least one character is a
				// policy under which no account can be without one.
				set := true
				r.PasscodeSet = &set
			}
		}
	}
	if out, err := run(ctx, regCmd, "query", policyKey, "/v", "InactivityTimeoutSecs"); err == nil {
		if n, known := parseRegDword(out, "InactivityTimeoutSecs"); known {
			r.ScreenLockTimeout = &n
		}
	}
	if out, err := run(ctx, netsh, "advfirewall", "show", "allprofiles", "state"); err == nil {
		if on, known := parseNetshFirewall(out); known {
			r.Firewall = &on
		}
	}
	return r
}

// parseManageBDE reads `manage-bde -status C:`: whether protection is on,
// and whether encryption is still running in the background.
func parseManageBDE(out string) (on, converting, known bool) {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Protection Status:"):
			known = true
			on = strings.Contains(t, "Protection On")
		case strings.HasPrefix(t, "Conversion Status:"):
			converting = strings.Contains(t, "in Progress")
		}
	}
	return on, converting, known
}

// parseNetAccountsMinLength reads `net accounts`: the enforced minimum
// password length for the machine.
func parseNetAccountsMinLength(out string) (n int, known bool) {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "Minimum password length") {
			continue
		}
		f := strings.Fields(t)
		v, err := strconv.Atoi(f[len(f)-1])
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// parseRegDword reads one value out of `reg query`, which prints it as
// "Name    REG_DWORD    0x384".
func parseRegDword(out, name string) (n int, known bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != name || f[1] != "REG_DWORD" {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(f[2]), "0x"), 16, 64)
		if err != nil {
			return 0, false
		}
		return int(v), true
	}
	return 0, false
}

// parseNetshFirewall reads `netsh advfirewall show allprofiles state`. The
// firewall is on when every profile is on: a machine whose public profile
// is off is off wherever it matters most.
func parseNetshFirewall(out string) (on, known bool) {
	seen := 0
	on = true
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "State" {
			continue
		}
		seen++
		if !strings.EqualFold(f[len(f)-1], "ON") {
			on = false
		}
	}
	return on, seen > 0
}

// activeSession finds the session at the console in `query session`, for
// a lock. The console session is the row marked ">" or in state Active
// whose name is console.
func activeSession(out string) (id string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimPrefix(strings.TrimSpace(line), ">")
		f := strings.Fields(t)
		if len(f) < 3 {
			continue
		}
		for i := 1; i < len(f)-1; i++ {
			if _, err := strconv.Atoi(f[i]); err == nil && strings.EqualFold(f[i+1], "Active") {
				return f[i], true
			}
		}
	}
	return "", false
}

// The Linux tools. Less is read here and less is put right: Linux is not
// a family the policy engine scopes yet, and the honest answer for the
// rest is unsaid.
const (
	lsblk         = "lsblk"
	ufw           = "ufw"
	firewallCmd   = "firewall-cmd"
	loginctl      = "loginctl"
	pwqualityConf = "/etc/security/pwquality.conf"
)

func linuxState(ctx context.Context, run Runner) policy.Report {
	var r policy.Report
	if out, err := run(ctx, lsblk, "-rno", "TYPE"); err == nil {
		on := strings.Contains(out, "crypt")
		r.DiskEncryption = &on
	}
	if out, err := run(ctx, ufw, "status"); err == nil {
		switch {
		case strings.Contains(out, "Status: active"):
			on := true
			r.Firewall = &on
		case strings.Contains(out, "Status: inactive"):
			on := false
			r.Firewall = &on
		}
	} else if out, err := run(ctx, firewallCmd, "--state"); err == nil || strings.Contains(out, "not running") {
		on := strings.TrimSpace(out) == "running"
		r.Firewall = &on
	}
	if b, err := os.ReadFile(pwqualityConf); err == nil {
		if n, known := parsePwquality(string(b)); known {
			r.PasscodeLength = &n
		}
	}
	return r
}

func parsePwquality(conf string) (n int, known bool) {
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || !strings.HasPrefix(t, "minlen") {
			continue
		}
		_, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return i, true
		}
	}
	return 0, false
}

// ------------------------------------------------------------------ acting

// Native locks the machine and puts settings right with the platform's own
// tools, and hands everything else, wipes above all, to a Fallback: the
// operator's helpers, or NotConfigured, which refuses by name. A wipe is
// never done natively because there is no undoing a wrong one; it stays
// an operator's deliberate decision to install a helper for it.
type Native struct {
	// OS is the platform to act as; runtime.GOOS when empty.
	OS string
	// Run runs the platform's tools; the real exec when nil.
	Run Runner
	// Dir is where the files this needs are written: the password policy
	// handed to pwpolicy, and the FileVault deferral when RecoveryKeyFile
	// is empty.
	Dir string
	// RecoveryKeyFile is where a captured recovery key is left for the
	// agent's escrow. FileVault is told to write its deferral record
	// there; the BitLocker recovery password is written there.
	RecoveryKeyFile string
	Fallback        Enforcer
	Log             *slog.Logger
}

func (n Native) os() string {
	if n.OS != "" {
		return n.OS
	}
	return runtime.GOOS
}

func (n Native) run() Runner {
	if n.Run != nil {
		return n.Run
	}
	return execRunner
}

func (n Native) fallback() Enforcer {
	if n.Fallback != nil {
		return n.Fallback
	}
	return NotConfigured{}
}

func (n Native) log() *slog.Logger {
	if n.Log != nil {
		return n.Log
	}
	return slog.Default()
}

func (n Native) Name() string {
	return "native (" + n.os() + "), then " + n.fallback().Name()
}

// Do carries out an instruction. Locking is native; the rest is handed on.
func (n Native) Do(ctx context.Context, kind string) error {
	switch kind {
	case "lock", "lost_mode":
		return n.lock(ctx)
	}
	return n.fallback().Do(ctx, kind)
}

func (n Native) lock(ctx context.Context) error {
	run := n.run()
	switch n.os() {
	case "darwin":
		user, uid := consoleUser(ctx, run)
		if user == "" {
			return errors.New("agent: nobody is logged in at the console, so there is no session to lock")
		}
		_, err := asUser(ctx, run, user, uid, cgsession, "-suspend")
		return err
	case "windows":
		out, err := run(ctx, querySess, "session")
		if err != nil {
			return fmt.Errorf("agent: could not list sessions: %w", err)
		}
		id, ok := activeSession(out)
		if !ok {
			return errors.New("agent: nobody is logged in at the console, so there is no session to lock")
		}
		_, err = run(ctx, tsdiscon, id)
		return err
	case "linux":
		_, err := run(ctx, loginctl, "lock-sessions")
		return err
	}
	return n.fallback().Do(ctx, "lock")
}

// The ranges a number from the server is held to before it becomes an
// argument. A passcode longer than this is one nobody can type; a lock
// longer than a day is no lock.
const (
	MaxPasscodeLength = 64
	MaxLockTimeout    = 24 * 60 * 60
)

// Remediate puts one failed requirement right, where the platform can.
//
// What it will not do, by kind: a passcode is chosen by a person, so
// passcode_required is not met by this; an operating system is updated by
// its own updater; a Mac with its protections off is reinstalled. Those
// come back as errors naming why, and the finding stays on the console.
func (n Native) Remediate(ctx context.Context, f policy.Finding) error {
	switch f.Kind {
	case policy.FirewallRequired:
		return n.firewallOn(ctx)
	case policy.DiskEncryptionRequired:
		return n.encrypt(ctx)
	case policy.PasscodeMinLength:
		if f.Num < 1 || f.Num > MaxPasscodeLength {
			return fmt.Errorf("agent: refusing a passcode length of %d; this build sets 1 to %d", f.Num, MaxPasscodeLength)
		}
		return n.passcodeLength(ctx, f.Num)
	case policy.ScreenLockTimeoutMax:
		if f.Num < 1 || f.Num > MaxLockTimeout {
			return fmt.Errorf("agent: refusing a lock timeout of %d seconds; this build sets 1 to %d", f.Num, MaxLockTimeout)
		}
		return n.screenLock(ctx, f.Num)
	case policy.PasscodeRequired:
		return errors.New("agent: a passcode is chosen by the person using the machine; the length policy can be set, the passcode itself cannot")
	case policy.OSVersionMin:
		return errors.New("agent: the operating system is updated by its own updater, not by this agent")
	case policy.JailbreakBlocked:
		return errors.New("agent: a machine with its protections switched off is put right by reinstalling it")
	}
	return fmt.Errorf("agent: %s is not something this machine can put right by itself", f.Kind)
}

func (n Native) firewallOn(ctx context.Context) error {
	run := n.run()
	switch n.os() {
	case "darwin":
		return failed(run(ctx, socketfilterfw, "--setglobalstate", "on"))
	case "windows":
		return failed(run(ctx, netsh, "advfirewall", "set", "allprofiles", "state", "on"))
	case "linux":
		return failed(run(ctx, ufw, "--force", "enable"))
	}
	return errors.New("agent: no firewall to switch on here")
}

// encrypt starts disk encryption. On both platforms the machine finishes
// it later, so the answer is ErrDeferred: FileVault enables at the next
// login (and writes its recovery key to the escrow file then); BitLocker
// encrypts in the background (and its recovery password is written to the
// escrow file now).
func (n Native) encrypt(ctx context.Context) error {
	run := n.run()
	switch n.os() {
	case "darwin":
		out, err := run(ctx, fdesetup, "status")
		if err != nil {
			return fmt.Errorf("agent: could not read FileVault's state: %w", err)
		}
		on, deferred, _ := parseFDESetup(out)
		if on {
			return nil
		}
		if deferred {
			return fmt.Errorf("%w: FileVault enables at the next login", ErrDeferred)
		}
		file := n.RecoveryKeyFile
		if file == "" {
			file = filepath.Join(n.Dir, "filevault-deferred.plist")
		}
		if err := failed(run(ctx, fdesetup, "enable", "-defer", file, "-forceatlogin", "0", "-dontaskatlogout")); err != nil {
			return err
		}
		return fmt.Errorf("%w: FileVault enables at the next login", ErrDeferred)
	case "windows":
		out, err := run(ctx, manageBDE, "-status", "C:")
		if err != nil {
			return fmt.Errorf("agent: could not read BitLocker's state: %w", err)
		}
		on, converting, _ := parseManageBDE(out)
		if on {
			return nil
		}
		if converting {
			return fmt.Errorf("%w: BitLocker is still encrypting", ErrDeferred)
		}
		if err := failed(run(ctx, manageBDE, "-on", "C:", "-RecoveryPassword", "-SkipHardwareTest")); err != nil {
			return err
		}
		if n.RecoveryKeyFile != "" {
			out, err := run(ctx, manageBDE, "-protectors", "-get", "C:", "-Type", "RecoveryPassword")
			if err == nil {
				if key := bitlockerPassword(out); key != "" {
					if werr := os.WriteFile(n.RecoveryKeyFile, []byte(key+"\n"), 0o600); werr != nil {
						n.log().Error("could not keep the BitLocker recovery password for escrow", "err", werr)
					}
				}
			}
		}
		return fmt.Errorf("%w: BitLocker is encrypting in the background", ErrDeferred)
	}
	return errors.New("agent: encrypting a running Linux root volume is a reinstall, not a setting")
}

var bitlockerKeyRE = regexp.MustCompile(`\b\d{6}(?:-\d{6}){7}\b`)

// bitlockerPassword finds the 48-digit recovery password in what
// `manage-bde -protectors -get` prints.
func bitlockerPassword(out string) string { return bitlockerKeyRE.FindString(out) }

func (n Native) passcodeLength(ctx context.Context, length int) error {
	run := n.run()
	switch n.os() {
	case "darwin":
		// pwpolicy takes the policy as a plist file. The file is written
		// here, by this process, from the one checked number.
		path := filepath.Join(n.Dir, "passcode-policy.plist")
		if err := os.WriteFile(path, []byte(passcodePolicyPlist(length)), 0o600); err != nil {
			return err
		}
		return failed(run(ctx, pwpolicy, "-setaccountpolicies", path))
	case "windows":
		return failed(run(ctx, netCmd, "accounts", "/minpwlen:"+strconv.Itoa(length)))
	}
	return errors.New("agent: this build does not set a password length policy on Linux")
}

// passcodePolicyPlist is the global account policy macOS reads: one rule,
// the length. It applies when a password is next set or changed.
func passcodePolicyPlist(length int) string {
	n := strconv.Itoa(length)
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>policyCategoryPasswordContent</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '.{` + n + `,}'</string>
			<key>policyIdentifier</key>
			<string>Password must be at least ` + n + ` characters</string>
			<key>policyParameters</key>
			<dict>
				<key>minimumLength</key>
				<integer>` + n + `</integer>
			</dict>
		</dict>
	</array>
</dict>
</plist>
`
}

func (n Native) screenLock(ctx context.Context, seconds int) error {
	run := n.run()
	switch n.os() {
	case "darwin":
		// The idle time before the screensaver, set as the person at the
		// keyboard. The delay between screensaver and password prompt is
		// theirs to set and needs their password to change, so it is
		// left as it is; the next report says what the two add up to.
		user, uid := consoleUser(ctx, run)
		if user == "" {
			return errors.New("agent: nobody is logged in at the console; the screen lock is a per-person setting")
		}
		return failed(asUser(ctx, run, user, uid, defaults, "-currentHost", "write",
			"com.apple.screensaver", "idleTime", "-int", strconv.Itoa(seconds)))
	case "windows":
		return failed(run(ctx, regCmd, "add", policyKey, "/v", "InactivityTimeoutSecs",
			"/t", "REG_DWORD", "/d", strconv.Itoa(seconds), "/f"))
	}
	return errors.New("agent: this build does not set the screen lock on Linux")
}

// failed turns a tool's exit into an error that carries what it printed,
// which is usually the reason.
func failed(out string, err error) error {
	if err != nil {
		return fmt.Errorf("agent: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}
