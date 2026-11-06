package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"platform/internal/policy"
)

// ---------------------------------------------------------------- enforcing

// NotConfigured is what an agent ships with until the platform-specific
// enforcement is written. It is the device-side twin of the server's
// command.AppleNotConfigured: it names what is missing rather than failing
// vaguely, and because it returns an error the command is NOT acknowledged,
// so the console keeps showing the instruction as outstanding instead of
// quietly reporting work that never happened.
type NotConfigured struct{}

func (NotConfigured) Name() string { return "no local enforcement" }

func (NotConfigured) Do(_ context.Context, kind string) error {
	return fmt.Errorf("agent: this build cannot %s on %s. "+
		"Locking, clearing a passcode and wiping are privileged platform calls: "+
		"on Apple hardware they arrive as an MDM payload and need the vendor "+
		"certificate; elsewhere they need a helper this agent has not been given",
		kind, runtime.GOOS)
}

// ScriptEnforcer runs a command per instruction kind.
//
// This is how a real agent does it on a platform whose enforcement is a
// privileged helper rather than an in-process call, and it is the honest
// shape for a build that cannot ship signed platform binaries: the operator
// installs the helpers, names them here, and this package stays free of
// operating-system calls.
//
// Nothing from the server reaches the shell. The map is keyed by instruction
// kind and an unknown kind is refused, so the only strings that can ever be
// executed are the ones an operator wrote in configuration.
type ScriptEnforcer struct {
	// Scripts maps an instruction kind to an executable path.
	Scripts map[string]string
	Timeout time.Duration
}

func (s ScriptEnforcer) Name() string { return "local helpers" }

func (s ScriptEnforcer) Do(ctx context.Context, kind string) error {
	path, ok := s.Scripts[kind]
	if !ok {
		return fmt.Errorf("agent: no helper is configured for %q", kind)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// No shell, and no arguments built from anything the server sent. The
	// path comes from configuration and the instruction kind only chooses
	// which configured path to run.
	out, err := exec.CommandContext(ctx, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("agent: %s helper failed: %w: %s",
			kind, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------------------------------------------------------------- probing

// HostProbe reads what it can from the machine it is running on.
//
// It is deliberately incomplete, and the incompleteness is the point. Reading
// whether FileVault is on, what the passcode policy is, or how long before
// the screen locks are per platform and mostly privileged. Rather than
// guessing, every field this probe cannot establish is left nil, and the
// server reads nil as "did not say" and never as a pass. An agent on a
// half-supported platform therefore produces an honest state_unknown.
//
// What it does establish: the operating system family and version, the
// hostname, and the hardware serial. Those are enough to enrol, to be
// recognised on re-enrolment, and to be judged against an os_version_min
// rule.
type HostProbe struct {
	// Overrides let a deployment supply what this probe cannot read, from a
	// management tool that already knows. They are applied last.
	Overrides policy.Report
	// OS is the platform to read as; runtime.GOOS when empty. A test on
	// Linux reads a Mac's command output through it.
	OS string
	// Run runs the platform's own tools; the real exec when nil.
	Run Runner
}

func (p HostProbe) os() string {
	if p.OS != "" {
		return p.OS
	}
	return runtime.GOOS
}

func (p HostProbe) run() Runner {
	if p.Run != nil {
		return p.Run
	}
	return execRunner
}

func (p HostProbe) Name() string { return "host probe (" + p.os() + ")" }

func (p HostProbe) OSFamily() string {
	switch p.os() {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	case "android":
		return "android"
	case "ios":
		return "ios"
	default:
		// Linux and everything else. There is no Linux family in the
		// platform's vocabulary yet; saying so out loud is better than
		// enrolling as something this machine is not.
		return ""
	}
}

func (HostProbe) Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unnamed device"
	}
	return h
}

// Serial is how a rebuilt machine is recognised as the same hardware, so it
// has to be stable across a wipe. Where it cannot be read, enrolment fails
// loudly rather than inventing one: a made-up serial would make every
// rebuild look like a new device and quietly double the fleet.
func (p HostProbe) Serial() (string, error) {
	run := p.run()
	switch p.os() {
	case "darwin":
		out, err := run(context.Background(), "/usr/sbin/ioreg", "-l")
		if err == nil {
			if s := after(out, `"IOPlatformSerialNumber" = "`, `"`); s != "" {
				return s, nil
			}
		}
	case "linux":
		for _, f := range []string{
			"/sys/class/dmi/id/product_serial",
			"/etc/machine-id",
		} {
			if b, err := os.ReadFile(f); err == nil {
				if s := strings.TrimSpace(string(b)); s != "" {
					return s, nil
				}
			}
		}
	case "windows":
		out, err := run(context.Background(), "wmic", "bios", "get", "serialnumber")
		if err == nil {
			lines := strings.Fields(out)
			if len(lines) > 1 {
				return lines[len(lines)-1], nil
			}
		}
	}
	return "", errors.New("this machine's hardware serial could not be read")
}

func (p HostProbe) Collect(ctx context.Context) (policy.Report, error) {
	// What the platform's own tools say, then the version and the apps.
	// Each reader leaves its field nil when the tool is missing, refuses
	// to run, or says something this build does not recognise.
	r := nativeState(ctx, p.os(), p.run())
	r.OSVersion = p.osVersion(ctx)
	r.Apps = installedApps(ctx)
	r.MACAddresses = hardwareAddresses()

	// Overrides last, and only where they say something. A deployment that
	// can read FileVault from elsewhere fills that in; everything it does
	// not fill in stays unsaid.
	o := p.Overrides
	if o.PasscodeSet != nil {
		r.PasscodeSet = o.PasscodeSet
	}
	if o.PasscodeLength != nil {
		r.PasscodeLength = o.PasscodeLength
	}
	if o.DiskEncryption != nil {
		r.DiskEncryption = o.DiskEncryption
	}
	if o.ScreenLockTimeout != nil {
		r.ScreenLockTimeout = o.ScreenLockTimeout
	}
	if o.Firewall != nil {
		r.Firewall = o.Firewall
	}
	if o.Jailbroken != nil {
		r.Jailbroken = o.Jailbroken
	}
	if o.OSVersion != "" {
		r.OSVersion = o.OSVersion
	}
	return r, nil
}

func (p HostProbe) osVersion(ctx context.Context) string {
	run := p.run()
	switch p.os() {
	case "darwin":
		out, err := run(ctx, "/usr/bin/sw_vers", "-productVersion")
		if err == nil {
			return strings.TrimSpace(out)
		}
	case "linux":
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			if v := after(string(b), "VERSION_ID=\"", "\""); v != "" {
				return v
			}
		}
	case "windows":
		out, err := run(ctx, "cmd", "/c", "ver")
		if err == nil {
			return strings.TrimSpace(out)
		}
	}
	// Unsaid rather than guessed. An os_version_min rule then reads this
	// device as state_unknown, which is the correct answer.
	return ""
}

func after(s, prefix, terminator string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	rest := s[i+len(prefix):]
	j := strings.Index(rest, terminator)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// FixedProbe reports exactly what it is given.
//
// It exists for tests and for a deployment whose state comes from somewhere
// this agent cannot reach, such as a management tool that already holds the
// answers. It is not a stub that pretends: whatever is left nil stays nil
// and is reported as unsaid.
type FixedProbe struct {
	SerialNumber string
	Family       string
	Host         string
	Report       policy.Report
}

func (FixedProbe) Name() string       { return "fixed" }
func (p FixedProbe) OSFamily() string { return p.Family }
func (p FixedProbe) Hostname() string { return p.Host }
func (p FixedProbe) Serial() (string, error) {
	if p.SerialNumber == "" {
		return "", errors.New("no serial was configured")
	}
	return p.SerialNumber, nil
}
func (p FixedProbe) Collect(context.Context) (policy.Report, error) { return p.Report, nil }

// RecordingEnforcer carries nothing out and writes down what it was asked
// to do. For tests, and for a dry run on a fleet before anyone trusts the
// helpers.
type RecordingEnforcer struct {
	Done []string
	Fail map[string]error
}

func (RecordingEnforcer) Name() string { return "recording (nothing is carried out)" }

func (r *RecordingEnforcer) Do(_ context.Context, kind string) error {
	if err, bad := r.Fail[kind]; bad {
		return err
	}
	r.Done = append(r.Done, kind)
	return nil
}

// installedApps is the inventory (F3), from the place each platform keeps
// it. Nil when this platform's list cannot be read, so the server records
// "did not say" rather than "nothing installed".
func installedApps(ctx context.Context) []policy.App {
	switch runtime.GOOS {
	case "darwin":
		var out []policy.App
		for _, dir := range []string{"/Applications", "/System/Applications"} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !strings.HasSuffix(e.Name(), ".app") {
					continue
				}
				name := strings.TrimSuffix(e.Name(), ".app")
				plist := dir + "/" + e.Name() + "/Contents/Info.plist"
				id, version := plistValues(plist)
				if id == "" {
					id = "app:" + strings.ToLower(name)
				}
				out = append(out, policy.App{Identifier: id, Name: name, Version: version})
				if len(out) >= 1500 {
					return out
				}
			}
		}
		return out
	case "linux":
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
		if err != nil {
			out, err = exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n").Output()
		}
		if err != nil {
			return nil
		}
		var apps []policy.App
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 || parts[0] == "" {
				continue
			}
			apps = append(apps, policy.App{Identifier: "pkg:" + parts[0], Name: parts[0], Version: parts[1]})
			if len(apps) >= 1500 {
				break
			}
		}
		return apps
	case "windows":
		out, err := exec.CommandContext(ctx, "reg", "query",
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/v", "DisplayName").Output()
		if err != nil {
			return nil
		}
		var apps []policy.App
		for _, line := range strings.Split(string(out), "\n") {
			if i := strings.Index(line, "REG_SZ"); i != -1 && strings.Contains(line, "DisplayName") {
				name := strings.TrimSpace(line[i+len("REG_SZ"):])
				if name != "" {
					apps = append(apps, policy.App{Identifier: "win:" + strings.ToLower(name), Name: name})
				}
			}
		}
		return apps
	}
	return nil
}

// plistValues reads the bundle id and version from an Info.plist without a
// plist library: the two keys are looked up by name in the XML. Binary
// plists come back empty, which is "unsaid".
func plistValues(path string) (id, version string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	s := string(b)
	id = strings.TrimSpace(after(s, "<key>CFBundleIdentifier</key>", "</string>"))
	version = strings.TrimSpace(after(s, "<key>CFBundleShortVersionString</key>", "</string>"))
	id = strings.TrimSpace(strings.TrimPrefix(id, "<string>"))
	version = strings.TrimSpace(strings.TrimPrefix(version, "<string>"))
	return id, version
}
