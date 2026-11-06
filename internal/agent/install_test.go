package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- the token

// The defect this sprint found. An enrolment token is a bearer credential,
// and on Linux and macOS the full argument list of every process is
// readable by every local user through ps. A -token flag hands it to
// anybody with a shell on the machine, and enrolment is the one command
// somebody types by hand, as root, from an install script.
func TestTheTokenIsNeverTakenAsACommandLineArgument(t *testing.T) {
	src, err := os.ReadFile("../../cmd/agent/main.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(src), `flag.String("token"`) {
		t.Fatal("cmd/agent takes the enrolment token as a flag again. " +
			"ps shows every process's arguments to every local user, so that " +
			"hands the token to anybody with a shell on the machine.")
	}
	// The same for the install script, which is the thing that actually
	// runs it as root.
	script, err := os.ReadFile("../../packaging/install.sh")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(script), "enrol -token") ||
		strings.Contains(string(script), "-token ") {
		t.Fatal("the install script passes the token as an argument")
	}
}

func TestTheTokenIsReadFromStandardInput(t *testing.T) {
	got, err := ReadToken("", strings.NewReader("  a-real-token  \n"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "a-real-token" {
		t.Fatalf("got %q", got)
	}
	// No newline at the end, which is what a here-string gives.
	if got, err := ReadToken("", strings.NewReader("a-real-token")); err != nil || got != "a-real-token" {
		t.Fatalf("got %q (%v)", got, err)
	}
	if _, err := ReadToken("", strings.NewReader("\n")); err == nil {
		t.Fatal("an empty line was accepted as a token")
	}
}

// A token file anybody can read is a token anybody can use. The same rule
// an SSH private key has, for the same reason.
func TestATokenFileOthersCanReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("a-real-token\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := ReadToken(path, nil)
	if err == nil {
		t.Fatal("a world-readable token file was accepted")
	}
	if !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// And the fix it suggests works.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	got, err := ReadToken(path, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != "a-real-token" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------- doctor

// clean builds an installation with nothing wrong with it, so each test
// below can break exactly one thing.
func clean(t *testing.T) Install {
	t.Helper()
	root := t.TempDir()
	// t.TempDir is 0700 already; the parent chain matters for the
	// directory-writability check, so make it explicit.
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(state, "key.pem"), []byte("k"), 0o600); err != nil {
		t.Fatalf("key: %v", err)
	}
	bin := filepath.Join(root, "mdm-agent")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("binary: %v", err)
	}
	svc := filepath.Join(root, "agent.service")
	if err := os.WriteFile(svc, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("service: %v", err)
	}
	helper := filepath.Join(root, "lock-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("helper: %v", err)
	}
	return Install{Binary: bin, Dir: state, Service: svc,
		Helpers: map[string]string{"lock": helper}}
}

func TestACleanInstallationHasNothingWrongWithIt(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the ownership checks need root to produce root-owned files")
	}
	if got := Check(clean(t)); len(got) != 0 {
		t.Fatalf("a clean installation reported %+v", got)
	}
}

// Each of these has happened to somebody.
func TestEachWayInIsFound(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	cases := map[string]struct {
		break_ func(Install) error
		expect string
	}{
		"the state directory is readable by others": {
			func(in Install) error { return os.Chmod(in.Dir, 0o755) },
			"private key",
		},
		"the private key is readable by others": {
			func(in Install) error {
				return os.Chmod(filepath.Join(in.Dir, "key.pem"), 0o644)
			},
			"should be 600",
		},
		"the binary can be replaced": {
			func(in Install) error { return os.Chmod(in.Binary, 0o777) },
			"runs as root",
		},
		"the helper can be replaced": {
			func(in Install) error { return os.Chmod(in.Helpers["lock"], 0o766) },
			"lock helper",
		},
		"the service definition can be rewritten": {
			func(in Install) error { return os.Chmod(in.Service, 0o666) },
			"rewritten",
		},
		"the binary is not owned by root": {
			func(in Install) error { return os.Chown(in.Binary, 1000, 1000) },
			"not owned by root",
		},
		"the binary sits in a directory others can write to": {
			func(in Install) error { return os.Chmod(filepath.Dir(in.Binary), 0o777) },
			"directory other users can write to",
		},
	}
	for name, c := range cases {
		in := clean(t)
		if err := c.break_(in); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := Check(in)
		if Serious(got) == 0 {
			t.Fatalf("%s: nothing was reported", name)
		}
		found := false
		for _, f := range got {
			if strings.Contains(f.Problem, c.expect) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: expected a finding mentioning %q, got %+v", name, c.expect, got)
		}
	}
}

// A safe file in a writable directory is not safe, UNLESS the sticky bit is
// set: that is exactly the case /tmp exists for, and reporting it would be
// a false alarm an administrator learns to ignore.
func TestTheStickyBitIsNotAFalseAlarm(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	in := clean(t)
	dir := filepath.Dir(in.Binary)
	// os.ModeSticky, not the raw 01000: Go carries the sticky bit as a high
	// bit in FileMode rather than in the permission bits, so 0o1777 sets
	// nothing and the first version of this test failed for that reason.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	for _, f := range Check(in) {
		if strings.Contains(f.Problem, "directory other users can write to") {
			t.Fatalf("a sticky directory was reported: %+v", f)
		}
	}
}

// A missing piece is a problem, not a pass. An installation where the
// binary is not there is not a clean one.
func TestWhatIsMissingIsReported(t *testing.T) {
	in := clean(t)
	in.Binary = filepath.Join(t.TempDir(), "not-here")
	in.Dir = filepath.Join(t.TempDir(), "also-not-here")

	got := Check(in)
	if Serious(got) < 2 {
		t.Fatalf("a missing binary and state directory gave %+v", got)
	}
}

// Every finding has to be actionable. A report that says something is wrong
// and not what to do about it is one an administrator closes.
func TestEveryFindingSaysWhatToDo(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	in := clean(t)
	if err := os.Chmod(in.Dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	got := Check(in)
	if len(got) == 0 {
		t.Fatal("nothing reported")
	}
	for _, f := range got {
		if f.Problem == "" {
			t.Fatalf("a finding with no problem: %+v", f)
		}
		if f.Serious && f.Fix == "" && !strings.Contains(f.Problem, "missing") {
			t.Fatalf("a serious finding with no fix: %+v", f)
		}
	}
}
