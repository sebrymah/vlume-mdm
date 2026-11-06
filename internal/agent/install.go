package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Installing the agent, and the two things that get it wrong.
//
// THE TOKEN MUST NOT REACH THE COMMAND LINE. An enrolment token is a bearer
// credential: whoever holds it can enrol a device into the tenant. On Linux
// and macOS the full argument list of every process is readable by every
// local user through ps, so `agent enrol -token XXXX` hands it to anybody
// with a shell on the machine, for as long as the command runs. That is a
// particularly unlucky shape, because enrolment is the one command a person
// types by hand, from a shell script, as root.
//
// THE AGENT RUNS AS ROOT AND EXECUTES HELPERS. It has to: locking and wiping
// are privileged. That makes the binary, the helper scripts and the
// directories holding them a path to root for anybody who can write to them.
// A file that is group or world writable is not a configuration preference
// at that point, it is a local privilege escalation with a service unit
// pointing at it.
//
// Neither is caught by anything the agent does at runtime, so both are
// checked here and reported by `agent doctor`.

// ReadToken gets the enrolment token from somewhere that is not argv.
//
// A path reads the file, after checking nobody else can. An empty path reads
// one line from standard input, which is what an interactive install does
// and what `echo "$TOKEN" | agent enrol` does in a script.
func ReadToken(path string, stdin io.Reader) (string, error) {
	if path == "" {
		r := bufio.NewReader(stdin)
		line, err := r.ReadString('\n')
		token := strings.TrimSpace(line)
		if token == "" {
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			return "", errors.New("agent: no enrolment token was given")
		}
		return token, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	// The same rule as an SSH private key, for the same reason: a token
	// file anyone can read is a token anyone can use.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf(
			"agent: %s is readable by other users (mode %04o). "+
				"An enrolment token is a credential: chmod 600 it, or pipe it in "+
				"on standard input instead", path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("agent: %s is empty", path)
	}
	return token, nil
}

// ---------------------------------------------------------------- doctor

// Finding is one thing wrong with an installation.
type Finding struct {
	Path string
	// Problem is what is wrong, in the words somebody fixing it needs.
	Problem string
	// Fix is the command that fixes it, where there is one.
	Fix string
	// Serious separates "this is a way in" from "this is untidy".
	Serious bool
}

// Install is where everything lives, so the checks can be run against a
// temporary directory in a test as easily as against a real machine.
type Install struct {
	Binary  string
	Dir     string
	Service string
	Helpers map[string]string
}

// Check looks for the ways an installation becomes a way in.
//
// It is deliberately not clever. Every finding below is something that has
// happened to somebody: a state directory left at 0755 by an install script
// that forgot umask, a binary dropped in /tmp during testing and never
// moved, a helper script written by the administrator who installed it and
// left writable by their group.
func Check(in Install) []Finding {
	var out []Finding
	if runtime.GOOS == "windows" {
		// The permission model is different enough that these checks would
		// be wrong rather than merely unhelpful. Saying so is better than
		// a clean bill of health that means nothing.
		return []Finding{{
			Path:    "",
			Problem: "permission checks are not implemented on Windows, so this says nothing about whether the installation is safe",
			Serious: false,
		}}
	}

	add := func(f Finding) { out = append(out, f) }

	// The state directory holds the private key that IS this device's
	// identity. Anything wider than owner-only and any local account can
	// become this machine.
	if info, err := os.Stat(in.Dir); err != nil {
		add(Finding{in.Dir, "the state directory does not exist: " + err.Error(), "", true})
	} else {
		if !info.IsDir() {
			add(Finding{in.Dir, "the state directory is not a directory", "", true})
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			add(Finding{in.Dir,
				fmt.Sprintf("the state directory is mode %04o, so other users can reach this device's private key", perm),
				"chmod 700 " + in.Dir, true})
		}
		if !ownedByRoot(info) {
			add(Finding{in.Dir, "the state directory is not owned by root",
				"chown root " + in.Dir, true})
		}
	}

	if key := filepath.Join(in.Dir, "key.pem"); exists(key) {
		if info, err := os.Stat(key); err == nil {
			if perm := info.Mode().Perm(); perm&0o077 != 0 {
				add(Finding{key,
					fmt.Sprintf("the private key is mode %04o and should be 600", perm),
					"chmod 600 " + key, true})
			}
		}
	}

	// The binary and the helpers run as root. Anybody who can write to
	// them, or to a directory on the way to them, can replace them and be
	// root at the next check-in.
	checkExecutable(in.Binary, "the agent", add)
	names := make([]string, 0, len(in.Helpers))
	for k := range in.Helpers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, kind := range names {
		checkExecutable(in.Helpers[kind], "the "+kind+" helper", add)
	}

	// A launchd plist that anyone can write is a way to make launchd run
	// anything as root. launchd itself refuses one, which is worth knowing
	// before the install silently does nothing.
	if in.Service != "" {
		if info, err := os.Stat(in.Service); err != nil {
			add(Finding{in.Service, "the service definition is missing: " + err.Error(), "", true})
		} else {
			if perm := info.Mode().Perm(); perm&0o022 != 0 {
				add(Finding{in.Service,
					fmt.Sprintf("the service definition is mode %04o and can be rewritten by other users", perm),
					"chmod 644 " + in.Service, true})
			}
			if !ownedByRoot(info) {
				add(Finding{in.Service, "the service definition is not owned by root",
					"chown root " + in.Service, true})
			}
		}
	}
	return out
}

func checkExecutable(path, what string, add func(Finding)) {
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		add(Finding{path, what + " is missing: " + err.Error(), "", true})
		return
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		add(Finding{path,
			fmt.Sprintf("%s is mode %04o, so another user can replace it and this runs as root", what, perm),
			"chmod 755 " + path, true})
	}
	if !ownedByRoot(info) {
		add(Finding{path, what + " is not owned by root", "chown root " + path, true})
	}
	// A safe file in a writable directory is not safe: the directory's
	// owner can rename it away and put their own there.
	dir := filepath.Dir(path)
	if info, err := os.Stat(dir); err == nil {
		perm := info.Mode().Perm()
		// The sticky bit makes /tmp-style directories safe from renaming
		// somebody else's file, which is exactly the case it exists for.
		if perm&0o022 != 0 && info.Mode()&fs.ModeSticky == 0 {
			add(Finding{dir,
				fmt.Sprintf("%s lives in a directory other users can write to (mode %04o), so they can replace it", what, perm),
				"chmod 755 " + dir, true})
		}
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Serious counts the findings that are ways in rather than untidiness, so a
// caller can exit non-zero on those alone.
func Serious(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if f.Serious {
			n++
		}
	}
	return n
}
