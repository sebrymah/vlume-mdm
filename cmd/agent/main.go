// Command agent runs on a managed device.
//
//	echo "$TOKEN" | agent -server https://... -dir /var/lib/mdm enrol
//	agent -server https://... -dir /var/lib/mdm -token-file /path enrol
//	agent -server https://... -dir /var/lib/mdm run
//	agent -server ... -dir ... once      # one cycle, for a timer
//	agent -server ... -dir ... doctor    # check the installation
//
// NOTE WHAT IS MISSING: there is no -token flag. An enrolment token is a
// bearer credential, and on Linux and macOS the full argument list of every
// process is readable by every local user through ps. A -token flag hands
// the token to anybody with a shell on the machine for as long as the
// command runs, and enrolment is the one command somebody types by hand, as
// root, from an install script. It is read from a file or from standard
// input instead.
//
// The private key is generated on this machine, written with owner-only
// permissions, and never transmitted. Only a certificate signing request
// leaves the device.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"platform/internal/agent"
)

// Set at build time by build_agent.sh. A binary found on a device years
// later should be traceable to the source that built it, and -ldflags -X on
// a variable that does not exist is a silent no-op, so these have to be
// here for the stamping to mean anything.
var (
	version = "unversioned"
	built   = "unknown"
)

func main() {
	var (
		server    = flag.String("server", "", "the console address for your organisation")
		dir       = flag.String("dir", "", "where this device's identity is kept")
		tokenFile = flag.String("token-file", "",
			"a file holding the one-time enrolment token; without it, the token is read from standard input")
		every  = flag.Duration("every", 15*time.Minute, "how often to report and check in")
		lock   = flag.String("lock-helper", "", "path to the helper that locks this machine")
		wipe   = flag.String("wipe-helper", "", "path to the helper that wipes this machine")
		native = flag.Bool("native", true,
			"read settings with the platform's own tools and put right what a policy asks; false means report only")
		recovery = flag.String("recovery-key-file", "",
			"where a recovery key is left for escrow; the default is recovery-key inside -dir")
		service = flag.String("service-file", "",
			"path to the launchd plist or systemd unit, for doctor to check")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	if cmd == "" {
		fail("say what to do: enrol, run, once, status, doctor or version")
	}
	// version answers before anything else is required. Somebody checking
	// which build is on a machine should not have to know its server
	// address to find out.
	if cmd == "version" {
		fmt.Printf("mdm-agent %s (built %s)\n", version, built)
		return
	}
	if *server == "" || *dir == "" {
		fail("both -server and -dir are required")
	}

	// Helpers are named in configuration and nowhere else. Nothing the
	// server sends can introduce a path here.
	var enforcer agent.Enforcer = agent.NotConfigured{}
	if *lock != "" || *wipe != "" {
		scripts := map[string]string{}
		if *lock != "" {
			scripts["lock"] = *lock
			scripts["lost_mode"] = *lock
		}
		if *wipe != "" {
			scripts["wipe_selective"] = *wipe
			scripts["wipe_full"] = *wipe
		}
		enforcer = agent.ScriptEnforcer{Scripts: scripts}
	}
	// The platform's own tools in front of the helpers: a lock is native,
	// a setting a policy asks to have put right is native, and a wipe is
	// still the helper's, because there is no undoing a wrong one.
	keyFile := *recovery
	if keyFile == "" && *dir != "" {
		keyFile = filepath.Join(*dir, "recovery-key")
	}
	if *native {
		enforcer = agent.Native{Dir: *dir, RecoveryKeyFile: keyFile, Fallback: enforcer, Log: log}
	}

	a, err := agent.New(agent.Config{
		ServerURL: *server, Dir: *dir,
		Probe: agent.HostProbe{}, Enforcer: enforcer, Log: log,
		RecoveryKeyFile: keyFile,
	})
	if err != nil {
		fail("%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "enrol", "enroll":
		token, err := agent.ReadToken(*tokenFile, os.Stdin)
		if err != nil {
			fail("%v", err)
		}
		if err := a.Enrol(ctx, token); err != nil {
			fail("enrolment failed: %v", err)
		}
		fmt.Printf("Enrolled as %s\n", a.DeviceID())

	case "once":
		if err := a.RunOnce(ctx); err != nil {
			fail("%v", err)
		}

	case "run":
		log.Info("agent running", "server", *server, "every", *every,
			"enforcement", enforcer.Name())
		if err := a.Run(ctx, *every); err != nil && ctx.Err() == nil {
			fail("%v", err)
		}

	case "status":
		if !a.Enrolled() {
			fmt.Println("Not enrolled.")
			os.Exit(1)
		}
		fmt.Printf("Enrolled as %s against %s\n", a.DeviceID(), *server)

	case "doctor":
		// Run after installing, and worth running on a schedule. Nothing
		// the agent does at runtime would notice any of this.
		findings := agent.Check(agent.Install{
			Binary: binaryPath(), Dir: *dir, Service: *service,
			Helpers: helperPaths(*lock, *wipe),
		})
		if len(findings) == 0 {
			fmt.Println("Nothing wrong with this installation.")
			return
		}
		serious := agent.Serious(findings)
		for _, f := range findings {
			mark := "note"
			if f.Serious {
				mark = "PROBLEM"
			}
			fmt.Printf("%-8s %s\n         %s\n", mark, f.Path, f.Problem)
			if f.Fix != "" {
				fmt.Printf("         fix: %s\n", f.Fix)
			}
		}
		if serious > 0 {
			word := "is a way"
			if serious > 1 {
				word = "are ways"
			}
			fmt.Printf("\n%d of these %s for another user on this machine to\n"+
				"become root, because this agent runs as root.\n", serious, word)
			os.Exit(1)
		}

	default:
		fail("unknown command %q: use enrol, run, once, status, doctor or version", cmd)
	}
}

// binaryPath is this executable, resolved through any symlink, because the
// thing an attacker would replace is the file on disk rather than the name
// it was invoked by.
func binaryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

func helperPaths(lock, wipe string) map[string]string {
	out := map[string]string{}
	if lock != "" {
		out["lock"] = lock
	}
	if wipe != "" {
		out["wipe"] = wipe
	}
	return out
}
