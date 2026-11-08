package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"platform/internal/catalog"
)

// guidedBody turns the guided editor's form into a policy body: the rules the
// policy judges by, what to do on failure, and the settings from the
// catalogue for its system. It builds nothing the catalogue does not know:
// the form is made from the catalogue, and what comes back is checked against
// it again by policy.Save, so a hand-made request cannot add a setting the
// editor never offered.
func guidedBody(r *http.Request) ([]byte, error) {
	os := strings.TrimSpace(r.FormValue("os_family"))
	if os != "android" && os != "windows" {
		return nil, fmt.Errorf("choose Android or Windows for a policy with settings")
	}
	body := map[string]any{}

	// What the policy judges a device by.
	for _, k := range []string{"passcode_required", "disk_encryption_required", "firewall_required", "jailbreak_blocked"} {
		if r.FormValue("rule."+k) != "" {
			body[k] = true
		}
	}
	for _, k := range []string{"passcode_min_length", "screen_lock_timeout_max"} {
		if v := strings.TrimSpace(r.FormValue("rule." + k)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%q needs a whole number above zero", k)
			}
			body[k] = n
		}
	}
	if v := strings.TrimSpace(r.FormValue("rule.os_version_min")); v != "" {
		body["os_version_min"] = v
	}
	if r.FormValue("on_failure") == "quarantine" {
		body["on_failure"] = "quarantine"
	}
	if r.FormValue("remediate") != "" {
		body["remediate"] = true
	}

	// What the policy sets.
	cfg := map[string]any{}
	for _, s := range catalog.ForOS(os) {
		name := "cfg." + s.Key
		v := strings.TrimSpace(r.FormValue(name))
		switch s.Kind {
		case catalog.Bool:
			if r.FormValue(name) != "" {
				cfg[s.Key] = true
			}
		case catalog.Int:
			if v == "" {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("%q needs a whole number", s.Label)
			}
			cfg[s.Key] = n
		case catalog.Choice, catalog.Text:
			if v != "" {
				cfg[s.Key] = v
			}
		case catalog.Apps:
			list, err := parseAppLines(r.FormValue(name))
			if err != nil {
				return nil, err
			}
			if len(list) > 0 {
				cfg[s.Key] = list
			}
		}
	}
	if len(cfg) > 0 {
		body["config"] = cfg
	}
	return json.Marshal(body)
}

// parseAppLines reads the apps box: one app a line, its package name and then
// what to do with it. A package name alone is refused, because "required" and
// "blocked" are opposites and guessing one would be a way to push or block an
// app nobody meant to.
func parseAppLines(text string) ([]catalog.AppRule, error) {
	var out []catalog.AppRule
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.NewReplacer(":", " ", ",", " ", "\t", " ").Replace(line))
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("each app needs its package name, then required, available or blocked (got %q)", line)
		}
		out = append(out, catalog.AppRule{Package: f[0], Install: strings.ToLower(f[1])})
	}
	return out, nil
}
