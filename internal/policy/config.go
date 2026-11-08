package policy

import (
	"errors"
	"fmt"
	"sort"

	"platform/internal/catalog"
)

// What a policy sets on a device (internal/catalog), beside what it judges.

// ErrConfigScope is a config that does not fit the policy's scope.
var ErrConfigScope = errors.New("policy: those settings do not fit this policy")

// checkConfig refuses a policy whose settings do not belong with its scope.
//
// A policy is for ONE operating system, which is the whole point of the
// per-system catalogues: settings from two systems in one policy cannot all be
// meant, and a setting on a policy for the wrong system would be saved, shown,
// and never reach anything. So the system must be named, every setting must be
// that system's, and a setting that only reaches company phones is not put on
// a policy for personal ones (and the other way round), because it would
// quietly do nothing there.
func checkConfig(scope Scope, cfg catalog.Values) error {
	if len(cfg) == 0 {
		return nil
	}
	sys, err := catalog.SystemOf(cfg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfigScope, err)
	}
	if scope.OSFamily == "" {
		return fmt.Errorf("%w: choose which system this policy is for (Android or Windows)", ErrConfigScope)
	}
	if scope.OSFamily != sys {
		return fmt.Errorf("%w: these are %s settings, but the policy is for %s", ErrConfigScope, sys, scope.OSFamily)
	}
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s, _ := catalog.Lookup(k)
		if s.For == "company" && scope.Ownership == "personal" {
			return fmt.Errorf("%w: %q only reaches company-owned devices, and this policy is for personal ones", ErrConfigScope, s.Label)
		}
		if s.For == "personal" && scope.Ownership == "company" {
			return fmt.Errorf("%w: %q only reaches personal devices (the work profile), and this policy is for company-owned ones", ErrConfigScope, s.Label)
		}
	}
	return nil
}

// MergeConfig is the settings the applied policies ask of one device: for
// each setting the strictest value, taken in order of policy name so the same
// policies always give the same answer.
func MergeConfig(applied []Policy) catalog.Values {
	ps := append([]Policy(nil), applied...)
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	sets := make([]catalog.Values, 0, len(ps))
	for _, p := range ps {
		if len(p.Config) > 0 {
			sets = append(sets, p.Config)
		}
	}
	return catalog.Merge(sets...)
}

// WhoAsked says which policy asked for each setting in a merged set, so a
// person looking at a phone can see why it has the rule it has. For a setting
// asked for by several, the ones whose value is the winning one are named.
func WhoAsked(applied []Policy, merged catalog.Values) map[string][]string {
	out := map[string][]string{}
	for k, want := range merged {
		for _, p := range applied {
			v, ok := p.Config[k]
			if !ok {
				continue
			}
			s, _ := catalog.Lookup(k)
			// A policy whose own value is as strict as the winner is a
			// reason for it.
			if catalog.Describe(s, v) == catalog.Describe(s, want) || s.Kind == catalog.Apps {
				out[k] = append(out[k], p.Label())
			}
		}
		sort.Strings(out[k])
	}
	return out
}
