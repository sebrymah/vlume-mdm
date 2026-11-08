package policy

import (
	"strings"
	"testing"

	"platform/internal/catalog"
)

// Every ready-made policy is an ordinary policy: it parses, fits its own
// scope, and speaks only the vocabulary of its own system. A library entry
// that did not would be a button that creates a policy the engine refuses.
func TestEveryReadyMadePolicyIsAValidPolicy(t *testing.T) {
	seen := map[string]bool{}
	perSystem := map[string]int{}
	for _, tpl := range Library() {
		if seen[tpl.Key] {
			t.Errorf("%s is listed twice", tpl.Key)
		}
		seen[tpl.Key] = true
		if tpl.Scope.OSFamily == "" {
			t.Errorf("%s: a ready-made policy is for one system", tpl.Key)
		}
		perSystem[tpl.Scope.OSFamily]++
		_, set, err := ParseBody(tpl.Title, []byte(tpl.Body))
		if err != nil {
			t.Errorf("%s: %v", tpl.Key, err)
			continue
		}
		if len(set.Config) == 0 {
			t.Errorf("%s: sets nothing", tpl.Key)
		}
		if err := checkConfig(tpl.Scope, set.Config); err != nil {
			t.Errorf("%s: %v", tpl.Key, err)
		}
		if tpl.Why == "" || !strings.HasPrefix(tpl.Title, strings.ToUpper(tpl.Scope.OSFamily[:1])+tpl.Scope.OSFamily[1:]+":") {
			t.Errorf("%s: needs a reason and a title that starts with its system", tpl.Key)
		}
	}
	if perSystem["android"] < 5 || perSystem["windows"] < 3 {
		t.Errorf("the library is thin: %v", perSystem)
	}
	// And Save accepts every one of them under its own scope.
	for _, tpl := range Library() {
		if _, set, _ := ParseBody(tpl.Key, []byte(tpl.Body)); checkConfig(tpl.Scope, set.Config) != nil {
			t.Errorf("%s would not save", tpl.Key)
		}
	}
}

func TestSettingsMustBelongToThePoliciesSystemAndKindOfDevice(t *testing.T) {
	body := func(s string) catalog.Values {
		_, set, err := ParseBody("x", []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return set.Config
	}
	cases := []struct {
		name  string
		scope Scope
		cfg   string
		ok    bool
	}{
		{"android on android", Scope{OSFamily: "android"}, `{"config":{"android.camera_disabled":true}}`, true},
		{"android on windows", Scope{OSFamily: "windows"}, `{"config":{"android.camera_disabled":true}}`, false},
		{"settings with no system named", Scope{}, `{"config":{"android.camera_disabled":true}}`, false},
		{"two systems in one policy", Scope{OSFamily: "android"}, `{"config":{"android.camera_disabled":true,"windows.camera_blocked":true}}`, false},
		{"company-only setting on a personal policy", Scope{OSFamily: "android", Ownership: "personal"}, `{"config":{"android.wallpaper_locked":true}}`, false},
		{"work-profile-only setting on a company policy", Scope{OSFamily: "android", Ownership: "company"}, `{"config":{"android.block_copy_to_personal":true}}`, false},
		{"work-profile setting on a personal policy", Scope{OSFamily: "android", Ownership: "personal"}, `{"config":{"android.block_copy_to_personal":true}}`, true},
		{"rules only, no system needed", Scope{}, `{"passcode_required":true}`, true},
	}
	for _, c := range cases {
		err := checkConfig(c.scope, body(c.cfg))
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v, got %v", c.name, c.ok, err)
		}
	}
}

func TestMergeConfigIsStrictAndDoesNotDependOnOrder(t *testing.T) {
	p1 := Policy{Name: "A", Config: catalog.Values{"android.password_min_length": 8, "android.camera_disabled": true}}
	p2 := Policy{Name: "B", Config: catalog.Values{"android.password_min_length": 12}}
	ab, ba := MergeConfig([]Policy{p1, p2}), MergeConfig([]Policy{p2, p1})
	for _, m := range []catalog.Values{ab, ba} {
		if m["android.password_min_length"] != 12 || m["android.camera_disabled"] != true {
			t.Fatalf("%v", m)
		}
	}
}
