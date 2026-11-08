package catalog

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func raw(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Every setting is built the same way, so a new one cannot be added half
// done: a type that fits its merge direction, a range, a sentence, and a
// place it goes.
func TestEverySettingIsWellFormed(t *testing.T) {
	for _, os := range Systems() {
		list := ForOS(os)
		if len(list) < 20 {
			t.Errorf("%s has only %d settings", os, len(list))
		}
		for _, s := range list {
			if !strings.HasPrefix(s.Key, os+".") {
				t.Errorf("%s: the key does not start with %q", s.Key, os+".")
			}
			if s.Label == "" || s.Section == "" || s.Path == "" {
				t.Errorf("%s: needs a label, a section and a path", s.Key)
			}
			switch s.Kind {
			case Bool:
				if s.Merge != Restrictive {
					t.Errorf("%s: a switch merges restrictively", s.Key)
				}
			case Int:
				if s.Min >= s.Max || s.Unit == "" || (s.Merge != Highest && s.Merge != Lowest) {
					t.Errorf("%s: a number needs a range, a unit and a direction", s.Key)
				}
			case Choice:
				if len(s.Options) < 2 || s.Merge != Strictest {
					t.Errorf("%s: a choice needs options and an order of strictness", s.Key)
				}
			case Text:
				if s.Merge != FirstByName {
					t.Errorf("%s: text has no stricter direction", s.Key)
				}
			case Apps:
				if s.Merge != Combine {
					t.Errorf("%s: apps combine", s.Key)
				}
			default:
				t.Errorf("%s: no type", s.Key)
			}
			switch os {
			case "android":
				// Apps are built into the policy's list, not sent as one value.
				if s.Send == nil && s.Kind != Apps {
					t.Errorf("%s: an Android setting must say how it is sent", s.Key)
				}
			case "windows":
				if !strings.HasPrefix(s.Path, "./Device/Vendor/MSFT/") || s.Note == "" {
					t.Errorf("%s: a Windows setting needs its CSP address and the note that it is not delivered yet", s.Key)
				}
			}
			if s.For != "all" && s.For != "company" && s.For != "personal" {
				t.Errorf("%s: For is all, company or personal", s.Key)
			}
		}
		if len(Sections(os)) < 4 {
			t.Errorf("%s has fewer than four sections", os)
		}
	}
}

func TestAnUnknownSettingIsRefused(t *testing.T) {
	for _, body := range []string{
		`{"android.camera_blocked": true}`, // the right one is android.camera_disabled
		`{"camera_disabled": true}`,
		`{"windows.nope": 1}`,
	} {
		if _, err := Parse(raw(t, body)); err == nil || !strings.Contains(err.Error(), "unknown setting") {
			t.Errorf("%s: %v", body, err)
		}
	}
}

func TestValuesAreCheckedForTypeAndRange(t *testing.T) {
	bad := []string{
		`{"android.camera_disabled": "yes"}`,
		`{"android.password_min_length": 3}`,
		`{"android.password_min_length": 65}`,
		`{"android.password_min_length": "8"}`,
		`{"android.password_quality": "STRONG"}`,
		`{"android.always_on_vpn_app": "not a package"}`,
		`{"android.short_message": "line one\nline two"}`,
		`{"windows.desktop_background_url": "http://insecure.example/a.png"}`,
		`{"windows.desktop_background_url": "https://example.com/a b.png"}`,
		`{"android.apps": [{"package": "com.example.a", "install": "sometimes"}]}`,
		`{"android.apps": [{"package": "x", "install": "required"}]}`,
		`{"android.apps": [{"package": "com.example.a", "install": "required"}, {"package": "com.example.a", "install": "blocked"}]}`,
	}
	for _, b := range bad {
		if _, err := Parse(raw(t, b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	good := `{"android.camera_disabled": true, "android.password_min_length": 8,
		"android.password_quality": "NUMERIC", "android.screen_lock_seconds": 120,
		"android.always_on_vpn_app": "com.example.vpn", "android.short_message": "Call IT",
		"android.apps": [{"package": "com.example.crm", "install": "required"}],
		"windows.desktop_background_url": "https://example.com/bg.png"}`
	if v, err := Parse(raw(t, good)); err != nil || len(v) != 8 {
		t.Fatalf("a good body was refused: %v (%d)", err, len(v))
	}
}

func TestAPolicyIsForOneSystem(t *testing.T) {
	v, _ := Parse(raw(t, `{"android.camera_disabled": true, "windows.camera_blocked": true}`))
	if _, err := SystemOf(v); err == nil {
		t.Fatal("a policy that mixes Android and Windows settings was accepted")
	}
	v, _ = Parse(raw(t, `{"windows.camera_blocked": true}`))
	if os, err := SystemOf(v); err != nil || os != "windows" {
		t.Fatalf("%q %v", os, err)
	}
}

func TestMergeTakesTheStricterAndDoesNotDependOnOrder(t *testing.T) {
	a := Values{"android.camera_disabled": true, "android.password_min_length": 8, "android.screen_lock_seconds": 300,
		"android.password_quality": "NUMERIC", "android.short_message": "A",
		"android.apps": []AppRule{{"com.example.a", "available"}, {"com.example.b", "required"}}}
	b := Values{"android.camera_disabled": false, "android.password_min_length": 12, "android.screen_lock_seconds": 120,
		"android.password_quality": "SOMETHING", "android.short_message": "B",
		"android.apps": []AppRule{{"com.example.a", "blocked"}, {"com.example.c", "available"}}}
	ab, ba := Merge(a, b), Merge(b, a)

	want := func(m Values, key string, v any) {
		t.Helper()
		if !reflect.DeepEqual(m[key], v) {
			t.Errorf("%s: got %v, want %v", key, m[key], v)
		}
	}
	for _, m := range []Values{ab, ba} {
		want(m, "android.camera_disabled", true)
		want(m, "android.password_min_length", 12)
		want(m, "android.screen_lock_seconds", 120)
		want(m, "android.password_quality", "NUMERIC")
		want(m, "android.apps", []AppRule{{"com.example.a", "blocked"}, {"com.example.b", "required"}, {"com.example.c", "available"}})
	}
	// A message has no stricter side: the earlier policy wins, and the caller
	// orders them by name, so the answer is the same every time.
	want(ab, "android.short_message", "A")
}

func TestDescribeSaysItInWords(t *testing.T) {
	s, _ := Lookup("android.screen_lock_seconds")
	if got := Describe(s, 120); got != "120 seconds" {
		t.Fatal(got)
	}
	s, _ = Lookup("android.password_quality")
	if got := Describe(s, "NUMERIC"); got != "A numeric PIN" {
		t.Fatal(got)
	}
}
