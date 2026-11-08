// Package catalog is the list of everything a policy can set on a device, one
// list for each operating system.
//
// A policy used to be one shape for every system with seven rules, which hid
// what each system can actually do: Android can lock the wallpaper and
// block USB, Windows can set BitLocker and Defender, and neither list is the
// other's. A policy now belongs to ONE system and offers that system's own
// settings, grouped in sections an administrator can read.
//
// Like the compliance rules, this is a FIXED catalogue, not an expression
// language. Every setting has a key, a type, a range, a plain sentence, a
// direction for "stricter" (so several policies merge the same way whatever
// order they come in), and, for Android, the exact field it becomes in
// Google's policy. A key nobody recognises is an error, not something to skip:
// a policy that says "camera_blocked" from memory would otherwise be saved,
// shown, and do nothing.
package catalog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind is the type of a setting's value.
type Kind int

const (
	Bool Kind = iota + 1
	Int
	Choice
	Text
	Apps
	// List is a list of short strings (email addresses, package names), one
	// per line in the editor. Max is the most it may hold and Check judges
	// each item.
	List
)

// Direction says which way "stricter" runs, so that two policies that
// disagree are settled the same way every time.
type Direction int

const (
	// Restrictive: a switch that is on beats one that is off.
	Restrictive Direction = iota + 1
	// Highest: a longer passcode, a later minimum.
	Highest
	// Lowest: a shorter lock time.
	Lowest
	// Strictest: the later option in the list is the stricter one.
	Strictest
	// FirstByName: no direction is stricter (a message), so the policy first
	// by name wins. Deterministic, and said so on the page.
	FirstByName
	// Combine: apps. The lists are joined; for one app the strictest
	// instruction wins (blocked, then required, then available).
	Combine
	// Union: a list where more is stricter or neutral (the accounts that may
	// recover a locked phone: every policy's are kept).
	Union
	// Intersect: an allow-list, where less is stricter. A service is allowed
	// only if every policy that has a list allows it.
	Intersect
)

// Option is one choice of a Choice setting.
type Option struct{ Value, Label string }

// Setting is one thing a policy can set.
type Setting struct {
	Key     string // "android.camera_disabled"
	OS      string // "android", "windows"
	Section string
	Label   string
	Help    string
	Kind    Kind
	Merge   Direction
	Min     int
	Max     int
	Unit    string
	Options []Option
	// For is which devices it reaches: "all", "company" (a fully managed
	// phone) or "personal" (the work profile on somebody's own phone).
	For string
	// Path is where it goes. For Android, the dotted path into Google's
	// policy; for Windows, the configuration service provider address the
	// Windows enrolment will send it to.
	Path string
	// Send turns the stored value into what Google is given. Android only.
	// Returning false means send nothing (a switch left off).
	Send func(v any) (any, bool)
	// Check refuses a text value that is the wrong shape.
	Check func(string) error
	// Note is what the Windows catalogue says until Windows can be enrolled.
	Note string
}

// AppRule is one app an Android policy has an instruction for.
type AppRule struct {
	Package string `json:"package"`
	// Install is "required" (pushed to the phone), "available" (offered in
	// the managed Play Store) or "blocked" (kept off).
	Install string `json:"install"`
}

var appInstall = map[string]int{"available": 1, "required": 2, "blocked": 3} // higher is stricter

// Values are the settings a policy sets, by key.
type Values map[string]any

var (
	ErrUnknown  = fmt.Errorf("catalog: unknown setting")
	ErrBadValue = fmt.Errorf("catalog: wrong value for setting")
)

var byKey = map[string]Setting{}
var order []Setting // catalogue order: section by section, the way the editor shows it

func add(ss ...Setting) {
	for _, s := range ss {
		if _, dup := byKey[s.Key]; dup {
			panic("catalog: duplicate setting " + s.Key)
		}
		if s.For == "" {
			s.For = "all"
		}
		byKey[s.Key] = s
		order = append(order, s)
	}
}

// Lookup finds a setting by key.
func Lookup(key string) (Setting, bool) { s, ok := byKey[key]; return s, ok }

// ForOS lists one system's settings in the order the editor shows them.
func ForOS(os string) []Setting {
	var out []Setting
	for _, s := range order {
		if s.OS == os {
			out = append(out, s)
		}
	}
	return out
}

// Section is a heading and its settings.
type Section struct {
	Name     string
	Settings []Setting
}

// Sections groups one system's settings by heading, in catalogue order.
func Sections(os string) []Section {
	var out []Section
	idx := map[string]int{}
	for _, s := range ForOS(os) {
		i, ok := idx[s.Section]
		if !ok {
			i = len(out)
			idx[s.Section] = i
			out = append(out, Section{Name: s.Section})
		}
		out[i].Settings = append(out[i].Settings, s)
	}
	return out
}

// Systems are the operating systems that have a catalogue.
func Systems() []string { return []string{"android", "windows"} }

var packageRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)

// MaxApps is the most apps one policy may carry. Google's limit is 3000.
const MaxApps = 500

// Parse reads and checks a policy's settings. raw is the "config" object of a
// policy body. Every key must be in the catalogue, every value of the right
// type and in range.
func Parse(raw map[string]json.RawMessage) (Values, error) {
	out := Values{}
	for key, rv := range raw {
		s, ok := byKey[key]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknown, key)
		}
		switch s.Kind {
		case Bool:
			var b bool
			if err := json.Unmarshal(rv, &b); err != nil {
				return nil, fmt.Errorf("%w: %s takes true or false", ErrBadValue, key)
			}
			out[key] = b
		case Int:
			var n int
			if err := json.Unmarshal(rv, &n); err != nil {
				return nil, fmt.Errorf("%w: %s takes a whole number", ErrBadValue, key)
			}
			if n < s.Min || n > s.Max {
				return nil, fmt.Errorf("%w: %s is between %d and %d", ErrBadValue, key, s.Min, s.Max)
			}
			out[key] = n
		case Choice:
			var v string
			if err := json.Unmarshal(rv, &v); err != nil {
				return nil, fmt.Errorf("%w: %s takes one of the listed choices", ErrBadValue, key)
			}
			okc := false
			for _, o := range s.Options {
				if o.Value == v {
					okc = true
				}
			}
			if !okc {
				return nil, fmt.Errorf("%w: %q is not a choice for %s", ErrBadValue, v, key)
			}
			out[key] = v
		case Text:
			var v string
			if err := json.Unmarshal(rv, &v); err != nil {
				return nil, fmt.Errorf("%w: %s takes text", ErrBadValue, key)
			}
			v = strings.TrimSpace(v)
			if len([]rune(v)) > 300 {
				return nil, fmt.Errorf("%w: %s is at most 300 characters", ErrBadValue, key)
			}
			for _, r := range v {
				if r < 0x20 || r == 0x7f {
					return nil, fmt.Errorf("%w: %s has a control character in it", ErrBadValue, key)
				}
			}
			if s.Check != nil && v != "" {
				if err := s.Check(v); err != nil {
					return nil, fmt.Errorf("%w: %s: %v", ErrBadValue, key, err)
				}
			}
			out[key] = v
		case List:
			var items []string
			if err := json.Unmarshal(rv, &items); err != nil {
				return nil, fmt.Errorf("%w: %s takes a list", ErrBadValue, key)
			}
			if len(items) > s.Max {
				return nil, fmt.Errorf("%w: %s holds at most %d entries", ErrBadValue, key, s.Max)
			}
			clean := make([]string, 0, len(items))
			seen := map[string]bool{}
			for _, it := range items {
				it = strings.TrimSpace(it)
				if it == "" || seen[it] {
					continue
				}
				if s.Check != nil {
					if err := s.Check(it); err != nil {
						return nil, fmt.Errorf("%w: %s: %q: %v", ErrBadValue, key, it, err)
					}
				}
				seen[it] = true
				clean = append(clean, it)
			}
			sort.Strings(clean)
			out[key] = clean
		case Apps:
			var list []AppRule
			if err := json.Unmarshal(rv, &list); err != nil {
				return nil, fmt.Errorf("%w: %s takes a list of apps", ErrBadValue, key)
			}
			if len(list) > MaxApps {
				return nil, fmt.Errorf("%w: %s lists more than %d apps", ErrBadValue, key, MaxApps)
			}
			seen := map[string]bool{}
			for i := range list {
				list[i].Package = strings.TrimSpace(list[i].Package)
				p := list[i].Package
				if !packageRE.MatchString(p) {
					return nil, fmt.Errorf("%w: %q is not an app's package name (like com.example.app)", ErrBadValue, p)
				}
				if _, ok := appInstall[list[i].Install]; !ok {
					return nil, fmt.Errorf("%w: %s must be required, available or blocked", ErrBadValue, p)
				}
				if seen[p] {
					return nil, fmt.Errorf("%w: %s is listed twice", ErrBadValue, p)
				}
				seen[p] = true
			}
			out[key] = list
		}
	}
	return out, nil
}

// SystemOf says which system a set of values belongs to. All the keys must
// agree; an empty set belongs to none.
func SystemOf(v Values) (string, error) {
	sys := ""
	for k := range v {
		s := byKey[k]
		if sys == "" {
			sys = s.OS
		} else if sys != s.OS {
			return "", fmt.Errorf("%w: a policy is for one system, but this one mixes %s and %s settings", ErrBadValue, sys, s.OS)
		}
	}
	return sys, nil
}

// Merge combines the settings of the policies that apply to one device. The
// sets are in a fixed order (by policy name) so the result never depends on
// the order the rows came back in.
func Merge(sets ...Values) Values {
	out := Values{}
	for _, set := range sets {
		for k, v := range set {
			held, seen := out[k]
			if !seen {
				out[k] = v
				continue
			}
			out[k] = stricter(byKey[k], held, v)
		}
	}
	return out
}

func stricter(s Setting, a, b any) any {
	switch s.Merge {
	case Restrictive:
		if bb, _ := b.(bool); bb {
			return b
		}
		return a
	case Highest:
		if b.(int) > a.(int) {
			return b
		}
		return a
	case Lowest:
		if b.(int) < a.(int) {
			return b
		}
		return a
	case Strictest:
		ai, bi := optionIndex(s, a.(string)), optionIndex(s, b.(string))
		if bi > ai {
			return b
		}
		return a
	case Combine:
		return combineApps(a.([]AppRule), b.([]AppRule))
	case Union:
		return mergeLists(a.([]string), b.([]string), true)
	case Intersect:
		return mergeLists(a.([]string), b.([]string), false)
	}
	return a // FirstByName: the one already held came from the earlier policy
}

// mergeLists joins two lists (union) or keeps what is in both (intersection),
// sorted, so the result never depends on which came first.
func mergeLists(a, b []string, union bool) []string {
	in := map[string]int{}
	for _, x := range a {
		in[x] |= 1
	}
	for _, x := range b {
		in[x] |= 2
	}
	out := make([]string, 0, len(in))
	for x, bits := range in {
		if union || bits == 3 {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func optionIndex(s Setting, v string) int {
	for i, o := range s.Options {
		if o.Value == v {
			return i
		}
	}
	return -1
}

func combineApps(a, b []AppRule) []AppRule {
	m := map[string]string{}
	for _, list := range [][]AppRule{a, b} {
		for _, r := range list {
			if cur, ok := m[r.Package]; !ok || appInstall[r.Install] > appInstall[cur] {
				m[r.Package] = r.Install
			}
		}
	}
	out := make([]AppRule, 0, len(m))
	for p, i := range m {
		out = append(out, AppRule{Package: p, Install: i})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

// Describe says a value the way it is shown to a person.
func Describe(s Setting, v any) string {
	switch s.Kind {
	case Bool:
		if b, _ := v.(bool); b {
			return "on"
		}
		return "off"
	case Int:
		return strconv.Itoa(v.(int)) + " " + s.Unit
	case Choice:
		for _, o := range s.Options {
			if o.Value == v.(string) {
				return o.Label
			}
		}
	case Text:
		return strconv.Quote(v.(string))
	case Apps:
		return fmt.Sprintf("%d app(s)", len(v.([]AppRule)))
	case List:
		return strings.Join(v.([]string), ", ")
	}
	return fmt.Sprint(v)
}
