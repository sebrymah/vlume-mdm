package console

import (
	"fmt"
	"strconv"
	"strings"

	"platform/internal/catalog"
	"platform/internal/policy"
)

// The guided policy editor: a form built from the catalogue for one
// operating system, so the person sees only what that system can do, grouped
// the way they would look for it, with the values the policy has now.

// PolicyForm is the editor for one policy.
type PolicyForm struct {
	OS        string
	OSName    string
	Name      string
	Ownership string
	// Editing fixes the name: saving writes a new version of the same policy.
	Editing  bool
	Sections []FormSection
	Rules    []FormRule
	// OnFailure and Remediate are the two behaviours beside the rules.
	OnFailure string
	Remediate bool
	// Note is what the page says before the first section: for Windows, that
	// nothing is delivered yet.
	Note string
	Why  string
}

// FormSection is a heading and the settings under it.
type FormSection struct {
	Name   string
	Fields []FormField
}

// FormField is one setting, with its current value ready to show.
type FormField struct {
	Key     string
	Input   string // the form field's name
	Label   string
	Help    string
	Unit    string
	Badge   string // which devices it reaches, when not all
	Note    string
	Kind    string // bool, int, choice, text, apps
	Checked bool
	Value   string // int, choice, text; and the apps as lines
	Min     int
	Max     int
	Options []catalog.Option
}

// FormRule is one thing the policy judges a device by.
type FormRule struct {
	Input   string
	Label   string
	Kind    string // bool, int, text
	Checked bool
	Value   string
	Unit    string
}

var osNames = map[string]string{"android": "Android", "windows": "Windows", "ios": "iOS", "ipados": "iPadOS", "macos": "macOS"}

// OSName is a system's name as a person writes it.
func OSName(os string) string {
	if n, ok := osNames[os]; ok {
		return n
	}
	return os
}

// The rules a device is judged by, in the order they are shown, with the
// systems each makes sense on. Android has no firewall to ask about; Windows
// has no jailbreak to ask about.
var formRules = []struct {
	kind  policy.Kind
	label string
	value string // "bool", "int", "text"
	unit  string
	skip  map[string]bool
}{
	{policy.PasscodeRequired, "A passcode must be set", "bool", "", nil},
	{policy.PasscodeMinLength, "The passcode is at least", "int", "characters", nil},
	{policy.DiskEncryptionRequired, "The disk must be encrypted", "bool", "", nil},
	{policy.ScreenLockTimeoutMax, "The screen locks within", "int", "seconds", nil},
	{policy.OSVersionMin, "The system is at least version", "text", "", nil},
	{policy.FirewallRequired, "The firewall must be on", "bool", "", map[string]bool{"android": true}},
	{policy.JailbreakBlocked, "The device must not be rooted or jailbroken", "bool", "", map[string]bool{"windows": true}},
}

// BuildPolicyForm makes the editor for one system, filled from a policy or a
// ready-made one.
func BuildPolicyForm(os, name string, scope policy.Scope, rules policy.Rules, set policy.Settings, why string, editing bool) *PolicyForm {
	f := &PolicyForm{OS: os, OSName: OSName(os), Name: name, Ownership: scope.Ownership, Editing: editing,
		OnFailure: set.OnFailure, Remediate: set.Remediate, Why: why}
	if f.OnFailure == "" {
		f.OnFailure = policy.FailNone
	}
	for _, sec := range catalog.Sections(os) {
		fs := FormSection{Name: sec.Name}
		for _, s := range sec.Settings {
			fs.Fields = append(fs.Fields, field(s, set.Config[s.Key]))
		}
		f.Sections = append(f.Sections, fs)
	}
	for _, r := range formRules {
		if r.skip[os] {
			continue
		}
		fr := FormRule{Input: "rule." + string(r.kind), Label: r.label, Kind: r.value, Unit: r.unit}
		if req, ok := rules[r.kind]; ok {
			switch r.value {
			case "bool":
				fr.Checked = req.Bool
			case "int":
				fr.Value = strconv.Itoa(req.Num)
			case "text":
				fr.Value = req.Text
			}
		}
		f.Rules = append(f.Rules, fr)
	}
	if os == "windows" {
		f.Note = "A Windows computer cannot be enrolled here yet. These settings are saved with the policy and will be sent to a Windows device when one can be enrolled; until then nothing is applied to anything."
	}
	return f
}

func field(s catalog.Setting, v any) FormField {
	f := FormField{Key: s.Key, Input: "cfg." + s.Key, Label: s.Label, Help: s.Help, Unit: s.Unit,
		Min: s.Min, Max: s.Max, Options: s.Options, Note: s.Note}
	switch s.For {
	case "company":
		f.Badge = "company phones only"
	case "personal":
		f.Badge = "personal phones (work profile) only"
	}
	switch s.Kind {
	case catalog.Bool:
		f.Kind = "bool"
		f.Checked, _ = v.(bool)
	case catalog.Int:
		f.Kind = "int"
		if n, ok := v.(int); ok {
			f.Value = strconv.Itoa(n)
		}
	case catalog.Choice:
		f.Kind = "choice"
		f.Value, _ = v.(string)
	case catalog.Text:
		f.Kind = "text"
		f.Value, _ = v.(string)
	case catalog.Apps:
		f.Kind = "apps"
		if list, ok := v.([]catalog.AppRule); ok {
			lines := make([]string, 0, len(list))
			for _, a := range list {
				lines = append(lines, a.Package+" "+a.Install)
			}
			f.Value = strings.Join(lines, "\n")
		}
	}
	return f
}

// ConfigLine is one setting a device is given, for the device page.
type ConfigLine struct {
	Section string
	Label   string
	Value   string
	From    string
}

// ConfigLines lists the merged settings a device is given, in catalogue
// order, each with the policies that asked for it.
func ConfigLines(os string, merged catalog.Values, who map[string][]string) []ConfigLine {
	var out []ConfigLine
	for _, s := range catalog.ForOS(os) {
		v, ok := merged[s.Key]
		if !ok {
			continue
		}
		// A switch that is off is not a setting. Listing "the camera is not
		// blocked" would be noise.
		if b, isBool := v.(bool); isBool && !b {
			continue
		}
		out = append(out, ConfigLine{Section: s.Section, Label: s.Label, Value: valueWords(s, v),
			From: strings.Join(who[s.Key], ", ")})
	}
	return out
}

func valueWords(s catalog.Setting, v any) string {
	if s.Kind == catalog.Apps {
		list := v.([]catalog.AppRule)
		parts := make([]string, 0, len(list))
		for _, a := range list {
			parts = append(parts, fmt.Sprintf("%s (%s)", a.Package, a.Install))
		}
		return strings.Join(parts, ", ")
	}
	if s.Kind == catalog.Bool {
		return "on"
	}
	return catalog.Describe(s, v)
}
