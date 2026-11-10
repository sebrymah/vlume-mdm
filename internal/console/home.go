package console

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/data"
	"platform/internal/policy"
)

// This file holds what the friendlier Home, Devices and side-panel pages
// need that the older pages did not: counts turned into plain sentences, a
// ring drawn from them, a device list that can be narrowed, and one device
// explained in words.
//
// Nothing here reads a tenant id. Every function takes the transaction the
// handler already holds, so row-level security decides what is visible, the
// same as everywhere else in the console.

// Need is one card under "Needs you today". A card exists only when there is
// something behind it: an empty fleet and a healthy one both get the calm
// card instead, never a row of zeros.
type Need struct {
	Tone   string // "warn", "bad", "info" or "ok": the pill classes in partials.html
	Title  string
	Detail string
	Href   string
	Button string
}

// RingSeg is one arc of the fleet ring. Dash and Offset are already worked
// out so the template only places them.
type RingSeg struct {
	Colour string
	Dash   string
	Offset string
}

// LegendRow is one line beside the ring, and a link to the devices it counts.
type LegendRow struct {
	Colour string
	Label  string
	Hint   string
	Href   string
	N      int
}

// Recent is one line of "what happened lately".
type Recent struct {
	Who  string
	What string
	When string
}

// Home is the dashboard's own data.
type Home struct {
	Needs   []Need
	Ring    []RingSeg
	Legend  []LegendRow
	Percent int
	Recent  []Recent
}

// Brand-independent state colours. They are fixed because they carry meaning
// (green is fine, red is failing) and a tenant's brand colour must never be
// able to turn one into the other.
const (
	colCompliant = "#1B7A47"
	colFailing   = "#C9382F"
	colQuiet     = "#D68A12"
	colHeld      = "#5B6764"
	colNever     = "#B9C4C1"
)

const ringCircumference = 339.292 // 2 * pi * 54, the radius the template draws

// BuildHome turns the counts into what the page shows. pending is how many
// requests wait on this person, or -1 when this role cannot approve anything
// and so should not be told about a queue it cannot touch.
func BuildHome(c data.StateCounts, pending int, audit []data.AuditEvent, now time.Time) *Home {
	h := &Home{}

	if c.Total > 0 {
		h.Percent = sharePercent(c.Compliant, c.Total)
	}

	// The ring, in the same order as the legend.
	type arc struct {
		n   int
		col string
	}
	arcs := []arc{
		{c.Compliant, colCompliant}, {c.NotCompliant, colFailing}, {c.StateUnknown, colQuiet},
		{c.Quarantined, colHeld}, {c.AwaitingFirst, colNever},
	}
	if c.Total > 0 {
		cum := 0.0
		for _, a := range arcs {
			if a.n == 0 {
				continue
			}
			length := float64(a.n) / float64(c.Total) * ringCircumference
			// A hairline gap between arcs reads as separate groups. It is
			// taken from the arc, never added, so the arcs still sum to the
			// whole circle.
			drawn := length
			if len(arcs) > 1 && length > 3 {
				drawn = length - 1.5
			}
			h.Ring = append(h.Ring, RingSeg{
				Colour: a.col,
				Dash:   fmt.Sprintf("%.1f", drawn),
				Offset: fmt.Sprintf("%.1f", -cum),
			})
			cum += length
		}
	}

	h.Legend = []LegendRow{
		{colCompliant, "Compliant", "", "/devices", c.Compliant},
		{colFailing, "Not compliant", "a rule is failing", "/devices?show=attention", c.NotCompliant},
		{colQuiet, "Gone quiet", "no report in 24 hours", "/devices?show=quiet", c.StateUnknown},
		{colHeld, "Quarantined", "work access removed", "/devices?show=attention", c.Quarantined},
		{colNever, "Never reported", "", "/devices?show=quiet", c.AwaitingFirst},
	}

	if pending > 0 {
		h.Needs = append(h.Needs, Need{
			Tone: "info", Title: plural(pending, "request needs", "requests need") + " your approval",
			Detail: "Something is waiting for a second person. It does nothing until someone decides.",
			Href:   "/approvals", Button: "Review requests",
		})
	}
	if c.NotCompliant+c.Quarantined > 0 {
		n := c.NotCompliant + c.Quarantined
		h.Needs = append(h.Needs, Need{
			Tone: "bad", Title: plural(n, "device needs", "devices need") + " attention",
			Detail: "A rule is failing, or work access has been removed until it is put right.",
			Href:   "/devices?show=attention", Button: "See which",
		})
	}
	if q := c.StateUnknown + c.AwaitingFirst; q > 0 {
		h.Needs = append(h.Needs, Need{
			Tone: "warn", Title: plural(q, "device has", "devices have") + " gone quiet",
			Detail: "No report lately. Most are switched off, out of signal, or never finished setting up.",
			Href:   "/devices?show=quiet", Button: "See which",
		})
	}
	if len(h.Needs) == 0 {
		detail := "Every device that has reported is meeting what is asked of it."
		if c.Total == 0 {
			detail = "No devices are enrolled yet. Make an invite and the first one will show up here."
		}
		h.Needs = append(h.Needs, Need{Tone: "ok", Title: "Nothing needs you right now", Detail: detail})
	}

	for _, e := range audit {
		h.Recent = append(h.Recent, Recent{
			Who:  e.Actor,
			What: words(e.Action) + refSuffix(e.ObjectRef),
			When: agoTime(now, e.OccurredAt),
		})
	}
	return h
}

// sharePercent rounds to the nearest whole number, but never says 100 unless
// every device is in the share, and never says 0 while one is. A fleet that is
// 99.6% compliant is not "all clear", and a headline number is the one place
// that mistake would be believed.
func sharePercent(n, total int) int {
	if total <= 0 || n <= 0 {
		return 0
	}
	if n >= total {
		return 100
	}
	p := (n*100 + total/2) / total
	if p >= 100 {
		p = 99
	}
	if p < 1 {
		p = 1
	}
	return p
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// words makes an audit action readable without pretending to know every one
// of them: "device.lock_requested" becomes "device lock requested".
func words(action string) string {
	r := strings.NewReplacer(".", " ", "_", " ", ":", " ")
	return strings.TrimSpace(r.Replace(action))
}

func refSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return ", " + ref
}

// agoTime is "4 min ago" style, for a moment that has definitely happened.
func agoTime(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// ago is agoTime for a device that may never have reported.
func ago(now time.Time, t *time.Time) string {
	if t == nil {
		return "never"
	}
	return agoTime(now, *t)
}

// ---- the devices page ----

// DeviceRow is one device as a row: everything the list shows, already in
// words, so the template carries no logic about what a state means.
type DeviceRow struct {
	ID      uuid.UUID
	Name    string
	Holder  string
	System  string
	Pill    string // a class from partials.html
	Label   string
	Seen    string
	Initial string
}

// Chip is one filter above the list.
type Chip struct {
	Label  string
	Href   string
	N      int
	Active bool
}

func stateWords(state string) (pill, label string) {
	switch state {
	case "compliant":
		return "ok", "Compliant"
	case "not_compliant":
		return "bad", "Not compliant"
	case "state_unknown":
		return "warn", "Gone quiet"
	case "quarantined":
		return "mute", "Quarantined"
	case "awaiting_first_boot":
		return "mute", "Never reported"
	case "retired":
		return "mute", "Retired"
	}
	return "mute", state
}

func needsAttention(state string) bool { return state == "not_compliant" || state == "quarantined" }
func isQuiet(state string) bool        { return state == "state_unknown" || state == "awaiting_first_boot" }

// matches says whether a device belongs under a filter. A filter that is not
// one of the named groups is read as an operating system, compared as text,
// so an unknown value narrows to nothing rather than to everything.
func matches(d data.Device, show string) bool {
	switch show {
	case "", "all":
		return true
	case "attention":
		return needsAttention(d.State)
	case "quiet":
		return isQuiet(d.State)
	}
	return strings.EqualFold(d.OSFamily, show)
}

func initials(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "?"
	}
	if i := strings.IndexByte(s, '@'); i > 0 {
		s = s[:i]
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '.' || r == '_' || r == '-' })
	out := ""
	for _, p := range parts {
		if len(out) >= 2 {
			break
		}
		out += strings.ToUpper(string([]rune(p)[:1]))
	}
	if out == "" {
		return "?"
	}
	return out
}

func containsFold(hay, needle string) bool {
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

func osLabel(family, ownership string) string {
	f := family
	if f != "" {
		f = strings.ToUpper(f[:1]) + f[1:]
	}
	if ownership == "" {
		return f
	}
	return f + ", " + ownership
}

// BuildDeviceList narrows the list by a filter and a search, and counts every
// filter over the WHOLE list so the chips stay true while one is chosen.
func BuildDeviceList(all []data.Device, show, q string, now time.Time) (rows []DeviceRow, chips []Chip) {
	q = strings.TrimSpace(q)
	show = strings.ToLower(strings.TrimSpace(show))
	if show == "all" {
		show = ""
	}

	counts := map[string]int{}
	var order []string // operating systems, in the order first met
	attention, quiet := 0, 0
	for _, d := range all {
		if needsAttention(d.State) {
			attention++
		}
		if isQuiet(d.State) {
			quiet++
		}
		k := strings.ToLower(d.OSFamily)
		if k == "" {
			continue
		}
		if _, seen := counts[k]; !seen {
			order = append(order, k)
		}
		counts[k]++
	}

	for _, d := range all {
		if !matches(d, show) {
			continue
		}
		if q != "" && !containsFold(d.Name, q) && !containsFold(d.AssignedTo, q) && !containsFold(d.Serial, q) {
			continue
		}
		pill, label := stateWords(d.State)
		holder := d.AssignedTo
		who := holder
		if holder == "" {
			holder = "Not held by anyone"
			who = ""
		}
		rows = append(rows, DeviceRow{
			ID: d.ID, Name: d.Name, Holder: holder, System: osLabel(d.OSFamily, d.Ownership),
			Pill: pill, Label: label, Seen: ago(now, d.LastReportAt), Initial: initials(who),
		})
	}

	chips = append(chips,
		Chip{Label: "All", Href: "/devices", N: len(all), Active: show == ""},
		Chip{Label: "Needs attention", Href: "/devices?show=attention", N: attention, Active: show == "attention"},
		Chip{Label: "Gone quiet", Href: "/devices?show=quiet", N: quiet, Active: show == "quiet"},
	)
	for _, k := range order {
		name := strings.ToUpper(k[:1]) + k[1:]
		chips = append(chips, Chip{Label: name, Href: "/devices?show=" + k, N: counts[k], Active: show == k})
	}
	return rows, chips
}

// ---- the side panel ----

// Explain says what is going on with one device in a sentence or two, and
// how serious it is. It never claims a pass it was not told: a device with no
// verdict is "quiet", not "fine".
func Explain(d data.Device, c *policy.Compliance) (tone, text string) {
	switch d.State {
	case "compliant":
		return "ok", "Everything checked passes."
	case "quarantined":
		why := "Work access was removed."
		if d.QuarantineReason != "" {
			why = "Work access was removed: " + d.QuarantineReason + "."
		}
		return "mute", why + " It stays this way until a person releases it."
	case "awaiting_first_boot":
		return "mute", "Enrolled, but it has not sent a first report yet. Check that it has data or Wi-Fi."
	case "state_unknown":
		return "warn", "No report lately, so we cannot say how it is doing. It may be switched off or out of signal."
	case "not_compliant":
		if c != nil && len(c.Findings) > 0 {
			var parts []string
			for i, f := range c.Findings {
				if i == 3 {
					parts = append(parts, fmt.Sprintf("and %d more", len(c.Findings)-3))
					break
				}
				parts = append(parts, f.Rule)
			}
			return "bad", "Not meeting: " + strings.Join(parts, "; ") + "."
		}
		return "bad", "A rule is failing."
	}
	return "mute", ""
}

// PanelLoad reads what the side panel shows. It is its own small read rather
// than the whole device page's, because the panel is opened often.
func PanelLoad(ctx context.Context, tx *data.Tx, id uuid.UUID, now time.Time) (*data.Device, *policy.Compliance, error) {
	d, err := data.GetDevice(ctx, tx, id)
	if err != nil {
		// Another tenant's device is indistinguishable from one that does
		// not exist. The caller turns this into a plain 404.
		return nil, nil, nil
	}
	c, found, err := policy.Of(ctx, tx, id, now)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return &d, nil, nil
	}
	return &d, &c, nil
}
