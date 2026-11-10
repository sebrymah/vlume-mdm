package catalog

import (
	"fmt"
	"regexp"
	"strconv"
)

// Helpers for the settings that are not one switch sent to one field: the
// lock-screen features (three switches that make one list), the Wi-Fi
// allow-list, the update freeze, and the oldest Android a phone may run.
//
// Every field name and value used by these settings was checked against the
// Android Management API's own published description of its policy, not
// written from memory; the tests read the shapes back.

// NoWifiAllowed is what an allow-list of networks becomes when two policies
// each allow networks the other does not, so that nothing is allowed by both.
// Google refuses an empty allow-list, and leaving the list out would allow
// every network, which is the opposite of what both policies asked for. A name
// that no network will have gives the right answer: nothing connects.
const NoWifiAllowed = "vlume-no-network-allowed"

// ssidName judges one Wi-Fi network name: one to 32 characters, as Wi-Fi allows.
func ssidName(s string) error {
	if n := len(s); n < 1 || n > 32 {
		return fmt.Errorf("a Wi-Fi network name is 1 to 32 characters")
	}
	return nil
}

// wifiAllowList is sent as Google's allow-list of network names. It is never
// sent empty: see NoWifiAllowed.
func wifiAllowList(v any) (any, bool) {
	names, _ := v.([]string)
	if len(names) == 0 {
		names = []string{NoWifiAllowed}
	}
	ssids := make([]map[string]any, 0, len(names))
	for _, n := range names {
		ssids = append(ssids, map[string]any{"wifiSsid": n})
	}
	return map[string]any{"wifiSsidPolicyType": "WIFI_SSID_ALLOWLIST", "wifiSsids": ssids}, true
}

// --- update freeze --------------------------------------------------------
//
// A freeze is a yearly period in which the phone installs no system update,
// security patches included. Google's rules: each period is at most 90 days,
// and two periods must be at least 60 days apart. Both are checked here, with
// a margin, so Google never has to refuse a policy that was saved. Leap years
// are ignored, as Google ignores them, and 29 February is refused so nobody
// is surprised by which day it means.

var freezeRE = regexp.MustCompile(`^(\d{2})-(\d{2}) to (\d{2})-(\d{2})$`)

// monthDays are the days of each month in a year that is not a leap year.
var monthDays = [13]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

const (
	// FreezeMaxDays is the longest a freeze may last.
	FreezeMaxDays = 90
	// FreezeMinGap is the fewest free days between two freezes. Google asks
	// for 60; counting free days, not the difference of the dates, is the
	// stricter reading, so it is the one used.
	FreezeMinGap = 60
	// MaxFreezes is how many a policy may hold.
	MaxFreezes = 2
)

type freezeSpan struct{ sm, sd, em, ed, start, end, days int }

func dayOfYear(m, d int) int {
	n := d
	for i := 1; i < m; i++ {
		n += monthDays[i]
	}
	return n
}

func parseFreeze(s string) (freezeSpan, error) {
	g := freezeRE.FindStringSubmatch(s)
	if g == nil {
		return freezeSpan{}, fmt.Errorf("write a period as month-day to month-day, like 10-20 to 12-31")
	}
	var v [4]int
	for i := range v {
		v[i], _ = strconv.Atoi(g[i+1])
	}
	for _, p := range [][2]int{{v[0], v[1]}, {v[2], v[3]}} {
		if p[0] < 1 || p[0] > 12 || p[1] < 1 || p[1] > monthDays[p[0]] {
			if p[0] == 2 && p[1] == 29 {
				return freezeSpan{}, fmt.Errorf("29 February cannot be used; use 28 February")
			}
			return freezeSpan{}, fmt.Errorf("%02d-%02d is not a date", p[0], p[1])
		}
	}
	f := freezeSpan{sm: v[0], sd: v[1], em: v[2], ed: v[3]}
	f.start, f.end = dayOfYear(v[0], v[1]), dayOfYear(v[2], v[3])
	f.days = f.end - f.start + 1
	if f.days <= 0 { // it wraps over the new year
		f.days += 365
	}
	if f.days > FreezeMaxDays {
		return freezeSpan{}, fmt.Errorf("a freeze lasts at most %d days; this one is %d", FreezeMaxDays, f.days)
	}
	return f, nil
}

// freezeEach judges one period on its own.
func freezeEach(s string) error { _, err := parseFreeze(s); return err }

// freezeTogether judges the periods as a set: not too many, and none too
// close to the next, counting round the year end.
func freezeTogether(list []string) error {
	if len(list) > MaxFreezes {
		return fmt.Errorf("at most %d freezes", MaxFreezes)
	}
	spans := make([]freezeSpan, 0, len(list))
	for _, s := range list {
		f, err := parseFreeze(s)
		if err != nil {
			return err
		}
		spans = append(spans, f)
	}
	for i := range spans {
		for j := range spans {
			if i == j {
				continue
			}
			// Free days from the end of i to the start of j, going forward.
			gap := spans[j].start - spans[i].end - 1
			for gap < 0 {
				gap += 365
			}
			if gap < FreezeMinGap {
				return fmt.Errorf("two freezes must be at least %d days apart", FreezeMinGap)
			}
		}
	}
	return nil
}

// freezePeriods is sent as Google's list of yearly periods.
func freezePeriods(v any) (any, bool) {
	list, _ := v.([]string)
	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		f, err := parseFreeze(s)
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"startDate": map[string]any{"month": f.sm, "day": f.sd},
			"endDate":   map[string]any{"month": f.em, "day": f.ed},
		})
	}
	return out, len(out) > 0
}

// minimumAPILevel turns the Android version a person chose into the number
// Google's policy takes.
func minimumAPILevel(v any) (any, bool) {
	s, _ := v.(string)
	n, err := strconv.Atoi(s)
	return n, err == nil && n > 0
}
