package console

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/data"
	"platform/internal/policy"
)

func dev(name, os, own, state string) data.Device {
	return data.Device{ID: uuid.New(), Name: name, OSFamily: os, Ownership: own, State: state}
}

func TestReachCountsOnlyTheSystemAndNeverARetiredDevice(t *testing.T) {
	ds := []data.Device{
		dev("a", "android", "company", "compliant"),
		dev("b", "Android", "personal", "not_compliant"), // case does not matter
		dev("c", "android", "company", "retired"),        // gone
		dev("d", "windows", "company", "compliant"),      // another system
	}
	r := ReachOf(ds, "android")
	if r.Any != 2 || r.Company != 1 || r.Personal != 1 {
		t.Fatalf("reach = %+v, want 2 / 1 / 1", r)
	}
	if got := ReachOf(ds, "macos"); got.Any != 0 {
		t.Fatalf("a system nobody has reaches %d devices", got.Any)
	}
}

func TestEveryInviteStatusHasItsOwnColour(t *testing.T) {
	want := map[string]string{
		"enrolled": "ok", "revoked": "mute", "expired": "warn", "waiting for the device": "info",
	}
	for status, pill := range want {
		if got := statusPill(status); got != pill {
			t.Errorf("%q is %q, want %q", status, got, pill)
		}
	}
	// An invite that has joined must never look the same as one still waiting.
	if statusPill("enrolled") == statusPill("waiting for the device") {
		t.Fatal("a joined invite looks like a waiting one")
	}
}

func TestTheRingAddsUpToTheWholeCircle(t *testing.T) {
	c := data.StateCounts{Total: 148, Compliant: 127, NotCompliant: 9, StateUnknown: 6, Quarantined: 2, AwaitingFirst: 4}
	h := BuildHome(c, -1, nil, time.Now())
	if h.Percent != 86 {
		t.Fatalf("percent = %d, want 86", h.Percent)
	}
	if len(h.Ring) != 5 {
		t.Fatalf("%d arcs, want 5", len(h.Ring))
	}
	// Arc i starts where arc i-1 ended, and the last one ends at the circle.
	var prevEnd float64
	for i, a := range h.Ring {
		dash, _ := strconv.ParseFloat(a.Dash, 64)
		off, _ := strconv.ParseFloat(a.Offset, 64)
		if math.Abs(-off-prevEnd) > 0.2 {
			t.Fatalf("arc %d starts at %.1f, previous ended at %.1f", i, -off, prevEnd)
		}
		prevEnd = -off + dash + 1.5 // the gap taken from each arc
	}
	if math.Abs(prevEnd-ringCircumference) > 1 {
		t.Fatalf("the arcs end at %.1f, the circle is %.1f", prevEnd, ringCircumference)
	}
}

func TestAnEmptyFleetGetsNoRingAndANextStep(t *testing.T) {
	h := BuildHome(data.StateCounts{}, -1, nil, time.Now())
	if len(h.Ring) != 0 || h.Percent != 0 {
		t.Fatal("an empty fleet has a ring")
	}
	if len(h.Needs) != 1 || !strings.Contains(h.Needs[0].Detail, "No devices are enrolled yet") {
		t.Fatalf("an empty fleet is not told what to do: %+v", h.Needs)
	}
}

func TestACardForTheQueueOnlyWhenThereIsOneAndOnlyWhenAsked(t *testing.T) {
	c := data.StateCounts{Total: 3, Compliant: 3}
	if h := BuildHome(c, -1, nil, time.Now()); strings.Contains(h.Needs[0].Title, "request") {
		t.Fatal("a role that cannot approve was told about requests")
	}
	if h := BuildHome(c, 0, nil, time.Now()); strings.Contains(h.Needs[0].Title, "request") {
		t.Fatal("an empty queue got a card")
	}
	h := BuildHome(c, 2, nil, time.Now())
	if h.Needs[0].Title != "2 requests need your approval" {
		t.Fatalf("title = %q", h.Needs[0].Title)
	}
	if h := BuildHome(c, 1, nil, time.Now()); h.Needs[0].Title != "1 request needs your approval" {
		t.Fatalf("title = %q", h.Needs[0].Title)
	}
}

func TestExplainNeverCallsASilentDeviceFine(t *testing.T) {
	if tone, _ := Explain(dev("x", "android", "company", "state_unknown"), nil); tone == "ok" {
		t.Fatal("a device nobody has heard from is explained as fine")
	}
	if tone, _ := Explain(dev("x", "android", "company", "awaiting_first_boot"), nil); tone == "ok" {
		t.Fatal("a device that never reported is explained as fine")
	}
	c := &policy.Compliance{Findings: []policy.Finding{{Rule: "a screen lock"}, {Rule: "encryption"}}}
	_, why := Explain(dev("x", "android", "company", "not_compliant"), c)
	if !strings.Contains(why, "a screen lock") || !strings.Contains(why, "encryption") {
		t.Fatalf("the failing rules are not named: %q", why)
	}
}

func TestTheHeadlinePercentNeverRoundsToAllClearOrNone(t *testing.T) {
	cases := []struct{ n, total, want int }{
		{127, 148, 86}, {0, 10, 0}, {10, 10, 100}, {1, 10, 10},
		{996, 1000, 99}, // 99.6 is not "all compliant"
		{1, 1000, 1},    // 0.1 is not "none compliant"
		{0, 0, 0},
	}
	for _, c := range cases {
		if got := sharePercent(c.n, c.total); got != c.want {
			t.Errorf("%d of %d = %d, want %d", c.n, c.total, got, c.want)
		}
	}
}
