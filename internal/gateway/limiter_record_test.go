package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// R1 says the bulk-wipe limiter pauses the queue AND records the attempt.
// internal/command does write the refusal row and audit it, and the unit
// test for it passes, because that test holds its own transaction open.
//
// Over HTTP it did not survive. Request returns ErrLimiterTripped, the
// handler returned that error out of WithTenant, and the transaction rolled
// back, taking the refusal record and its audit entry with it. The platform
// believed it had recorded something it had not, which is the same family of
// defect as the console line claiming the Security Manager had been told.
func TestTheLimitersRefusalSurvivesTheRequestThatCausedIt(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	wipe := func() int {
		rec, _ := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-super",
			url.Values{"reason": {"a drill"}, "scope": {"all"}}))
		return rec.Code
	}

	// Trip it. The limiter allows ten full wipes by one admin in the window.
	tripped := false
	for i := 0; i < 14; i++ {
		if wipe() == http.StatusTooManyRequests {
			tripped = true
			break
		}
	}
	if !tripped {
		t.Fatal("the limiter never tripped")
	}

	// The refusal has to be in the tenant's own record afterwards.
	_, body := do(t, f, req(t, "GET", hostA, "/api/audit", "a-auditor"))
	events := ""
	for _, e := range body["events"].([]any) {
		events += e.(map[string]any)["action"].(string) + " "
	}
	if !strings.Contains(events, "command.refused.limiter") {
		t.Fatalf("the limiter's refusal was rolled back with the request: %s", events)
	}

	// And the refused command itself, so an investigator can see what was
	// asked for and by whom.
	_, cmds := do(t, f, req(t, "GET", hostA, "/api/commands", "a-itadmin"))
	refused := 0
	for _, c := range cmds["commands"].([]any) {
		if c.(map[string]any)["state"] == "refused" {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("no refused command was kept")
	}
}
