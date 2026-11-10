package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The friendlier Home, the narrowed Devices list, the side panel and the
// erase-everything confirmation. Each of these has a rule worth a test: Home
// must say what needs a person and only to the people who can act on it, the
// list must narrow and never widen, the panel must not cross a tenant, and a
// wrong name must not start a wipe.

func TestHomeSaysWhatNeedsAttentionAndLinksToIt(t *testing.T) {
	f := newFixture(t)
	mbp, win := f.devices[tenantA][0], f.devices[tenantA][1]
	exec(t, `UPDATE devices SET state = 'compliant', last_report_at = now() WHERE id = $1`, mbp)
	exec(t, `UPDATE devices SET state = 'not_compliant', last_report_at = now() WHERE id = $1`, win)

	_, page := getHTML(t, f, hostA, "/", "a-itadmin")
	if !strings.Contains(page, "1 device needs attention") {
		t.Fatalf("Home does not say that one device needs attention:\n%s", page)
	}
	if !strings.Contains(page, `href="/devices?show=attention"`) {
		t.Fatal("the attention card does not lead to the devices that need it")
	}
	if !strings.Contains(page, "stroke-dasharray") || !strings.Contains(page, "50%") {
		t.Fatal("the fleet ring is missing, or does not say half the fleet is compliant")
	}
	if strings.Contains(page, "Nothing needs you right now") {
		t.Fatal("Home says all is calm while a device is failing")
	}
}

func TestHomeIsCalmOnlyWhenEverythingIsFine(t *testing.T) {
	f := newFixture(t)
	for _, id := range f.devices[tenantA] {
		exec(t, `UPDATE devices SET state = 'compliant', last_report_at = now() WHERE id = $1`, id)
	}
	_, page := getHTML(t, f, hostA, "/", "a-itadmin")
	if !strings.Contains(page, "Nothing needs you right now") {
		t.Fatal("a healthy fleet does not get the calm card")
	}
	if strings.Contains(page, "need attention") || strings.Contains(page, "gone quiet") {
		t.Fatal("a healthy fleet is being told something needs attention")
	}

	// A device nobody has heard from is not "fine".
	exec(t, `UPDATE devices SET state = 'state_unknown' WHERE id = $1`, f.devices[tenantA][0])
	_, page = getHTML(t, f, hostA, "/", "a-itadmin")
	if strings.Contains(page, "Nothing needs you right now") || !strings.Contains(page, "gone quiet") {
		t.Fatal("a silent device is being counted as fine")
	}
}

func TestOnlyWhoCanApproveIsToldAboutTheQueue(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	rec, _ := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"scope": {"all"}, "reason": {"stolen"}}))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("could not raise a wipe: %d", rec.Code)
	}

	_, sec := getHTML(t, f, hostA, "/", "a-secmgr")
	if !strings.Contains(sec, "1 request needs your approval") || !strings.Contains(sec, `href="/approvals"`) {
		t.Fatalf("someone who can approve is not told a request is waiting:\n%s", sec)
	}
	_, help := getHTML(t, f, hostA, "/", "a-helpdesk")
	if strings.Contains(help, "approval") {
		t.Fatal("someone who cannot approve is told about the approvals queue")
	}
}

func TestHomeCountsOnlyTheTenantsOwnDevices(t *testing.T) {
	f := newFixture(t)
	_, a := getHTML(t, f, hostA, "/", "a-itadmin")
	_, b := getHTML(t, f, hostB, "/", "b-itadmin")
	if !strings.Contains(a, "2 devices enrolled") || !strings.Contains(b, "3 devices enrolled") {
		t.Fatal("a tenant's Home does not count its own devices")
	}
}

// ---------------------------------------------------------------- the list

func rowsIn(page string) int { return strings.Count(page, `href="/devices/`) }

func TestTheDeviceListNarrowsAndNeverWidens(t *testing.T) {
	f := newFixture(t)
	mbp, win := f.devices[tenantA][0], f.devices[tenantA][1]
	exec(t, `UPDATE devices SET state = 'compliant', last_report_at = now() WHERE id = $1`, mbp)
	exec(t, `UPDATE devices SET state = 'not_compliant', last_report_at = now() WHERE id = $1`, win)

	cases := []struct {
		path string
		rows int
		has  string
	}{
		{"/devices", 2, ""},
		{"/devices?show=attention", 1, "HQ-WIN-004"},
		{"/devices?show=windows", 1, "HQ-WIN-004"},
		{"/devices?show=macos", 1, "HQ-MBP-001"},
		{"/devices?q=mbp", 1, "HQ-MBP-001"},
		{"/devices?show=attention&q=mbp", 0, ""},
		// An operating system nobody has is nothing, never everything.
		{"/devices?show=plan9", 0, ""},
	}
	for _, c := range cases {
		_, page := getHTML(t, f, hostA, c.path, "a-itadmin")
		if n := rowsIn(page); n != c.rows {
			t.Errorf("%s: %d rows, want %d", c.path, n, c.rows)
		}
		if c.has != "" && !strings.Contains(page, c.has) {
			t.Errorf("%s: does not show %s", c.path, c.has)
		}
	}

	// The chips count the whole fleet, so choosing one does not change the
	// numbers on the others.
	_, page := getHTML(t, f, hostA, "/devices?show=windows", "a-itadmin")
	if !strings.Contains(page, `Needs attention<small>1</small>`) || !strings.Contains(page, `All<small>2</small>`) {
		t.Fatal("the filter chips do not count the whole fleet")
	}
	if !strings.Contains(page, `aria-current="true"`) {
		t.Fatal("the chosen filter is not marked")
	}

	// Another tenant's devices never turn up under any filter.
	_, b := getHTML(t, f, hostB, "/devices?show=attention", "b-itadmin")
	if rowsIn(b) != 0 {
		t.Fatal("tenant B sees rows for tenant A's failing device")
	}
}

// ---------------------------------------------------------------- the panel

func TestThePanelExplainsOneDeviceAndStaysInItsTenant(t *testing.T) {
	f := newFixture(t)
	win := f.devices[tenantA][1]
	exec(t, `UPDATE devices SET state = 'state_unknown', last_report_at = now() - interval '3 days' WHERE id = $1`, win)

	rec, body := getHTML(t, f, hostA, "/devices/"+win.String()+"/panel", "a-helpdesk")
	if rec.Code != 200 {
		t.Fatalf("panel: got %d", rec.Code)
	}
	if !strings.Contains(body, "HQ-WIN-004") || !strings.Contains(body, "No report lately") {
		t.Fatalf("the panel does not say what is going on:\n%s", body)
	}
	if strings.Contains(body, "<html") || strings.Contains(body, "<nav") {
		t.Fatal("the panel is a whole page, not a fragment")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("a device's panel can be kept by a shared cache")
	}
	if !strings.Contains(body, `href="/devices/`+win.String()+`"`) {
		t.Fatal("the panel does not lead to the full page")
	}

	// Another tenant's device is the same as one that does not exist.
	other := f.devices[tenantB][0]
	if rec, _ := getHTML(t, f, hostA, "/devices/"+other.String()+"/panel", "a-itadmin"); rec.Code != http.StatusNotFound {
		t.Fatalf("tenant A read tenant B's device through the panel: got %d", rec.Code)
	}
	// And a person who may not list devices may not open the panel either.
	if rec, _ := getHTML(t, f, hostA, "/devices/"+win.String()+"/panel", "a-employee"); rec.Code == 200 {
		t.Fatal("an employee opened the fleet's device panel")
	}
}

// ---------------------------------------------------------------- erase

func heldCount(t *testing.T, f fixture) int {
	t.Helper()
	_, list := do(t, f, req(t, "GET", hostA, "/api/commands?held=1", "a-super"))
	return len(list["commands"].([]any))
}

func TestEraseNeedsTheDevicesNameWhenOneIsSent(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0] // HQ-MBP-001
	path := "/devices/" + dev.String() + "/wipe"

	// The page carries the box, the name to match, and the field.
	_, page := getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if !strings.Contains(page, `data-confirm-name="HQ-MBP-001"`) || !strings.Contains(page, `name="confirm_name"`) {
		t.Fatal("the device page does not ask for the name before an erase")
	}

	// A wrong name starts nothing.
	rec := postForm(t, f, "a-itadmin", path,
		url.Values{"scope": {"all"}, "reason": {"stolen"}, "confirm_name": {"HQ-MBP-002"}})
	if !strings.Contains(said(rec), "not the device's name") {
		t.Fatalf("a wrong name was not refused: %q", said(rec))
	}
	if n := heldCount(t, f); n != 0 {
		t.Fatalf("a wrong name still raised %d wipe request(s)", n)
	}
	// So does a name left empty, which is the browser's field submitted blank.
	rec = postForm(t, f, "a-itadmin", path,
		url.Values{"scope": {"all"}, "reason": {"stolen"}, "confirm_name": {"  "}})
	if !strings.Contains(said(rec), "not the device's name") || heldCount(t, f) != 0 {
		t.Fatal("a blank name started a wipe")
	}

	// The right name, in any case and with stray spaces, goes through to the
	// same approval every full wipe needs.
	rec = postForm(t, f, "a-itadmin", path,
		url.Values{"scope": {"all"}, "reason": {"stolen"}, "confirm_name": {"  hq-mbp-001 "}})
	if !strings.Contains(said(rec), "waiting for a second approval") {
		t.Fatalf("the right name did not raise the request: %q", said(rec))
	}
	if n := heldCount(t, f); n != 1 {
		t.Fatalf("held %d, want 1", n)
	}
}

func TestEraseWithNoNameFieldStillWorksForScripts(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	rec := postForm(t, f, "a-itadmin", "/devices/"+dev.String()+"/wipe",
		url.Values{"scope": {"all"}, "reason": {"stolen"}})
	if !strings.Contains(said(rec), "waiting for a second approval") {
		t.Fatalf("a form with no name field was refused: %q", said(rec))
	}
}

func TestAWorkOnlyRemovalDoesNotAskForTheName(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	rec := postForm(t, f, "a-itadmin", "/devices/"+dev.String()+"/wipe",
		url.Values{"scope": {"work"}, "reason": {"leaving"}, "confirm_name": {"something else"}})
	if strings.Contains(said(rec), "not the device's name") {
		t.Fatal("removing only work data asked for the device's name")
	}
}
