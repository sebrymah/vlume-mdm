package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The policy builder and the "add devices" pages.

func TestTheBuilderSaysHowManyDevicesAPolicyWouldReach(t *testing.T) {
	f := newFixture(t)
	mbp, win := f.devices[tenantA][0], f.devices[tenantA][1]
	exec(t, `UPDATE devices SET os_family = 'android', ownership = 'company' WHERE id = $1`, mbp)
	exec(t, `UPDATE devices SET os_family = 'android', ownership = 'personal' WHERE id = $1`, win)

	_, page := getHTML(t, f, hostA, "/policies?new=android", "a-itadmin")
	for _, want := range []string{
		`data-reach-any="2"`, `data-reach-company="1"`, `data-reach-personal="1"`,
		`class="sw"`, "What this does", "Who it reaches", "Save as a new version",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Android builder is missing %q", want)
		}
	}

	// A system with no devices reaches none, rather than everything.
	_, win2 := getHTML(t, f, hostA, "/policies?new=windows", "a-itadmin")
	if !strings.Contains(win2, `data-reach-any="0"`) {
		t.Fatal("a Windows policy claims to reach devices when no Windows device exists")
	}

	// Another tenant's devices are never counted.
	_, b := getHTML(t, f, hostB, "/policies?new=android", "b-itadmin")
	if !strings.Contains(b, `data-reach-any="0"`) {
		t.Fatal("tenant B's builder counted tenant A's devices")
	}
}

func TestTheBuilderStillPostsEveryFieldItAlwaysDid(t *testing.T) {
	f := newFixture(t)
	_, page := getHTML(t, f, hostA, "/policies?new=android", "a-itadmin")
	for _, name := range []string{`name="csrf"`, `name="guided"`, `name="os_family"`, `name="name"`,
		`name="ownership"`, `name="on_failure"`, `name="remediate"`, `name="cfg.`} {
		if !strings.Contains(page, name) {
			t.Errorf("the builder no longer sends %s", name)
		}
	}
}

func TestAddDevicesPointsEachKindOfDeviceToItsWay(t *testing.T) {
	f := newFixture(t)
	_, page := getHTML(t, f, hostA, "/enrolments", "a-itadmin")
	for _, want := range []string{"Add devices", "What are you adding?", `href="/android"`, `id="invite"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the add devices page is missing %q", want)
		}
	}
	// Someone who cannot make invites is not shown the form.
	_, help := getHTML(t, f, hostA, "/enrolments", "a-helpdesk")
	if strings.Contains(help, `id="invite"`) {
		t.Fatal("a role that cannot invite is shown the invite form")
	}
}

func TestTheWaitingListShowsOnlyThisTenantsInvitesAndNoSecret(t *testing.T) {
	f := newFixture(t)
	rec := postForm(t, f, "a-itadmin", "/enrolments",
		url.Values{"label": {"Kemi laptop"}, "os_family": {"windows"}, "ownership": {"company"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("could not make an invite: %d", rec.Code)
	}
	created := rec.Body.String()
	if !strings.Contains(created, "Waiting for the device") || !strings.Contains(created, "/enrolments/recent") {
		t.Fatal("the link-ready page does not watch for the device")
	}

	rr, frag := getHTML(t, f, hostA, "/enrolments/recent", "a-helpdesk")
	if rr.Code != 200 || !strings.Contains(frag, "Kemi laptop") || !strings.Contains(frag, "Waiting") {
		t.Fatalf("the waiting list does not show the invite: %d %s", rr.Code, frag)
	}
	if strings.Contains(frag, "<html") || strings.Contains(frag, "token") || strings.Contains(frag, "/enrol?") {
		t.Fatal("the waiting list is not a plain fragment, or it leaks the link")
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the waiting list can be kept by a shared cache")
	}

	_, other := getHTML(t, f, hostB, "/enrolments/recent", "b-itadmin")
	if strings.Contains(other, "Kemi laptop") {
		t.Fatal("tenant B sees tenant A's invite")
	}
	if rec, _ := getHTML(t, f, hostA, "/enrolments/recent", "a-employee"); rec.Code == 200 {
		t.Fatal("an employee opened the invite list")
	}
}
