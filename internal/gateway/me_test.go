package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Isolation inside a tenant.
//
// Everything before this sprint separated tenants, and had two independent
// controls doing it: the repository functions and row-level security. This
// separates PEOPLE inside one tenant, and has one. Row-level security cannot
// help: an administrator legitimately reads every row in the tenant, so a
// policy strong enough to stop an employee would stop them too.
//
// So the predicate in data.MyDevices is the control, and these are the tests
// that hold it up.

// assign puts a device in someone's hands, which is what enrolment does for
// real: the typed address or subject becomes a person the platform has met
// (0040), and the device is keyed to them.
func assign(t *testing.T, device uuid.UUID, who string) {
	t.Helper()
	exec(t, `
		INSERT INTO people (tenant_id, subject, email, source)
		SELECT tenant_id, CASE WHEN $2 LIKE '%@%' THEN '' ELSE $2 END,
		       CASE WHEN $2 LIKE '%@%' THEN lower($2) ELSE '' END, 'assignment'
		  FROM devices WHERE id = $1
		ON CONFLICT DO NOTHING`, device, who)
	exec(t, `
		UPDATE devices d SET assigned_to = $2,
		       person_id = (SELECT id FROM people p WHERE p.tenant_id = d.tenant_id AND p.left_at IS NULL
		                     AND (p.subject = $2 OR p.email = lower($2)) LIMIT 1)
		 WHERE id = $1`, device, who)
}

func TestAnEmployeeSeesTheirOwnDeviceAndNobodyElses(t *testing.T) {
	f := newFixture(t)
	mine := f.devices[tenantA][0]
	theirs := f.devices[tenantA][1]

	assign(t, mine, "t.eze")
	assign(t, theirs, "o.martins")

	rec, body := do(t, f, req(t, "GET", hostA, "/api/me/devices", "a-employee"))
	if rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	ds, _ := body["devices"].([]any)
	if len(ds) != 1 {
		t.Fatalf("an employee sees %d devices, want 1: %v", len(ds), ds)
	}
	if got := ds[0].(map[string]any)["id"]; got != mine.String() {
		t.Fatalf("an employee was shown someone else's device: %v", got)
	}
}

// The identity comes from the claim, so there is nothing on the route to
// change. This proves it by trying the obvious things anyway.
func TestThereIsNoWayToAskForSomeoneElsesDevices(t *testing.T) {
	f := newFixture(t)
	mine := f.devices[tenantA][0]
	theirs := f.devices[tenantA][1]
	assign(t, mine, "t.eze")
	assign(t, theirs, "o.martins")

	for _, query := range []string{
		"?subject=o.martins",
		"?assigned_to=o.martins",
		"?user=o.martins",
		"?email=o.martins@kalesi.example",
		"?device=" + theirs.String(),
	} {
		_, body := do(t, f, req(t, "GET", hostA, "/api/me/devices"+query, "a-employee"))
		ds, _ := body["devices"].([]any)
		if len(ds) != 1 || ds[0].(map[string]any)["id"] != mine.String() {
			t.Fatalf("%s changed the answer: %v", query, ds)
		}
	}
}

// An employee signing in used to land on a dashboard they may not read and
// get a 403 on the front page, which is a product that looks broken rather
// than one working correctly.
func TestAnEmployeeLandsOnTheirOwnPageRatherThanA403(t *testing.T) {
	f := newFixture(t)
	assign(t, f.devices[tenantA][0], "t.eze")

	r := httptest.NewRequest("GET", "http://"+hostA+"/", nil)
	r.Host = hostA
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookie(t, "a-employee")})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)

	if rec.Code != http.StatusFound {
		t.Fatalf("got %d, want a redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/me" {
		t.Fatalf("sent to %q", loc)
	}

	// And an administrator still gets the dashboard.
	rec, body := getHTML(t, f, hostA, "/", "a-itadmin")
	if rec.Code != 200 || !strings.Contains(body, "Dashboard") {
		t.Fatalf("an administrator no longer gets the dashboard: %d", rec.Code)
	}
}

func TestTheEmployeePageShowsWhatToFixInPlainWords(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	assign(t, dev, "t.eze")
	baseline(t, f)

	if code, body := reportAs(t, f, hostA, tenantA, dev, map[string]any{
		"passcode_set": true, "passcode_length": 4, "disk_encryption": true,
	}); code != 200 || body["state"] != "not_compliant" {
		t.Fatalf("expected a failing report first: %d %v", code, body)
	}

	rec, page := getHTML(t, f, hostA, "/me", "a-employee")
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	for _, want := range []string{
		"at least 8 characters",        // what to do
		"the passcode is 4 characters", // how it is now
		"one thing to put right",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page does not say %q", want)
		}
	}
	// And it does not show the fleet, the audit log or anyone else's device.
	for _, forbidden := range []string{"HQ-WIN-004", "Audit log", "Approvals"} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("the employee page leaked %q", forbidden)
		}
	}
}

func TestADeviceNobodyHoldsAppearsOnNobodysPage(t *testing.T) {
	f := newFixture(t)
	// Both seeded devices are unassigned, which is the state of every
	// device enrolled before assignment existed.
	_, body := do(t, f, req(t, "GET", hostA, "/api/me/devices", "a-employee"))
	if ds, _ := body["devices"].([]any); len(ds) != 0 {
		t.Fatalf("an employee was shown %d unassigned devices", len(ds))
	}
	// Including for an administrator, who is also a person.
	_, body = do(t, f, req(t, "GET", hostA, "/api/me/devices", "a-itadmin"))
	if ds, _ := body["devices"].([]any); len(ds) != 0 {
		t.Fatalf("an administrator was shown %d unassigned devices as their own", len(ds))
	}
}

// A device certificate has no person behind it, so it owns nothing. Without
// the empty-subject guard it would match every unassigned device.
func TestADeviceCertificateOwnsNothing(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	assign(t, dev, "t.eze")

	r := req(t, "GET", hostA, "/api/me/devices", "")
	r.TLS = trustedCert(t, tenantA, dev)
	rec, body := do(t, f, r)
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	if ds, _ := body["devices"].([]any); len(ds) != 0 {
		t.Fatalf("a device certificate was handed %d devices", len(ds))
	}
}

// ---------------------------------------------------------- reporting lost

func TestReportingADeviceLostFlagsItAndDoesNothingElse(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	assign(t, dev, "t.eze")

	sess, err := f.sessions.Verify(f.cookie(t, "a-employee"))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	r := httptest.NewRequest("POST", "http://"+hostA+"/me/devices/"+dev.String()+"/lost",
		strings.NewReader("note=Left+it+in+a+taxi&csrf="+
			f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookie(t, "a-employee")})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}

	// The flag is on the device, where an administrator can see it.
	_, page := getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if !strings.Contains(page, "reported this device lost") {
		t.Fatal("the administrator's page does not show the report")
	}
	if !strings.Contains(page, "Left it in a taxi") {
		t.Fatal("what the person said is not shown")
	}

	// And NOTHING was executed. The device's state is untouched and no
	// command exists: locking or wiping is still an administrator's
	// decision, through the pipeline, with its approvals.
	_, d := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "awaiting_first_boot" {
		t.Fatalf("reporting a device lost changed its state to %v", d["state"])
	}
	_, cmds := do(t, f, req(t, "GET", hostA, "/api/commands", "a-itadmin"))
	if n := len(cmds["commands"].([]any)); n != 0 {
		t.Fatalf("reporting a device lost created %d commands", n)
	}
}

func TestSomeoneCannotReportAColleaguesDeviceLost(t *testing.T) {
	f := newFixture(t)
	theirs := f.devices[tenantA][1]
	assign(t, theirs, "o.martins")

	sess, err := f.sessions.Verify(f.cookie(t, "a-employee"))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	r := httptest.NewRequest("POST", "http://"+hostA+"/me/devices/"+theirs.String()+"/lost",
		strings.NewReader("note=not+mine&csrf="+
			f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookie(t, "a-employee")})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)

	// The same answer a device that does not exist would give.
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "No+such+device") {
		t.Fatalf("got %q", loc)
	}
	_, page := getHTML(t, f, hostA, "/devices/"+theirs.String(), "a-itadmin")
	if strings.Contains(page, "reported this device lost") {
		t.Fatal("a colleague's device was flagged")
	}
}

func TestOnlyAnAdministratorCanStandTheReportDown(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	assign(t, dev, "t.eze")
	exec(t, `UPDATE devices SET reported_lost_at = now(), reported_lost_by = 't.eze'
	          WHERE id = $1`, dev)

	post := func(bearer string) int {
		sess, err := f.sessions.Verify(f.cookie(t, bearer))
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		r := httptest.NewRequest("POST", "http://"+hostA+"/devices/"+dev.String()+"/found",
			strings.NewReader("csrf="+f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)))
		r.Host = hostA
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookie(t, bearer)})
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, r)
		return rec.Code
	}

	// The person who raised it cannot quietly clear it. Someone phished
	// into reporting a laptop lost should not also be the one who can
	// stand it down.
	post("a-employee")
	_, page := getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if !strings.Contains(page, "reported this device lost") {
		t.Fatal("an employee cleared their own lost report")
	}

	post("a-itadmin")
	_, page = getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if strings.Contains(page, "reported this device lost") {
		t.Fatal("an administrator could not clear the report")
	}
}

// Pressing it twice must not move the timestamp: when it was first reported
// is the fact anyone investigating will want.
func TestReportingTwiceKeepsTheFirstTime(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	assign(t, dev, "t.eze")

	report := func() {
		sess, _ := f.sessions.Verify(f.cookie(t, "a-employee"))
		r := httptest.NewRequest("POST", "http://"+hostA+"/me/devices/"+dev.String()+"/lost",
			strings.NewReader("csrf="+f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)))
		r.Host = hostA
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookie(t, "a-employee")})
		f.h.ServeHTTP(httptest.NewRecorder(), r)
	}
	report()
	first := lostAt(t, dev)
	report()
	if second := lostAt(t, dev); second != first {
		t.Fatalf("the reported time moved from %s to %s", first, second)
	}
}

// ------------------------------------------------- assignment at enrolment

func TestAnInvitationNamesWhoTheDeviceIsForAndTheDeviceInheritsIt(t *testing.T) {
	f := newFixture(t)

	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/enrolments", "a-itadmin",
		map[string]any{"label": "Kemi's laptop", "ownership": "company",
			"os_family": "macos", "assigned_to": "t.eze"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %v", rec.Code, body)
	}
	token := body["token"].(string)

	got := redeem(t, f, hostA, token, "SN-ASSIGNED-1", "Kemi's MacBook")
	if got.code != http.StatusCreated {
		t.Fatalf("redeem: %d %v", got.code, got.body)
	}

	// It is on that person's page without anyone doing anything else.
	_, mine := do(t, f, req(t, "GET", hostA, "/api/me/devices", "a-employee"))
	ds, _ := mine["devices"].([]any)
	if len(ds) != 1 || ds[0].(map[string]any)["id"] != got.deviceID.String() {
		t.Fatalf("the enrolled device did not reach its holder: %v", ds)
	}
}

func TestAnInvitationForNobodyLeavesTheDeviceUnassigned(t *testing.T) {
	f := newFixture(t)
	_, token := makeEnrolment(t, f, hostA, "a-itadmin", "a spare laptop")
	got := redeem(t, f, hostA, token, "SN-SPARE-1", "")
	if got.code != http.StatusCreated {
		t.Fatalf("redeem: %d", got.code)
	}
	_, mine := do(t, f, req(t, "GET", hostA, "/api/me/devices", "a-employee"))
	if ds, _ := mine["devices"].([]any); len(ds) != 0 {
		t.Fatalf("a spare laptop landed on someone's page: %v", ds)
	}
}
