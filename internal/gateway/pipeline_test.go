package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/authz"
	"platform/internal/command"
	"platform/internal/directory"
)

// nonceOf reads the one-time code the way a device would receive it: inside
// the signed command. Nothing in the API hands it to a console user, which is
// why this goes to the database rather than through a response body.
func nonceOf(t *testing.T, id string) string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin: %v", err)
	}
	defer conn.Close(ctx)
	var n string
	if err := conn.QueryRow(ctx, `SELECT coalesce(nonce,'') FROM commands WHERE id=$1`, id).Scan(&n); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return n
}

// ---------------------------------------------------------------- the path

func TestLockGoesAllTheWayToAcknowledged(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	rec, body := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/lock", "a-itadmin",
		url.Values{"reason": {"reported stolen this morning"}}))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("lock: got %d, body %v", rec.Code, body)
	}
	if body["state"] != "pushed" {
		t.Fatalf("state is %v, want pushed", body["state"])
	}
	// Pushed is not done, and the response says so by not claiming otherwise.
	if body["done"] != false {
		t.Fatal("a pushed command is reporting itself as done")
	}

	id := body["id"].(string)
	r := req(t, "POST", hostA, "/api/commands/"+id+"/ack?code="+nonceOf(t, id), "")
	r.TLS = trustedCert(t, tenantA, dev)
	rec, body = do(t, f, r)
	if rec.Code != 200 {
		t.Fatalf("acknowledge: got %d, body %v", rec.Code, body)
	}
	if body["state"] != "acknowledged" || body["done"] != true {
		t.Fatalf("after acknowledgement: state %v done %v", body["state"], body["done"])
	}
}

// Only the device the command names may acknowledge it, and only on the
// certificate path. A console session cannot mark its own work done.
func TestOnlyTheNamedDeviceMayAcknowledge(t *testing.T) {
	f := newFixture(t)
	devA := f.devices[tenantA][0]

	_, body := do(t, f, form(t, hostA, "/api/devices/"+devA.String()+"/lock", "a-itadmin",
		url.Values{"reason": {"stolen"}}))
	id := body["id"].(string)
	code := nonceOf(t, id)

	// A console session, with the right code, is still refused.
	rec, _ := do(t, f, req(t, "POST", hostA, "/api/commands/"+id+"/ack?code="+code, "a-super"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a console session acknowledged a command: got %d", rec.Code)
	}

	// A different device of the same tenant, with the right code, is refused.
	// It has to be a real one now: since enrolment, a certificate is only
	// trusted if we issued it, and we cannot have issued one to a device
	// that does not exist.
	other := f.devices[tenantA][1]
	r := req(t, "POST", hostA, "/api/commands/"+id+"/ack?code="+code, "")
	r.TLS = trustedCert(t, tenantA, other)
	rec, _ = do(t, f, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("another device acknowledged the command: got %d", rec.Code)
	}
}

// ---------------------------------------------------------------- approvals

func TestFullWipeWaitsAndThenGoesThroughOnASecondRole(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	rec, body := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"scope": {"all"}, "reason": {"stolen, police report AB/2026/4417"}}))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("wipe: got %d, body %v", rec.Code, body)
	}
	if body["state"] != "held" {
		t.Fatalf("a full wipe is %v, want held", body["state"])
	}
	id := body["id"].(string)

	// It is now in the approvals queue.
	_, list := do(t, f, req(t, "GET", hostA, "/api/commands?held=1", "a-super"))
	if n := len(list["commands"].([]any)); n != 1 {
		t.Fatalf("approvals queue holds %d, want 1", n)
	}

	// The person who asked may not approve, even as a Super Admin would.
	rec, _ = do(t, f, form(t, hostA, "/api/commands/"+id+"/approve", "a-itadmin", url.Values{}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an IT Admin approved: got %d", rec.Code)
	}

	// A Security Manager, a different person and a different role, may.
	rec, body = do(t, f, form(t, hostA, "/api/commands/"+id+"/approve", "a-secmgr",
		url.Values{"note": {"spoke to Adaeze, confirmed"}}))
	if rec.Code != 200 {
		t.Fatalf("approve: got %d, body %v", rec.Code, body)
	}
	if body["state"] != "pushed" {
		t.Fatalf("after approval the wipe is %v, want pushed", body["state"])
	}
}

func TestOneTenantCannotApproveAnothersCommandThroughTheAPI(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	_, body := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"scope": {"all"}, "reason": {"stolen"}}))
	id := body["id"].(string)

	rec, _ := do(t, f, form(t, hostB, "/api/commands/"+id+"/approve", "b-itadmin", url.Values{}))
	if rec.Code == 200 {
		t.Fatal("tenant B approved tenant A's wipe")
	}
}

// ---------------------------------------------------------------- csrf

func tokenFor(f fixture, tenant uuid.UUID, subject string, role authz.Role) string {
	return f.g.csrfToken(Resolution{
		Tenant: directory.Tenant{ID: tenant}, Subject: subject, Role: role,
	})
}

// A browser attaches the session by itself, so a form from another site would
// otherwise carry real authority.
func TestConsoleFormsNeedTheirToken(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	path := "/devices/" + dev.String() + "/lock"

	post := func(vals url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://"+hostA+path, strings.NewReader(vals.Encode()))
		r.Host = hostA
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: "session", Value: f.cookie(t, "a-itadmin")})
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, r)
		return rec
	}

	rec := post(url.Values{"reason": {"stolen"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "expired") {
		t.Fatalf("a form with no token was accepted: %d %s", rec.Code, loc)
	}

	rec = post(url.Values{"reason": {"stolen"}, "csrf": {"not-the-token"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "expired") {
		t.Fatalf("a form with a wrong token was accepted: %s", loc)
	}

	good := tokenFor(f, tenantA, "o.martins", authz.ITAdmin)
	rec = post(url.Values{"reason": {"stolen"}, "csrf": {good}})
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "expired") {
		t.Fatalf("a form with the right token was refused: %s", loc)
	}
	// The fixture has a working push provider, so the honest answer is that
	// it was sent and not yet confirmed. Never that it is done.
	if !strings.Contains(loc, "not+confirmed+it+yet") {
		t.Fatalf("the console did not say where the command got to: %s", loc)
	}
}

// With no push provider, which is today's reality, the console says what is
// missing rather than failing vaguely or pretending the command went out.
func TestWithNoPushProviderTheConsoleNamesWhatIsMissing(t *testing.T) {
	f := newFixtureWith(t, command.AppleNotConfigured())
	dev := f.devices[tenantA][0]

	r := httptest.NewRequest("POST", "http://"+hostA+"/devices/"+dev.String()+"/lock",
		strings.NewReader(url.Values{
			"reason": {"stolen"},
			"csrf":   {tokenFor(f, tenantA, "o.martins", authz.ITAdmin)},
		}.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "session", Value: f.cookie(t, "a-itadmin")})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "Apple") {
		t.Fatalf("the console did not say the Apple certificate is what is missing: %s", loc)
	}
	if !strings.Contains(loc, "queued") {
		t.Fatalf("a command with nowhere to go should be queued, not refused: %s", loc)
	}
}

// A caller who set an Authorization header cannot be made to by another site,
// so requiring a token there would be ceremony rather than protection.
func TestBearerCallersNeedNoFormToken(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	rec, _ := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/lock", "a-itadmin",
		url.Values{"reason": {"stolen"}}))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a bearer call was refused for a missing form token: %d", rec.Code)
	}
}

// ---------------------------------------------------------------- console

func TestDeviceActionsAppearByRole(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	path := "/devices/" + dev.String()

	_, itadmin := getHTML(t, f, hostA, path, "a-itadmin")
	for _, want := range []string{"Lock the device", "Remove work data only", "Erase everything"} {
		if !strings.Contains(itadmin, want) {
			t.Errorf("an IT Admin cannot see %q", want)
		}
	}

	// The reversible action is offered beside the irreversible one, and the
	// irreversible one carries its warning.
	if !strings.Contains(itadmin, "there is no undo") {
		t.Error("erase everything is offered without saying it cannot be undone")
	}

	_, auditor := getHTML(t, f, hostA, path, "a-auditor")
	for _, never := range []string{"Lock the device", "Erase everything"} {
		if strings.Contains(auditor, never) {
			t.Errorf("an auditor is being shown %q", never)
		}
	}
}

func TestApprovalsPageIsOnlyForRolesThatMayApprove(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"scope": {"all"}, "reason": {"stolen, police report filed"}}))

	rec, secmgr := getHTML(t, f, hostA, "/approvals", "a-secmgr")
	if rec.Code != 200 {
		t.Fatalf("a Security Manager cannot open approvals: %d", rec.Code)
	}
	if !strings.Contains(secmgr, "Erase everything") {
		t.Fatal("the held wipe is not in the approvals queue")
	}
	if !strings.Contains(secmgr, "police report filed") {
		t.Fatal("the approver cannot see the reason they are being asked to accept")
	}

	rec, _ = getHTML(t, f, hostA, "/approvals", "a-itadmin")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an IT Admin reached the approvals queue: %d", rec.Code)
	}

	_, nav := getHTML(t, f, hostA, "/", "a-itadmin")
	if strings.Contains(nav, `href="/approvals"`) {
		t.Error("an IT Admin is shown a link to a page they may not open")
	}
}

// The console never says a queued command is done.
func TestConsoleDoesNotClaimAQueuedCommandIsDone(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/wipe", "a-itadmin",
		url.Values{"scope": {"all"}, "reason": {"stolen"}}))

	_, page := getHTML(t, f, hostA, "/devices/"+dev.String(), "a-itadmin")
	if !strings.Contains(page, "Waiting for approval") {
		t.Fatal("a held wipe is not shown as waiting")
	}
	if strings.Contains(page, "Confirmed by the device") {
		t.Fatal("a held wipe is being shown as confirmed")
	}
}
