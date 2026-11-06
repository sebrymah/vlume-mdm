package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/android"
	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/tenantclaim"
)

// F4. Offboarding is a wipe, then retirement when the wipe is done; a
// leaver is every device they hold; HR may say so through a token that
// may say nothing else.

func TestOffboardingWipesThenRetiresWhenTheDeviceConfirms(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	// It has a certificate: it is a real, enrolled device.
	cert := trustedCert(t, tenantA, dev)

	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/offboard", "a-itadmin",
		map[string]any{"reason": "Returned to IT"}))
	if rec.Code != http.StatusAccepted || body["retired"] != false {
		t.Fatalf("offboard: %d %v", rec.Code, body)
	}
	cmd := body["command"].(map[string]any)
	if cmd["type"] != "wipe_selective" || cmd["state"] != "pushed" {
		t.Fatalf("the wipe: %v", cmd)
	}
	// Marked, not retired, certificate still good.
	_, d := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] == "retired" {
		t.Fatal("retired before the wipe was confirmed")
	}
	if n := adminCount(t, `SELECT count(*) FROM devices WHERE id = $1 AND offboarding_at IS NOT NULL AND offboarded_at IS NULL`, dev); n != 1 {
		t.Fatal("not marked as offboarding")
	}
	// The help desk may not; a second offboard is one in progress.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/offboard", "a-helpdesk",
		map[string]any{"reason": "x"})); rec.Code != http.StatusForbidden {
		t.Fatalf("the help desk offboarded a device: %d", rec.Code)
	}

	// The device confirms the wipe: now it is retired, its certificate is
	// revoked, and its next request is refused.
	id := cmd["id"].(string)
	r := req(t, "POST", hostA, "/api/commands/"+id+"/ack?code="+nonceOf(t, id), "")
	r.TLS = cert
	if rec, body := do(t, f, r); rec.Code != 200 {
		t.Fatalf("ack: %d %v", rec.Code, body)
	}
	_, d = do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "retired" {
		t.Fatalf("after the wipe the device is %v", d["state"])
	}
	r = req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = cert
	if rec, _ := do(t, f, r); rec.Code != http.StatusForbidden {
		t.Fatalf("a retired device's certificate still works: %d", rec.Code)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action IN ('device.offboarding','device.retired')`, tenantA); n != 2 {
		t.Fatalf("%d offboarding audit records", n)
	}
	// Retired is final.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/offboard", "a-itadmin",
		map[string]any{"reason": "again"})); rec.Code != http.StatusConflict {
		t.Fatalf("offboarding a retired device: %d", rec.Code)
	}
	// And a device that never enrolled is retired at once.
	other := f.devices[tenantA][1]
	rec, body = do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+other.String()+"/offboard", "a-itadmin",
		map[string]any{"reason": "Never used"}))
	if rec.Code != http.StatusAccepted || body["retired"] != true {
		t.Fatalf("a never-enrolled device: %d %v", rec.Code, body)
	}
}

func TestALeaverIsEveryDeviceTheyHoldAndHRMaySaySo(t *testing.T) {
	f := newFixture(t)
	devs := f.devices[tenantA]
	exec(t, `UPDATE devices SET assigned_to = 'kemi@kalesi.example' WHERE id = ANY($1::uuid[])`, []uuid.UUID{devs[0], devs[1]})
	for _, id := range devs {
		trustedCert(t, tenantA, id)
	}
	// A network token may not say it; an HR token may, and may do nothing else.
	netTok, _ := mintToken(t, f, "a-super", "NAC")
	hrTok, _ := mintScopedToken(t, f, "a-super", "Workday", "hr")
	if netTok == "" || hrTok == "" {
		t.Fatal("tokens")
	}
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/hr/leavers", netTok, map[string]any{"email": "kemi@kalesi.example"})); rec.Code != http.StatusForbidden {
		t.Fatalf("a network token offboarded a person: %d", rec.Code)
	}
	if rec, _ := do(t, f, req(t, "GET", hostA, "/api/network/denied", hrTok)); rec.Code != http.StatusForbidden {
		t.Fatalf("an HR token read the access feed: %d", rec.Code)
	}
	// An HR token may not wipe or offboard a NAMED device: only say a
	// person has left.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+devs[0].String()+"/wipe", hrTok, map[string]any{"reason": "x", "scope": "selective"})); rec.Code != http.StatusForbidden {
		t.Fatalf("an HR token wiped a named device: %d", rec.Code)
	}
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+devs[0].String()+"/offboard", hrTok, map[string]any{"reason": "x"})); rec.Code != http.StatusForbidden {
		t.Fatalf("an HR token offboarded a named device: %d", rec.Code)
	}
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/hr/leavers", hrTok, map[string]any{"email": "Kemi@Kalesi.example"}))
	if rec.Code != http.StatusAccepted || body["count"] != float64(2) {
		t.Fatalf("HR leaver: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM commands WHERE tenant_id = $1 AND type = 'wipe_selective'`, tenantA); n != 2 {
		t.Fatalf("%d wipes for a leaver with two devices", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'employee.offboarded'`, tenantA); n != 1 {
		t.Fatal("the leaver was not audited")
	}
	// Saying it twice starts nothing new.
	rec, body = do(t, f, jsonReq(t, "POST", hostA, "/api/hr/leavers", hrTok, map[string]any{"email": "kemi@kalesi.example"}))
	if rec.Code != http.StatusAccepted || body["count"] != float64(0) {
		t.Fatalf("second leaver call: %d %v", rec.Code, body)
	}
	// The help desk may not offboard a person either.
	if rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/people/offboard", "a-helpdesk", map[string]any{"email": "x@kalesi.example"})); rec.Code != http.StatusForbidden {
		t.Fatalf("the help desk offboarded a person: %d", rec.Code)
	}
}

func TestAnAndroidPhoneIsRetiredAsSoonAsGoogleHasWipedIt(t *testing.T) {
	f := newFixture(t)
	if msg := bindAndroid(t, f, "a-super"); !strings.Contains(msg, "Bound") {
		t.Fatalf("bind: %q", msg)
	}
	ent := adminString(t, `SELECT name FROM android_enterprises WHERE tenant_id = $1`, tenantA)
	tok, _ := f.g.android.CreateEnrollmentToken(context.Background(), ent, android.TokenInput{PolicyName: ent + "/policies/default", OneTime: true})
	name := f.google.Enrol(tok.Value, "PHONE-OFF", "Pixel", "15", true, true)
	do(t, f, req(t, "POST", hostA, "/api/android/sync", "a-itadmin"))
	dev := adminUUID(t, `SELECT id FROM devices WHERE tenant_id = $1 AND android_name = $2`, tenantA, name)
	rec, body := do(t, f, jsonReq(t, "POST", hostA, "/api/devices/"+dev.String()+"/offboard", "a-itadmin",
		map[string]any{"reason": "Leaving"}))
	if rec.Code != http.StatusAccepted || body["retired"] != true {
		t.Fatalf("android offboard: %d %v", rec.Code, body)
	}
	if _, wiped := f.google.Wipes[name]; !wiped {
		t.Fatal("Google was not asked to wipe the work profile")
	}
	_, d := do(t, f, req(t, "GET", hostA, "/api/devices/"+dev.String(), "a-itadmin"))
	if d["state"] != "retired" {
		t.Fatalf("after Google wiped it the phone is %v", d["state"])
	}
}

func mintScopedToken(t *testing.T, f fixture, bearer, name, scope string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	cookie := f.cookie(t, bearer)
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	vals := url.Values{"name": {name}, "scope": {scope},
		"csrf": {f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)}}
	r := httptest.NewRequest("POST", "http://"+hostA+"/identity/tokens", strings.NewReader(vals.Encode()))
	r.Host = hostA
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "text/html")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return tokenRE.FindString(rec.Body.String()), rec
}

// The offboarding permission is for the work-data removal only. Through
// the pipeline directly, with the flag set, a full wipe is still refused
// to a role that holds offboard.employee and not wipe.request.
func TestTheOffboardingPermissionDoesNotReachAFullWipe(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	hrTok, _ := mintScopedToken(t, f, "a-super", "Workday", "hr")
	// Resolve the token's claim the way the gateway does, then ask the
	// pipeline for a full wipe under the offboarding flag.
	tenant, err := f.g.dir.ResolveID(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	id, err := f.g.resolveIntegration(context.Background(), tenant, hrTok)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	claim, err := f.g.signer.Mint(tenantclaim.Claim{
		TenantID: id.TenantID, Subject: id.Subject, Role: string(id.Role), RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	err = f.g.store.WithTenant(context.Background(), claim, func(ctx context.Context, tx *data.Tx) error {
		_, rerr := f.g.pipe.Request(ctx, tx, command.RequestInput{
			DeviceID: dev, Type: command.WipeFull, Reason: "x", Offboarding: true})
		return rerr
	})
	if err == nil || !strings.Contains(err.Error(), "may not") {
		t.Fatalf("a full wipe under the offboarding flag: %v", err)
	}
}
