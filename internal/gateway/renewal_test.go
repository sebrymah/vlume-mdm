package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"platform/internal/enrol"
	"platform/internal/notify"
)

// renew asks for a fresh certificate as the device holding `state`.
func renew(t *testing.T, f fixture, state *tls.ConnectionState) (int, map[string]any) {
	t.Helper()
	r := jsonReq(t, "POST", hostA, "/api/my/certificate", "",
		map[string]any{"csr": string(newCSR(t, "renewing"))})
	r.TLS = state
	rec, body := do(t, f, r)
	return rec.Code, body
}

func asState(t *testing.T, certPEM string) *tls.ConnectionState {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("the renewed certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

// ---------------------------------------------------------------- the path

// Without this, the first device enrolled stops being able to authenticate
// exactly a year later, and so does every device after it, one at a time.
func TestADeviceNearExpiryRenewsItselfAndTheNewCertificateWorks(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	old := certUntil(t, tenantA, dev, time.Now().UTC().Add(10*24*time.Hour))

	// It works before renewing.
	r := req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = old
	if rec, _ := do(t, f, r); rec.Code != 200 {
		t.Fatalf("the old certificate did not work: %d", rec.Code)
	}

	code, body := renew(t, f, old)
	if code != http.StatusCreated {
		t.Fatalf("renew: %d %v", code, body)
	}
	fresh, _ := body["certificate"].(string)
	if fresh == "" {
		t.Fatalf("no certificate came back: %v", body)
	}

	// The new one authenticates.
	r = req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = asState(t, fresh)
	if rec, b := do(t, f, r); rec.Code != 200 {
		t.Fatalf("the renewed certificate does not work: %d %v", rec.Code, b)
	}
	// And it lasts about a year rather than inheriting the old expiry.
	notAfter, _ := time.Parse(time.RFC3339, body["not_after"].(string))
	if until := time.Until(notAfter); until < 300*24*time.Hour {
		t.Fatalf("the renewed certificate expires in %v", until)
	}
}

// The old certificate is deliberately NOT revoked on renewal: revoking it
// the moment the new one is signed would brick any device that fails to
// write the answer to disk.
func TestTheOldCertificateKeepsWorkingUntilItExpires(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	old := certUntil(t, tenantA, dev, time.Now().UTC().Add(10*24*time.Hour))

	if code, body := renew(t, f, old); code != http.StatusCreated {
		t.Fatalf("renew: %d %v", code, body)
	}
	r := req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = old
	if rec, _ := do(t, f, r); rec.Code != 200 {
		t.Fatalf("the old certificate stopped working immediately: %d", rec.Code)
	}
}

// ---------------------------------------------------------- the refusals

// THE ONE THAT MATTERS. A renewal path that let a revoked certificate get a
// fresh one would make revocation decorative.
func TestARevokedCertificateCannotRenewItsWayBack(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	state := certUntil(t, tenantA, dev, time.Now().UTC().Add(10*24*time.Hour))

	exec(t, `UPDATE device_certificates
	            SET revoked_at = now(), revoked_reason = 'the laptop was stolen'
	          WHERE device_id = $1`, dev)

	code, body := renew(t, f, state)
	if code != http.StatusForbidden {
		t.Fatalf("a revoked certificate renewed itself: %d %v", code, body)
	}
	// Nothing was issued.
	var issued int
	queryRow(t, `SELECT count(*) FROM device_certificates
	              WHERE device_id = $1 AND revoked_at IS NULL`, &issued, dev)
	if issued != 0 {
		t.Fatalf("%d valid certificates exist after a revoked renewal", issued)
	}
}

// Past the end, a device must enrol again. That is a person's decision, and
// the correct one: a machine nobody has heard from in a year is not a
// machine to quietly re-admit.
func TestAnExpiredCertificateCannotRenew(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	state := certUntil(t, tenantA, dev, time.Now().UTC().Add(-time.Hour))

	code, _ := renew(t, f, state)
	if code != http.StatusForbidden {
		t.Fatalf("an expired certificate renewed: %d", code)
	}
}

// A device that has just enrolled cannot mint another certificate. The
// window is the rate limit: a fresh certificate is not in its own window.
func TestADeviceCannotMintCertificatesByRenewingRepeatedly(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	fresh := certUntil(t, tenantA, dev, time.Now().UTC().Add(300*24*time.Hour))

	code, body := renew(t, f, fresh)
	if code != http.StatusConflict {
		t.Fatalf("a fresh certificate renewed: %d %v", code, body)
	}
	if days, _ := body["renew_within_days"].(float64); int(days) != int(enrol.RenewalWindow.Hours()/24) {
		t.Fatalf("the answer does not say when to come back: %v", body)
	}

	// And renewing once does not open the door to renewing again.
	inWindow := certUntil(t, tenantA, dev, time.Now().UTC().Add(10*24*time.Hour))
	code, body = renew(t, f, inWindow)
	if code != http.StatusCreated {
		t.Fatalf("the first renewal failed: %d %v", code, body)
	}
	code, _ = renew(t, f, inWindow)
	if code != http.StatusCreated {
		// Renewing with the same still-in-window certificate is allowed:
		// it is a retry, and refusing it would punish a device whose first
		// answer was lost. What is refused is renewing with the NEW one.
		t.Fatalf("a retry was refused: %d", code)
	}
	newest, _ := body["certificate"].(string)
	code, _ = renew(t, f, asState(t, newest))
	if code != http.StatusConflict {
		t.Fatalf("a just-issued certificate renewed again: %d", code)
	}
}

// A session is not a device. An administrator renewing on a device's behalf
// would be an administrator minting a device identity.
func TestASessionCannotRenewACertificate(t *testing.T) {
	f := newFixture(t)
	rec, _ := do(t, f, jsonReq(t, "POST", hostA, "/api/my/certificate", "a-super",
		map[string]any{"csr": string(newCSR(t, "x"))}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a console session renewed a certificate: %d", rec.Code)
	}
}

// A certificate of the right shape that we never issued cannot renew, for
// the same reason it cannot do anything else: the gateway refuses it during
// resolution, before this route is chosen.
func TestACertificateWeNeverIssuedCannotRenew(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]

	r := jsonReq(t, "POST", hostA, "/api/my/certificate", "",
		map[string]any{"csr": string(newCSR(t, "x"))})
	r.TLS = deviceCert(t, tenantA, dev) // never registered
	rec, _ := do(t, f, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a self-made certificate renewed: %d", rec.Code)
	}
}

func TestRenewingWithoutARequestIsRefused(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	state := certUntil(t, tenantA, dev, time.Now().UTC().Add(10*24*time.Hour))

	r := jsonReq(t, "POST", hostA, "/api/my/certificate", "", map[string]any{})
	r.TLS = state
	if rec, _ := do(t, f, r); rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

// ------------------------------------------------------------- the warning

// A device that is off, or whose agent has stopped, quietly stops being
// able to authenticate on the day its certificate expires. Until this
// existed the first anyone knew was a device going silent, which looks
// exactly like a stolen laptop.
func TestSomebodyIsToldWhenADeviceIsAboutToStopReporting(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.CertificateExpiring, chat.URL)

	soon := f.devices[tenantA][0]
	fine := f.devices[tenantA][1]
	certUntil(t, tenantA, soon, time.Now().UTC().Add(20*24*time.Hour))
	certUntil(t, tenantA, fine, time.Now().UTC().Add(300*24*time.Hour))

	sweep(t, f)
	deliver(t, f)

	msgs := chat.messages()
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1: %v", len(msgs), msgs)
	}
	if !strings.Contains(msgs[0]["subject"].(string), "stop reporting") {
		t.Fatalf("the message does not say what happens: %v", msgs[0])
	}
	if !strings.Contains(msgs[0]["body"].(string), "enrolled again") {
		t.Fatalf("the message does not say what to do: %v", msgs[0]["body"])
	}
}

// A device that renewed last week still has an OLD certificate expiring
// soon. Warning about that would be a false alarm every single time, which
// is how a warning stops being read.
func TestADeviceThatHasRenewedIsNotWarnedAbout(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.CertificateExpiring, chat.URL)

	dev := f.devices[tenantA][0]
	old := certUntil(t, tenantA, dev, time.Now().UTC().Add(10*24*time.Hour))
	if code, body := renew(t, f, old); code != http.StatusCreated {
		t.Fatalf("renew: %d %v", code, body)
	}

	sweep(t, f)
	deliver(t, f)
	if n := len(chat.messages()); n != 0 {
		t.Fatalf("a device that renewed was warned about: %d messages", n)
	}
}

// The same expiry does not produce a message every sweep.
func TestTheWarningIsNotRepeatedEverySweep(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.CertificateExpiring, chat.URL)
	certUntil(t, tenantA, f.devices[tenantA][0], time.Now().UTC().Add(20*24*time.Hour))

	for i := 0; i < 3; i++ {
		sweep(t, f)
		deliver(t, f)
	}
	if n := len(chat.messages()); n != 1 {
		t.Fatalf("three sweeps produced %d messages", n)
	}
}

// A retired device is not a problem to be told about.
func TestARetiredDeviceIsNotWarnedAbout(t *testing.T) {
	f := newFixture(t)
	chat := newChat(t)
	pointAt(t, f, notify.CertificateExpiring, chat.URL)

	dev := f.devices[tenantA][0]
	certUntil(t, tenantA, dev, time.Now().UTC().Add(20*24*time.Hour))
	exec(t, `UPDATE devices SET state = 'retired' WHERE id = $1`, dev)

	sweep(t, f)
	deliver(t, f)
	if n := len(chat.messages()); n != 0 {
		t.Fatalf("a retired device was warned about: %d", n)
	}
}
