package gateway

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/command"
)

// Command signing keys: stored, sealed, per tenant, shared by every
// instance, rotated without breaking what is already signed.

func signingKeysFor(t *testing.T, f fixture, cert *tls.ConnectionState) (uuid.UUID, []command.PublicKey) {
	t.Helper()
	r := req(t, "GET", hostA, "/api/my/signing-keys", "")
	r.TLS = cert
	rec, body := do(t, f, r)
	if rec.Code != 200 {
		t.Fatalf("signing keys: %d %v", rec.Code, body)
	}
	tenant := uuid.MustParse(body["tenant_id"].(string))
	var out []command.PublicKey
	for _, k := range body["keys"].([]any) {
		m := k.(map[string]any)
		block, _ := pem.Decode([]byte(m["public_key_pem"].(string)))
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, command.PublicKey{Version: int(m["version"].(float64)), Key: pub.(*rsa.PublicKey)})
	}
	return tenant, out
}

// heldCommand is the command the device is holding that is not `except`:
// the one just pushed, whatever order the list comes in.
func heldCommand(t *testing.T, f fixture, cert *tls.ConnectionState, except uuid.UUID) command.Command {
	t.Helper()
	r := req(t, "GET", hostA, "/api/my/commands", "")
	r.TLS = cert
	rec, body := do(t, f, r)
	if rec.Code != 200 {
		t.Fatalf("my commands: %d %v", rec.Code, body)
	}
	var m map[string]any
	for _, c := range body["commands"].([]any) {
		cm := c.(map[string]any)
		if uuid.MustParse(cm["id"].(string)) != except {
			m = cm
		}
	}
	if m == nil {
		t.Fatal("no new command held for the device")
	}
	exp, _ := time.Parse(time.RFC3339Nano, m["nonce_expires_at"].(string))
	return command.Command{
		ID: uuid.MustParse(m["id"].(string)), DeviceID: uuid.MustParse(m["device_id"].(string)),
		Type: command.Type(m["type"].(string)), Nonce: m["nonce"].(string), NonceExpiresAt: &exp,
		Signature: m["signature"].(string),
	}
}

func lock(t *testing.T, f fixture, dev uuid.UUID, reason string) {
	t.Helper()
	if rec, body := do(t, f, form(t, hostA, "/api/devices/"+dev.String()+"/lock", "a-itadmin",
		url.Values{"reason": {reason}})); rec.Code != http.StatusAccepted {
		t.Fatalf("lock: %d %v", rec.Code, body)
	}
}

func TestSigningKeysAreStoredSealedPerTenantAndSurviveARestart(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	cert := trustedCert(t, tenantA, dev)

	lock(t, f, dev, "left in a taxi")
	tenant, keys := signingKeysFor(t, f, cert)
	if tenant != tenantA || len(keys) != 1 {
		t.Fatalf("tenant %s, %d keys", tenant, len(keys))
	}
	first := heldCommand(t, f, cert, uuid.Nil)
	if err := command.Verify(keys[0].Key, tenantA, first); err != nil {
		t.Fatalf("the device cannot verify what it was handed: %v", err)
	}

	// The private half is sealed: what is in the row is not a key.
	var sealed []byte
	queryRow(t, `SELECT private_key_sealed FROM command_signing_keys WHERE tenant_id = $1`, &sealed, tenantA)
	if _, err := x509.ParsePKCS1PrivateKey(sealed); err == nil {
		t.Fatal("the signing key is stored in the clear")
	}

	// A second pipeline over the same database, as another instance or a
	// restart would be, signs with the same key: the device needs no new
	// trust for it.
	other := command.New(&command.StoredKeys{Sealer: f.sealer, Bits: 1024}, command.ByOS{Fallback: okPush{}}, command.DefaultLimiter())
	b := New(Config{Directory: f.g.dir, Store: f.g.store, Signer: f.g.signer, Pipeline: other, Identity: idp,
		CSRFKey: testKey, Sessions: f.sessions, Sealer: f.sealer, Enrol: f.enrol, Notify: f.notify, InsecureCookies: true})
	bf := fixture{h: b.Handler(), g: b, pipe: other, sessions: f.sessions, enrol: f.enrol, sealer: f.sealer, devices: f.devices}
	lock(t, bf, dev, "and again, from another instance")
	second := heldCommand(t, f, cert, first.ID)
	if err := command.Verify(keys[0].Key, tenantA, second); err != nil {
		t.Fatalf("the other instance signed with a different key: %v", err)
	}

	// Tenant B has a key of its own; A's signatures mean nothing to it.
	devB := f.devices[tenantB][0]
	certB := trustedCert(t, tenantB, devB)
	rB := req(t, "GET", hostB, "/api/my/signing-keys", "")
	rB.TLS = certB
	rB.Host = hostB
	rec, body := do(t, f, rB)
	if rec.Code != 200 {
		t.Fatalf("tenant B keys: %d %v", rec.Code, body)
	}
	bKeys := body["keys"].([]any)
	if len(bKeys) != 1 || strings.Contains(bKeys[0].(map[string]any)["public_key_pem"].(string), pemOf(t, keys[0].Key)) {
		t.Fatal("tenant B was handed tenant A's key")
	}
}

func TestRotatingTheSigningKeyKeepsWhatWasAlreadySigned(t *testing.T) {
	f := newFixture(t)
	dev := f.devices[tenantA][0]
	cert := trustedCert(t, tenantA, dev)
	lock(t, f, dev, "before the rotation")
	before := heldCommand(t, f, cert, uuid.Nil)
	_, v1 := signingKeysFor(t, f, cert)

	for _, bearer := range []string{"a-itadmin", "a-helpdesk"} {
		if rec, _ := do(t, f, req(t, "POST", hostA, "/api/signing-keys/rotate", bearer)); rec.Code != http.StatusForbidden {
			t.Fatalf("%s rotated the signing key: %d", bearer, rec.Code)
		}
	}
	rec, body := do(t, f, req(t, "POST", hostA, "/api/signing-keys/rotate", "a-super"))
	if rec.Code != 200 || body["version"].(float64) != 2 {
		t.Fatalf("rotate: %d %v", rec.Code, body)
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'signing_key.rotated'`, tenantA); n != 1 {
		t.Fatal("the rotation was not audited")
	}

	_, v2 := signingKeysFor(t, f, cert)
	if len(v2) != 2 || v2[0].Version != 2 || v2[1].Version != 1 {
		t.Fatalf("after rotation the device sees %+v", v2)
	}
	// The old command still verifies, with the old key; the new one is
	// signed with the new key and not the old.
	if err := command.Verify(v1[0].Key, tenantA, before); err != nil {
		t.Fatalf("the earlier command no longer verifies: %v", err)
	}
	lock(t, f, dev, "after the rotation")
	after := heldCommand(t, f, cert, before.ID)
	if err := command.Verify(v2[0].Key, tenantA, after); err != nil {
		t.Fatalf("the new command does not verify with the new key: %v", err)
	}
	if err := command.Verify(v1[0].Key, tenantA, after); err == nil {
		t.Fatal("the new command was signed with the retired key")
	}
	_ = base64.StdEncoding
}

func pemOf(t *testing.T, k *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
