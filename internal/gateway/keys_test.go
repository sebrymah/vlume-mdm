package gateway

import (
	"context"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/secrets"
	"platform/internal/tenantclaim"
)

type dataTx = data.Tx

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// claim mints a claim for a seeded identity, for a test that works inside
// a tenant transaction directly.
func (f fixture) claim(t *testing.T, bearer string) string {
	t.Helper()
	cookie := f.cookie(t, bearer)
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	claim, err := f.g.signer.Mint(tenantclaim.Claim{
		TenantID: sess.TenantID, Subject: sess.Subject, Role: string(authz.Role(sess.Role)),
		RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return claim
}

// T3. One key per tenant; rotation re-seals that tenant's values and no
// other's; a value sealed before rotation still opens.

func TestRotatingATenantsKeyTouchesOnlyThatTenant(t *testing.T) {
	f := newFixture(t)
	// Both tenants hold sealed values: an identity secret (through the
	// console, so it is sealed under the tenant key) and a notification
	// endpoint.
	for _, tc := range []struct{ host, bearer string }{{hostA, "a-itadmin"}, {hostB, "b-itadmin"}} {
		do(t, f, jsonReq(t, "POST", tc.host, "/api/notifications", tc.bearer,
			map[string]any{"topic": "device.lost", "kind": "log", "endpoint": "-"}))
	}
	exec(t, `INSERT INTO tenant_identity (tenant_id, issuer, client_id, client_secret_sealed, redirect_url)
	         VALUES ($1, 'https://login.example/v2.0', 'c', '\x00', 'https://x/signin/callback') ON CONFLICT DO NOTHING`, tenantA)
	// Seal tenant A's secret properly, through the keyring, as the console does.
	if err := f.g.store.WithTenant(context.Background(), f.claim(t, "a-super"), func(ctx context.Context, tx *dataTx) error {
		sealed, err := f.g.sealer.Seal(ctx, tx, []byte("the-secret"))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE tenant_identity SET client_secret_sealed = $1`, sealed)
		return err
	}); err != nil {
		t.Fatalf("seal: %v", err)
	}
	beforeA := adminString(t, `SELECT encode(client_secret_sealed, 'hex') FROM tenant_identity WHERE tenant_id = $1`, tenantA)
	beforeB := adminString(t, `SELECT encode(endpoint_sealed, 'hex') FROM notification_targets WHERE tenant_id = $1`, tenantB)
	if secrets.Version(mustHex(t, beforeA)) != 1 {
		t.Fatalf("tenant A's secret is not under key version 1: %d", secrets.Version(mustHex(t, beforeA)))
	}

	// Only a Super Admin rotates.
	if rec, _ := do(t, f, req(t, "POST", hostA, "/api/keys/rotate", "a-itadmin")); rec.Code != http.StatusForbidden {
		t.Fatalf("an IT admin rotated the key: %d", rec.Code)
	}
	rec, body := do(t, f, req(t, "POST", hostA, "/api/keys/rotate", "a-super"))
	if rec.Code != 200 || body["version"] != float64(2) {
		t.Fatalf("rotate: %d %v", rec.Code, body)
	}
	afterA := adminString(t, `SELECT encode(client_secret_sealed, 'hex') FROM tenant_identity WHERE tenant_id = $1`, tenantA)
	afterB := adminString(t, `SELECT encode(endpoint_sealed, 'hex') FROM notification_targets WHERE tenant_id = $1`, tenantB)
	if afterA == beforeA || secrets.Version(mustHex(t, afterA)) != 2 {
		t.Fatalf("tenant A's secret was not re-sealed under version 2: %d", secrets.Version(mustHex(t, afterA)))
	}
	if afterB != beforeB {
		t.Fatal("tenant B's value changed when tenant A rotated")
	}
	// The value still opens, and reads the same.
	tenant, _ := f.g.dir.ResolveID(context.Background(), tenantA)
	cfg, err := f.g.identityConfig(context.Background(), tenant)
	if err != nil || cfg.ClientSecret != "the-secret" {
		t.Fatalf("after rotation the secret reads %q, %v", cfg.ClientSecret, err)
	}
	// Two versions on the row, one current; and the audit says so.
	if n := adminCount(t, `SELECT count(*) FROM tenant_keys WHERE tenant_id = $1`, tenantA); n != 2 {
		t.Fatalf("%d key versions", n)
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_keys WHERE tenant_id = $1 AND retired_at IS NULL AND version = 2`, tenantA); n != 1 {
		t.Fatal("version 2 is not the current key")
	}
	if n := adminCount(t, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'keys.rotated'`, tenantA); n != 1 {
		t.Fatal("rotation was not audited")
	}
	// Tenant B still has version 1, untouched.
	if n := adminCount(t, `SELECT count(*) FROM tenant_keys WHERE tenant_id = $1 AND version = 1 AND retired_at IS NULL`, tenantB); n != 1 {
		t.Fatal("tenant B's key moved")
	}
}

// A value sealed before tenant keys existed, under the master, still opens.
func TestAValueSealedBeforeTenantKeysStillOpens(t *testing.T) {
	f := newFixture(t)
	master, _ := secrets.NewAESSealer(sealKey)
	legacy, _ := master.Seal([]byte("old-secret"))
	exec(t, `INSERT INTO tenant_identity (tenant_id, issuer, client_id, client_secret_sealed, redirect_url)
	         VALUES ($1, 'https://login.example/v2.0', 'c', $2, 'https://x/signin/callback')
	         ON CONFLICT (tenant_id) DO UPDATE SET client_secret_sealed = excluded.client_secret_sealed`, tenantA, legacy)
	tenant, _ := f.g.dir.ResolveID(context.Background(), tenantA)
	cfg, err := f.g.identityConfig(context.Background(), tenant)
	if err != nil || cfg.ClientSecret != "old-secret" {
		t.Fatalf("legacy secret: %q %v", cfg.ClientSecret, err)
	}
	// Rotation brings it under the tenant's key.
	if rec, _ := do(t, f, req(t, "POST", hostA, "/api/keys/rotate", "a-super")); rec.Code != 200 {
		t.Fatalf("rotate: %d", rec.Code)
	}
	after := adminString(t, `SELECT encode(client_secret_sealed, 'hex') FROM tenant_identity WHERE tenant_id = $1`, tenantA)
	if secrets.Version(mustHex(t, after)) == 0 {
		t.Fatal("the legacy value was not brought under the tenant's key")
	}
	cfg, err = f.g.identityConfig(context.Background(), tenant)
	if err != nil || cfg.ClientSecret != "old-secret" {
		t.Fatalf("after rotation: %q %v", cfg.ClientSecret, err)
	}
}
