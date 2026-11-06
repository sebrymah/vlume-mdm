package directory

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// T5. Certificates are issued for verified tenant hostnames and nothing
// else; the cache is the operator's table.

func TestOnlyAVerifiedTenantHostnameGetsACertificate(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	if err := d.HostAllowed(ctx, "MDM.Kalesi.example."); err != nil {
		t.Fatalf("a verified tenant hostname was refused: %v", err)
	}
	for _, bad := range []string{"stranger.example", "kalesi.example", "mdm.kalesi.example.evil.example", ""} {
		if err := d.HostAllowed(ctx, bad); !errors.Is(err, ErrHostNotOurs) {
			t.Fatalf("%q: got %v, want refused", bad, err)
		}
	}
	// An unverified hostname is not ours yet.
	queryExec(t, `INSERT INTO tenant_domains (host, tenant_id) VALUES ('pending.kalesi.example', $1)`, tenantA)
	if err := d.HostAllowed(ctx, "pending.kalesi.example"); !errors.Is(err, ErrHostNotOurs) {
		t.Fatalf("an unverified hostname got a certificate: %v", err)
	}
	// An offboarded tenant's hostname is not ours any more.
	queryExec(t, `UPDATE tenants SET status = 'offboarded' WHERE id = $1`, tenantA)
	if err := d.HostAllowed(ctx, "mdm.kalesi.example"); !errors.Is(err, ErrHostNotOurs) {
		t.Fatalf("an offboarded tenant's hostname got a certificate: %v", err)
	}
}

func TestTheCertificateCacheRoundTrips(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	c := d.CertCache()
	if _, err := c.Get(ctx, "mdm.kalesi.example"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("an empty cache: %v", err)
	}
	if err := c.Put(ctx, "mdm.kalesi.example", []byte("cert-and-key")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := c.Put(ctx, "mdm.kalesi.example", []byte("renewed")); err != nil {
		t.Fatalf("put again: %v", err)
	}
	got, err := c.Get(ctx, "mdm.kalesi.example")
	if err != nil || string(got) != "renewed" {
		t.Fatalf("get: %q %v", got, err)
	}
	if err := c.Delete(ctx, "mdm.kalesi.example"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Get(ctx, "mdm.kalesi.example"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatal("deleted and still there")
	}
	// The cache is the operator's; the application role has no grant.
	if err := d.probe(ctx, `SELECT data FROM tls_cache LIMIT 1`); err != nil {
		t.Fatalf("the operator could not read its own cache: %v", err)
	}
}
