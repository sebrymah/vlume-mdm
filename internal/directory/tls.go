package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/acme/autocert"
)

// T5: managed TLS. The directory is the host policy, and the operator's
// table is the certificate cache.

var ErrHostNotOurs = errors.New("directory: that hostname is not a verified tenant domain")

// HostAllowed is autocert's HostPolicy: a certificate is issued for a
// hostname only when a tenant that is not offboarded owns it and it is
// verified. Everything else is refused before any ACME call is made.
func (d *Directory) HostAllowed(ctx context.Context, host string) error {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	var status string
	err := d.pool.QueryRow(ctx, `
		SELECT t.status FROM tenant_domains dom
		  JOIN tenants t ON t.id = dom.tenant_id
		 WHERE dom.host = $1 AND dom.verified_at IS NOT NULL`, h).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %q", ErrHostNotOurs, h)
	}
	if err != nil {
		return err
	}
	if status == "offboarded" {
		return fmt.Errorf("%w: %q belonged to a tenant that has left", ErrHostNotOurs, h)
	}
	return nil
}

// CertCache is autocert.Cache on the tls_cache table.
type CertCache struct{ d *Directory }

func (d *Directory) CertCache() *CertCache { return &CertCache{d: d} }

func (c *CertCache) Get(ctx context.Context, name string) ([]byte, error) {
	var data []byte
	err := c.d.pool.QueryRow(ctx, `SELECT data FROM tls_cache WHERE name = $1`, name).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	return data, err
}

func (c *CertCache) Put(ctx context.Context, name string, data []byte) error {
	_, err := c.d.pool.Exec(ctx, `
		INSERT INTO tls_cache (name, data) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET data = excluded.data, updated_at = now()`, name, data)
	return err
}

func (c *CertCache) Delete(ctx context.Context, name string) error {
	_, err := c.d.pool.Exec(ctx, `DELETE FROM tls_cache WHERE name = $1`, name)
	return err
}

var _ autocert.Cache = (*CertCache)(nil)
