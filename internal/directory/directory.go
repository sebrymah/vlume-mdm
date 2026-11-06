// Package directory answers the one question that necessarily spans tenants:
// which tenant owns this hostname.
//
// It exists as its own package, with its own database role, because the
// alternative was an escape hatch on data.WithTenant, and an escape hatch is
// how the isolation model dies. The role it connects as, mdm_operator, has
// SELECT on tenants and tenant_domains and nothing else. There is a test that
// proves it cannot read devices.
//
// Nothing in this package is reachable once a request has a tenant. By then
// the question is already answered and the claim carries it.
package directory

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUnknownHost = errors.New("directory: no tenant owns this hostname")
	ErrNotActive   = errors.New("directory: tenant is not active")
)

type Tenant struct {
	ID            uuid.UUID
	Name          string
	Slug          string
	Plan          string
	Status        string
	APIRatePerMin int
	// The plan's quotas and switches (T8). Features is what the row says
	// explicitly; Feature() lays it over the plan's defaults.
	DeviceCap  int
	AdminSeats int
	Features   map[string]bool
	// Region is where this tenant's data is kept (T11). A deployment
	// serves one region and refuses a tenant whose region is another.
	Region string
	// CreatedAt is the start of the PRD's first success metric: time from
	// sign-up to first enrolled device.
	CreatedAt time.Time
	// SessionsInvalidBefore revokes every session a tenant has at once.
	// It is read here, on the row this package already fetches for every
	// request, so checking it costs nothing extra.
	SessionsInvalidBefore time.Time
}

func (t Tenant) Active() bool { return t.Status == "active" || t.Status == "near_cap" }

// Exporting is the one inactive status the console still answers in: the
// Super Admin can download the export and nothing else runs.
func (t Tenant) Exporting() bool { return t.Status == "exporting" }

type Directory struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Directory, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Directory{pool: pool}, nil
}

func (d *Directory) Close() { d.pool.Close() }

// ResolveHost maps a request's hostname to its tenant. The port is stripped
// and the comparison is case-insensitive, because neither carries meaning and
// both are things a client controls.
func (d *Directory) ResolveHost(ctx context.Context, host string) (Tenant, error) {
	h := strings.ToLower(host)
	if i := strings.LastIndex(h, ":"); i != -1 && !strings.Contains(h, "]") {
		h = h[:i]
	}

	var t Tenant
	err := d.pool.QueryRow(ctx, `
		SELECT t.id, t.name, t.slug, t.plan, t.status, t.api_rate_per_min,
		       t.sessions_invalid_before, t.created_at, t.device_cap, t.admin_seats, t.features, t.region
		  FROM tenant_domains d
		  JOIN tenants t ON t.id = d.tenant_id
		 WHERE d.host = $1`, h).Scan(
		&t.ID, &t.Name, &t.Slug, &t.Plan, &t.Status, &t.APIRatePerMin,
		&t.SessionsInvalidBefore, &t.CreatedAt, &t.DeviceCap, &t.AdminSeats, &t.Features, &t.Region)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrUnknownHost
	}
	if err != nil {
		return Tenant{}, err
	}
	return t, nil
}

func (d *Directory) ResolveID(ctx context.Context, id uuid.UUID) (Tenant, error) {
	var t Tenant
	err := d.pool.QueryRow(ctx, `
		SELECT id, name, slug, plan, status, api_rate_per_min,
		       sessions_invalid_before, created_at, device_cap, admin_seats, features, region
		  FROM tenants WHERE id = $1`, id).Scan(
		&t.ID, &t.Name, &t.Slug, &t.Plan, &t.Status, &t.APIRatePerMin,
		&t.SessionsInvalidBefore, &t.CreatedAt, &t.DeviceCap, &t.AdminSeats, &t.Features, &t.Region)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrUnknownHost
	}
	if err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// ---------------------------------------------------------------- identity

// IdentityConfig is one tenant's identity provider, as stored. The client
// secret is still sealed: this package holds no key and could not open it.
type IdentityConfig struct {
	TenantID     uuid.UUID
	Issuer       string
	ClientID     string
	SecretSealed []byte
	RedirectURL  string
	RoleClaim    string
	// Protocol is "oidc" or "saml"; the SAML fields are empty under OIDC.
	Protocol        string
	SAMLSSOURL      string
	SAMLCertificate string
	// Single logout (0043). The signing key is sealed under the tenant's
	// key; the gateway opens it as it opens the client secret.
	SAMLSLOURL           string
	SAMLSigningKeySealed []byte
	SAMLSigningCert      string
}

var ErrNoIdentityConfig = errors.New("directory: tenant has no identity provider configured")

// Identity reads a tenant's provider settings.
//
// This is the one read that genuinely has to happen before anyone is signed
// in: the browser arrives at the sign-in route with nothing but a hostname,
// and we cannot send them to their provider without knowing which provider
// that is. It is scoped to the tenant the hostname already named, and the
// only sensitive column it returns is sealed.
//
// It widens this package by exactly one table, which is a thing worth saying
// out loud: the alternative was a second pool with cross-tenant reach, and
// one such pool, already proven unable to read devices, is better than two.
func (d *Directory) Identity(ctx context.Context, tenantID uuid.UUID) (IdentityConfig, error) {
	var c IdentityConfig
	err := d.pool.QueryRow(ctx, `
		SELECT tenant_id, issuer, client_id, client_secret_sealed,
		       redirect_url, role_claim, protocol, saml_sso_url, saml_certificate,
		       saml_slo_url, saml_sp_key_sealed, saml_sp_cert
		  FROM tenant_identity WHERE tenant_id = $1`, tenantID).Scan(
		&c.TenantID, &c.Issuer, &c.ClientID, &c.SecretSealed,
		&c.RedirectURL, &c.RoleClaim, &c.Protocol, &c.SAMLSSOURL, &c.SAMLCertificate,
		&c.SAMLSLOURL, &c.SAMLSigningKeySealed, &c.SAMLSigningCert)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityConfig{}, ErrNoIdentityConfig
	}
	if err != nil {
		return IdentityConfig{}, err
	}
	return c, nil
}

// probe exists only so the test can demonstrate what this role cannot reach.
// It is unexported, so no production code can call it.
func (d *Directory) probe(ctx context.Context, sql string) error {
	_, err := d.pool.Exec(ctx, sql)
	return err
}

// ActiveTenantIDs is for the platform's own background work, which has to
// visit every tenant in turn.
//
// It returns identifiers and nothing else on purpose. A caller that wanted
// names or plans would be building a cross-tenant view of customers, and
// this exists so a worker can mint a claim per tenant and then read
// everything else inside row-level security like any other code path.
func (d *Directory) ActiveTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id FROM tenants WHERE status IN ('active','near_cap') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// PrimaryHost is the hostname a link back to the tenant's console uses:
// the first one it was given, which is the one its people know.
func (d *Directory) PrimaryHost(ctx context.Context, id uuid.UUID) (string, error) {
	var host string
	err := d.pool.QueryRow(ctx, `
		SELECT host FROM tenant_domains WHERE tenant_id = $1 ORDER BY verified_at NULLS LAST, host LIMIT 1`,
		id).Scan(&host)
	return host, err
}

// SlugOf is the tenant's slug, for a sweep that needs a name on a line.
func (d *Directory) SlugOf(ctx context.Context, id uuid.UUID) (string, error) {
	var slug string
	err := d.pool.QueryRow(ctx, `SELECT slug FROM tenants WHERE id = $1`, id).Scan(&slug)
	return slug, err
}
