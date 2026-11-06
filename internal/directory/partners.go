package directory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// T7: partners. An operator-side account that manages many tenants under
// a shared brand, and sees nothing of anyone else's.

var (
	ErrNoSuchPartner   = errors.New("directory: no such partner")
	ErrPartnerCap      = errors.New("directory: the partner's tenant cap is reached")
	ErrNotYourTenant   = errors.New("directory: that tenant is not this partner's")
	ErrBadPartnerToken = errors.New("directory: partner token not accepted")
)

type Partner struct {
	ID          uuid.UUID
	Slug        string
	Name        string
	ProductName string
	Colour      string
	LegalFooter string
	TenantCap   int
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	Tenants     int
}

const PartnerTokenPrefix = "mdm_prt_"

// CreatePartner makes the account and returns its token, once.
func (d *Directory) CreatePartner(ctx context.Context, slug, name, product, colour, footer string, cap int) (Partner, string, error) {
	slug, err := cleanSlug(slug)
	if err != nil {
		return Partner{}, "", err
	}
	if strings.TrimSpace(name) == "" {
		return Partner{}, "", errors.New("directory: a partner needs a name")
	}
	if cap <= 0 {
		cap = 25
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Partner{}, "", err
	}
	token := PartnerTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	var p Partner
	err = d.pool.QueryRow(ctx, `
		INSERT INTO partners (slug, name, token_hash, product_name, brand_colour, legal_footer, tenant_cap)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, slug, name, product_name, brand_colour, legal_footer, tenant_cap, created_at`,
		slug, strings.TrimSpace(name), sum[:], strings.TrimSpace(product), strings.TrimSpace(colour),
		strings.TrimSpace(footer), cap).Scan(&p.ID, &p.Slug, &p.Name, &p.ProductName, &p.Colour,
		&p.LegalFooter, &p.TenantCap, &p.CreatedAt)
	if isUnique(err) {
		return Partner{}, "", ErrSlugTaken
	}
	if err != nil {
		return Partner{}, "", err
	}
	return p, token, nil
}

// PartnerByToken resolves a presented token. Revocation is a new token:
// RotatePartnerToken replaces the hash and the old one stops working.
func (d *Directory) PartnerByToken(ctx context.Context, token string) (Partner, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, PartnerTokenPrefix))
	if err != nil || len(raw) != 32 || !strings.HasPrefix(token, PartnerTokenPrefix) {
		return Partner{}, ErrBadPartnerToken
	}
	sum := sha256.Sum256(raw)
	p, err := d.scanPartner(ctx, `WHERE p.token_hash = $1`, sum[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return Partner{}, ErrBadPartnerToken
	}
	if err != nil {
		return Partner{}, err
	}
	_, _ = d.pool.Exec(ctx, `UPDATE partners SET last_used_at = now() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, p.ID)
	return p, nil
}

func (d *Directory) PartnerBySlug(ctx context.Context, slug string) (Partner, error) {
	p, err := d.scanPartner(ctx, `WHERE p.slug = $1`, slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return Partner{}, ErrNoSuchPartner
	}
	return p, err
}

func (d *Directory) scanPartner(ctx context.Context, where string, arg any) (Partner, error) {
	var p Partner
	err := d.pool.QueryRow(ctx, `
		SELECT p.id, p.slug, p.name, p.product_name, p.brand_colour, p.legal_footer, p.tenant_cap,
		       p.created_at, p.last_used_at,
		       (SELECT count(*) FROM tenants t WHERE t.partner_id = p.id AND t.status <> 'offboarded')
		  FROM partners p `+where, arg).Scan(&p.ID, &p.Slug, &p.Name, &p.ProductName, &p.Colour,
		&p.LegalFooter, &p.TenantCap, &p.CreatedAt, &p.LastUsedAt, &p.Tenants)
	return p, err
}

func (d *Directory) ListPartners(ctx context.Context) ([]Partner, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT p.id, p.slug, p.name, p.product_name, p.brand_colour, p.legal_footer, p.tenant_cap,
		       p.created_at, p.last_used_at,
		       (SELECT count(*) FROM tenants t WHERE t.partner_id = p.id AND t.status <> 'offboarded')
		  FROM partners p ORDER BY p.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Partner{}
	for rows.Next() {
		var p Partner
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.ProductName, &p.Colour, &p.LegalFooter,
			&p.TenantCap, &p.CreatedAt, &p.LastUsedAt, &p.Tenants); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RotatePartnerToken replaces the token; the old one is dead at once.
func (d *Directory) RotatePartnerToken(ctx context.Context, slug string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	tag, err := d.pool.Exec(ctx, `UPDATE partners SET token_hash = $2 WHERE slug = $1`, slug, sum[:])
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNoSuchPartner
	}
	return PartnerTokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// CreateTenantFor is CreateTenant under a partner: counted against the
// partner's cap, marked with the partner, started with the partner's
// brand. The brand is the tenant's own row from then on.
func (d *Directory) CreateTenantFor(ctx context.Context, partner Partner, in NewTenant) (uuid.UUID, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	var have int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE partner_id = $1 AND status <> 'offboarded'`, partner.ID).Scan(&have); err != nil {
		return uuid.Nil, err
	}
	if have >= partner.TenantCap {
		return uuid.Nil, fmt.Errorf("%w: %d of %d", ErrPartnerCap, have, partner.TenantCap)
	}
	id, err := createTenant(ctx, tx, in)
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE tenants SET partner_id = $2 WHERE id = $1`, id, partner.ID); err != nil {
		return uuid.Nil, err
	}
	if partner.ProductName != "" {
		colour := partner.Colour
		if colour == "" {
			colour = "#0F6E66"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_branding (tenant_id, product_name, legal_footer, brand_colour, mark_letter)
			VALUES ($1, $2, $3, $4, $5)`, id, partner.ProductName, partner.LegalFooter, colour,
			strings.ToUpper(partner.ProductName[:1])); err != nil {
			return uuid.Nil, err
		}
	}
	return id, tx.Commit(ctx)
}

// AssignPartner moves an existing tenant under a partner (operator only).
func (d *Directory) AssignPartner(ctx context.Context, tenantSlug, partnerSlug string) error {
	p, err := d.PartnerBySlug(ctx, partnerSlug)
	if err != nil {
		return err
	}
	tag, err := d.pool.Exec(ctx, `UPDATE tenants SET partner_id = $2 WHERE slug = $1`, tenantSlug, p.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSlug
	}
	return nil
}

// TenantsOf is the partner's own list and nobody else's.
func (d *Directory) TenantsOf(ctx context.Context, partner Partner) ([]Summary, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT t.id, t.name, t.slug, t.plan, t.status, t.created_at,
		       coalesce(array_agg(h.host ORDER BY h.host) FILTER (WHERE h.host IS NOT NULL), '{}')
		  FROM tenants t LEFT JOIN tenant_domains h ON h.tenant_id = t.id
		 WHERE t.partner_id = $1
		 GROUP BY t.id ORDER BY t.created_at`, partner.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Summary{}
	for rows.Next() {
		var s Summary
		if err := rows.Scan(&s.ID, &s.Name, &s.Slug, &s.Plan, &s.Status, &s.CreatedAt, &s.Hosts); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// OwnTenant resolves a slug within the partner's own tenants, or refuses.
func (d *Directory) OwnTenant(ctx context.Context, partner Partner, slug string) (Summary, error) {
	ts, err := d.TenantsOf(ctx, partner)
	if err != nil {
		return Summary{}, err
	}
	for _, t := range ts {
		if t.Slug == slug {
			return t, nil
		}
	}
	return Summary{}, ErrNotYourTenant
}
