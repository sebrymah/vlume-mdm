package directory

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Getting a locked-out customer back in.
//
// A customer whose only administrator has lost their phone cannot sign in,
// and nobody on our side can read inside the customer to fix it: the
// operator's role has no SELECT on local_accounts (0044), on purpose.
//
// What the role does have is the same two INSERT policies that open the door
// for a customer's first administrator when the customer is made. This reuses
// exactly those, on a customer that already exists: one NEW Super Admin
// account, invited, and one invitation link for it. It reads nothing, changes
// nothing that is there, and the account that was locked out stays as it is.
// The new administrator can disable the old one from the Users page.
//
// That is a way into a customer's console for whoever holds the operator's
// login, so it is narrow and it leaves a line in operator_events, which the
// role can add to and never change.

var (
	// ErrNoSuchTenant is an unknown short name.
	ErrNoSuchTenant = errors.New("directory: no organisation has that short name")
	// ErrTenantNotLocal is an organisation that signs in through its own
	// identity provider: a local account there cannot sign in at all (0044),
	// so adding one would be a door that opens onto nothing.
	ErrTenantNotLocal = errors.New("directory: that organisation signs in through its own identity provider, not with accounts held here")
	// ErrTenantNotActive is a suspended, exporting or ended organisation.
	ErrTenantNotActive = errors.New("directory: that organisation is not active")
	// ErrAdminExists is an address that already has an account there. Use a
	// different address: the account that is there cannot be read or reset
	// from here.
	ErrAdminExists = errors.New("directory: that organisation already has an account with that address")
	// ErrBadAdminAddress is anything that is not one plain email address.
	ErrBadAdminAddress = errors.New("directory: that is not an email address")
	// ErrHostNotTheirs is a --host that does not belong to the organisation.
	ErrHostNotTheirs = errors.New("directory: that hostname does not belong to that organisation")
)

// AdminRecoveryLinkLife is how long the link works. It is a recovery, made
// for a person who is waiting, so it is a day and not the week a first
// invitation gets.
const AdminRecoveryLinkLife = 24 * time.Hour

// normaliseAdminAddress lower-cases and trims, and accepts one address and
// nothing else: no spaces, no second @, a dot in the domain.
func normaliseAdminAddress(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	at := strings.IndexByte(s, '@')
	if at < 1 || at != strings.LastIndexByte(s, '@') || len(s) > 254 {
		return "", false
	}
	domain := s[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", false
	}
	if strings.ContainsAny(s, " \t\r\n\"<>,;") {
		return "", false
	}
	return s, true
}

// AddTenantAdmin adds one invited Super Admin to an existing organisation
// that signs in with accounts held here, with one invitation whose SHA-256
// is inviteHash, and writes the line to operator_events, all in one
// transaction. It returns the hostname for the link: host if given and the
// organisation's own, otherwise its first.
func (d *Directory) AddTenantAdmin(ctx context.Context, slug, email, name string, inviteHash []byte, host, by string) (string, error) {
	addr, ok := normaliseAdminAddress(email)
	if !ok {
		return "", ErrBadAdminAddress
	}
	if len(inviteHash) != 32 {
		return "", errors.New("directory: the invitation must be the SHA-256 of a token")
	}
	name = strings.TrimSpace(name)
	if len(name) > 100 {
		name = name[:100]
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantID uuid.UUID
	var status string
	err = tx.QueryRow(ctx, `SELECT id, status FROM tenants WHERE slug = $1`, strings.ToLower(strings.TrimSpace(slug))).Scan(&tenantID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoSuchTenant
	}
	if err != nil {
		return "", err
	}
	if status != "active" {
		return "", ErrTenantNotActive
	}

	var protocol string
	err = tx.QueryRow(ctx, `SELECT protocol FROM tenant_identity WHERE tenant_id = $1`, tenantID).Scan(&protocol)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotLocal
	}
	if err != nil {
		return "", err
	}
	if protocol != "local" {
		return "", ErrTenantNotLocal
	}

	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		err = tx.QueryRow(ctx, `SELECT host FROM tenant_domains WHERE tenant_id = $1 ORDER BY host LIMIT 1`, tenantID).Scan(&host)
	} else {
		err = tx.QueryRow(ctx, `SELECT host FROM tenant_domains WHERE tenant_id = $1 AND host = $2`, tenantID, host).Scan(&host)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrHostNotTheirs
	}
	if err != nil {
		return "", err
	}

	accountID := uuid.New()
	// The same INSERT, under the same policy, that CreateTenant uses for a
	// first administrator. No RETURNING: the role may not read the row back.
	if _, err := tx.Exec(ctx, `
		INSERT INTO local_accounts (id, tenant_id, email, name, role, status, password_hash, created_by)
		VALUES ($1, $2, $3, $4, 'super_admin', 'invited', '', $5)`,
		accountID, tenantID, addr, name, by); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return "", ErrAdminExists
		}
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO local_tokens (tenant_id, account_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, 'invite', $3, now() + $4::interval)`,
		tenantID, accountID, inviteHash, "24 hours"); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO operator_events (actor, action, target, detail) VALUES ($1, $2, $3, $4)`,
		by, "tenant.admin_added", strings.ToLower(strings.TrimSpace(slug)), addr); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return host, nil
}
