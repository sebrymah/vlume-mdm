package directory

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Onboarding is the one thing the operator does TO a tenant rather than for
// it, and it lives here because this package owns the only connection that
// can see across tenants.
//
// What the operator writes: the tenant, its hostname, which identity provider
// its people sign in against, and ONE role mapping so the first administrator
// can get in. What the operator still cannot do afterwards: read a device, a
// command, an audit entry or a policy. The grants in 0014_onboarding.sql are
// exactly those four tables, and the probe test in directory_test.go proves
// the rest are still out of reach.
//
// Why the first mapping is the operator's: to configure sign-in you have to
// be signed in. Somebody breaks that circle once per tenant, and it is the
// person who knows which group at the customer's directory holds the people
// who asked for this.

var (
	ErrBadSlug    = errors.New("directory: a slug is lowercase letters, digits and hyphens")
	ErrBadHost    = errors.New("directory: that is not a hostname")
	ErrSlugTaken  = errors.New("directory: that slug is already in use")
	ErrHostTaken  = errors.New("directory: that hostname already belongs to a tenant")
	ErrNoSuchSlug = errors.New("directory: no tenant has that slug")
)

type NewTenant struct {
	Name string
	Slug string
	Plan string
	// Host is where the console answers. It decides the tenant on every
	// request, which is the reason it is set here and not inside the
	// tenant: a tenant choosing its own hostname would be a tenant choosing
	// to answer on somebody else's.
	Host string

	// Sign-in. The redirect URL is derived from Host rather than typed, so
	// it cannot disagree with where the console actually is.
	Issuer             string
	ClientID           string
	ClientSecretSealed []byte
	RoleClaim          string
	// Protocol is "oidc" (the default) or "saml". Under SAML, Issuer is
	// the provider's entity id, ClientID and the secret are not taken (our
	// entity id is derived from the hostname, and there is no secret), and
	// the two fields below are required.
	Protocol        string
	SAMLSSOURL      string
	SAMLCertificate string
	// SAMLSLOURL is the provider's single logout URL, optional (0043).
	SAMLSLOURL string
	// AdminGroup is the claim value that becomes super_admin. One mapping,
	// so the first administrator can sign in and make the rest.
	AdminGroup string

	// Local sign-in (0044): a tenant with no identity provider. Protocol
	// "local" takes no issuer, no secret and no admin group, and instead
	// makes the first administrator an account here: either with the
	// password they chose (OwnerPasswordHash, from the self-service
	// sign-up) or invited by a link (OwnerInviteHash, from tenantctl).
	OwnerEmail        string
	OwnerName         string
	OwnerPasswordHash string
	OwnerInviteHash   []byte
	OwnerCreatedBy    string

	// Region is where the tenant's data is kept (T11); empty takes the
	// deployment's default.
	Region string

	// KeySealed is the tenant's own data key (T3), sealed under the
	// platform's master key: version 1, made by whoever creates the
	// tenant, under which ClientSecretSealed was sealed.
	KeySealed []byte

	// ConsoleURL, when set, is where the console actually answers, and the
	// redirect URL is derived from it instead of from Host. It may only be
	// https on Host itself, or plain http on this machine: the one case
	// where the console is not at https://<Host> is a local demonstration.
	ConsoleURL string
}

func (n NewTenant) consoleBase() string {
	if n.ConsoleURL != "" {
		return strings.TrimSuffix(n.ConsoleURL, "/")
	}
	return "https://" + n.Host
}

// RedirectURL is where the provider sends the browser back: the OIDC
// callback, or the SAML assertion consumer service.
func (n NewTenant) RedirectURL() string {
	switch n.Protocol {
	case "saml":
		return n.consoleBase() + "/signin/saml"
	case "local":
		// Nothing comes back from anywhere; the column is not null, and
		// the sign-in page is the honest value.
		return n.consoleBase() + "/signin"
	}
	return n.consoleBase() + "/signin/callback"
}

// InviteLink is where the first administrator of a local tenant sets a
// password, given the token whose hash was stored.
func (n NewTenant) InviteLink(token string) string {
	return n.consoleBase() + "/signin/local/accept/" + token
}

// EntityID is our name to a SAML provider, and the address of our metadata.
func (n NewTenant) EntityID() string { return n.consoleBase() + "/saml/metadata" }

// checkConsoleURL refuses a ConsoleURL that would send sign-ins anywhere
// other than this tenant's own hostname.
func checkConsoleURL(raw, host string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("directory: the console URL is a scheme and a host, nothing else")
	}
	if !strings.EqualFold(u.Hostname(), host) {
		return errors.New("directory: the console URL must be on the tenant's own hostname")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := strings.ToLower(u.Hostname())
		if h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "127.0.0.1" {
			return nil
		}
	}
	return errors.New("directory: the console URL must be https, or http on this machine only")
}

func cleanSlug(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 40 {
		return "", ErrBadSlug
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return "", ErrBadSlug
		}
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return "", ErrBadSlug
	}
	if reservedSlugs[s] {
		return "", ErrSlugTaken
	}
	return s, nil
}

// reservedSlugs are names a customer cannot have, because each is a hostname
// the platform or its operator uses under the same domain: the operator's own
// host (app), the public site (www), mail and name-server records, and the
// words people would trust on sight (admin, login, support). A customer on one
// would either shadow the operator's page or look like it.
var reservedSlugs = map[string]bool{
	"app": true, "www": true, "admin": true, "api": true, "mail": true, "smtp": true,
	"imap": true, "pop": true, "mx": true, "ns": true, "ns1": true, "ns2": true,
	"status": true, "support": true, "help": true, "docs": true, "login": true,
	"signin": true, "signup": true, "auth": true, "sso": true, "static": true,
	"cdn": true, "console": true, "portal": true, "dashboard": true, "billing": true,
	"security": true, "root": true, "mdm": true, "vlume": true, "vlumesec": true,
	// The owner's console answers on one of these (0048).
	"ops": true, "operator": true, "operators": true, "platform": true, "system": true, "owner": true,
}

func cleanHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if h == "" || strings.ContainsAny(h, "/:@ \t\r\n") || !strings.Contains(h, ".") {
		return "", ErrBadHost
	}
	return h, nil
}

// CreateTenant writes everything a new tenant needs to let its first
// administrator in, in one transaction. A tenant with no hostname, or a
// hostname with no tenant, is a half-created row somebody will find later.
func (d *Directory) CreateTenant(ctx context.Context, in NewTenant) (uuid.UUID, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	id, err := createTenant(ctx, tx, in)
	if err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}

// createTenant is the body, on a transaction the caller owns, so that a
// self-service sign-up can create the tenant and spend its one-time token in
// the same unit of work (signup.go).
func createTenant(ctx context.Context, tx pgx.Tx, in NewTenant) (uuid.UUID, error) {
	slug, err := cleanSlug(in.Slug)
	if err != nil {
		return uuid.Nil, err
	}
	host, err := cleanHost(in.Host)
	if err != nil {
		return uuid.Nil, err
	}
	in.Slug, in.Host = slug, host
	if strings.TrimSpace(in.Name) == "" {
		return uuid.Nil, errors.New("directory: a tenant needs a name")
	}
	if in.Plan == "" {
		in.Plan = "starter"
	}
	switch in.Protocol {
	case "", "oidc":
		in.Protocol = "oidc"
		if in.Issuer == "" || in.ClientID == "" || len(in.ClientSecretSealed) == 0 {
			return uuid.Nil, errors.New(
				"directory: sign-in needs an issuer, a client id and a sealed client secret")
		}
		if !strings.HasPrefix(in.Issuer, "https://") && !loopbackIssuer(in.Issuer) {
			return uuid.Nil, errors.New("directory: the issuer must be an https:// address")
		}
		in.SAMLSSOURL, in.SAMLCertificate, in.SAMLSLOURL = "", "", ""
	case "saml":
		if in.Issuer == "" || in.SAMLSSOURL == "" || in.SAMLCertificate == "" {
			return uuid.Nil, errors.New(
				"directory: SAML sign-in needs the provider's entity id, sign-in url and certificate")
		}
		if !strings.HasPrefix(in.SAMLSSOURL, "https://") && !loopbackIssuer(in.SAMLSSOURL) {
			return uuid.Nil, errors.New("directory: the SAML sign-in url must be an https:// address")
		}
		if in.SAMLSLOURL != "" && !strings.HasPrefix(in.SAMLSLOURL, "https://") && !loopbackIssuer(in.SAMLSLOURL) {
			return uuid.Nil, errors.New("directory: the SAML logout url must be an https:// address")
		}
		if !strings.HasPrefix(in.SAMLCertificate, "-----BEGIN CERTIFICATE-----") {
			return uuid.Nil, errors.New("directory: the SAML certificate must be PEM (use identity.ParseCertificate)")
		}
		in.ClientID, in.ClientSecretSealed = in.EntityID(), nil
	case "local":
		in.OwnerEmail = strings.ToLower(strings.TrimSpace(in.OwnerEmail))
		if !strings.Contains(in.OwnerEmail, "@") || len(in.OwnerEmail) < 3 {
			return uuid.Nil, errors.New("directory: a tenant without an identity provider needs its first administrator's email address")
		}
		if in.OwnerPasswordHash == "" && len(in.OwnerInviteHash) == 0 {
			return uuid.Nil, errors.New("directory: the first administrator needs a password or an invitation, or nobody can sign in")
		}
		in.Issuer, in.ClientID, in.ClientSecretSealed = "", "", nil
		in.SAMLSSOURL, in.SAMLCertificate, in.SAMLSLOURL = "", "", ""
	default:
		return uuid.Nil, errors.New("directory: the protocol is oidc, saml or local")
	}
	if in.RoleClaim == "" {
		in.RoleClaim = "groups"
	}
	if err := checkConsoleURL(in.ConsoleURL, host); err != nil {
		return uuid.Nil, err
	}
	if in.Protocol != "local" && strings.TrimSpace(in.AdminGroup) == "" {
		return uuid.Nil, errors.New(
			"directory: name the group whose members are the first administrators, " +
				"or nobody will be able to sign in")
	}

	var id uuid.UUID
	region := strings.TrimSpace(in.Region)
	if region == "" {
		region = "eu-west"
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, plan, status, region)
		VALUES ($1, $2, $3, 'active', $4)
		RETURNING id`, strings.TrimSpace(in.Name), slug, in.Plan, region).Scan(&id)
	if isUnique(err) {
		return uuid.Nil, ErrSlugTaken
	}
	if err != nil {
		return uuid.Nil, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_domains (host, tenant_id, verified_at)
		VALUES ($1, $2, now())`, host, id); err != nil {
		if isUnique(err) {
			return uuid.Nil, ErrHostTaken
		}
		return uuid.Nil, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_identity
		  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim,
		   protocol, saml_sso_url, saml_certificate, saml_slo_url)
		VALUES ($1, $2, $3, coalesce($4, ''::bytea), $5, $6, $7, $8, $9, $10)`,
		id, in.Issuer, in.ClientID, in.ClientSecretSealed, in.RedirectURL(),
		in.RoleClaim, in.Protocol, in.SAMLSSOURL, in.SAMLCertificate, in.SAMLSLOURL); err != nil {
		return uuid.Nil, err
	}

	if len(in.KeySealed) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenant_keys (tenant_id, version, key_sealed) VALUES ($1, 1, $2)`,
			id, in.KeySealed); err != nil {
			return uuid.Nil, err
		}
	}

	if in.Protocol == "local" {
		// The first administrator: an account, not a group. Written by the
		// operator's role through the one INSERT policy it has on this
		// table, which allows a Super Admin and nothing else, and no
		// RETURNING because it may not read the row back.
		status := "invited"
		if in.OwnerPasswordHash != "" {
			status = "active"
		}
		by := in.OwnerCreatedBy
		if by == "" {
			by = "tenant creation"
		}
		accountID := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO local_accounts (id, tenant_id, email, name, role, status, password_hash, password_set_at, created_by)
			VALUES ($1, $2, $3, $4, 'super_admin', $5, $6, CASE WHEN $6 <> '' THEN now() END, $7)`,
			accountID, id, in.OwnerEmail, strings.TrimSpace(in.OwnerName), status, in.OwnerPasswordHash, by); err != nil {
			return uuid.Nil, err
		}
		if len(in.OwnerInviteHash) > 0 {
			if _, err := tx.Exec(ctx, `
				INSERT INTO local_tokens (tenant_id, account_id, purpose, token_hash, expires_at)
				VALUES ($1, $2, 'invite', $3, now() + interval '7 days')`,
				id, accountID, in.OwnerInviteHash); err != nil {
				return uuid.Nil, err
			}
		}
		return id, nil
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_role_map (tenant_id, claim_value, role)
		VALUES ($1, $2, 'super_admin')`, id, strings.TrimSpace(in.AdminGroup)); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// AddHost gives an existing tenant another hostname. The common case is a
// tenant moving from the operator's subdomain to their own domain (T5), and
// both should answer during the changeover.
func (d *Directory) AddHost(ctx context.Context, slug, host string) error {
	host, err := cleanHost(host)
	if err != nil {
		return err
	}
	tag, err := d.pool.Exec(ctx, `
		INSERT INTO tenant_domains (host, tenant_id, verified_at)
		SELECT $1, id, now() FROM tenants WHERE slug = $2`, host, slug)
	if isUnique(err) {
		return ErrHostTaken
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSlug
	}
	return nil
}

// SetStatus suspends or reactivates. A suspended tenant's hostname still
// resolves, so a visitor is told the tenant is not active rather than that
// it does not exist, which is the difference between a billing conversation
// and a support ticket about a vanished product.
func (d *Directory) SetStatus(ctx context.Context, slug, status string) error {
	switch status {
	case "active", "suspended", "exporting":
	default:
		return fmt.Errorf("directory: status is active, suspended or exporting, not %q", status)
	}
	tag, err := d.pool.Exec(ctx,
		`UPDATE tenants SET status = $2 WHERE slug = $1`, slug, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSlug
	}
	return nil
}

// Summary is what the operator may see about a tenant, which is the
// administrative shell and nothing from inside it.
type Summary struct {
	ID        uuid.UUID
	Name      string
	Slug      string
	Plan      string
	Status    string
	Region    string
	Hosts     []string
	CreatedAt time.Time
}

func (d *Directory) List(ctx context.Context) ([]Summary, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT t.id, t.name, t.slug, t.plan, t.status, t.created_at, t.region,
		       coalesce(array_agg(h.host ORDER BY h.host)
		                FILTER (WHERE h.host IS NOT NULL), '{}')
		  FROM tenants t
		  LEFT JOIN tenant_domains h ON h.tenant_id = t.id
		 GROUP BY t.id
		 ORDER BY t.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Summary{}
	for rows.Next() {
		var s Summary
		if err := rows.Scan(&s.ID, &s.Name, &s.Slug, &s.Plan, &s.Status,
			&s.CreatedAt, &s.Region, &s.Hosts); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func isUnique(err error) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

var _ = pgx.ErrNoRows

// loopbackIssuer allows a plain-HTTP identity provider only on this machine,
// which is what a local demonstration runs. Anything that leaves the host
// over http:// is refused.
func loopbackIssuer(issuer string) bool {
	return strings.HasPrefix(issuer, "http://127.0.0.1") ||
		strings.HasPrefix(issuer, "http://localhost")
}
