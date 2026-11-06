package directory

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Self-service sign-up, the operator's side of it.
//
// A stranger asks; we send a link to the address they gave; opening the link
// is the proof the address is theirs; with that proof they may create ONE
// tenant, once, within the day. Everything the stranger can cause before the
// proof is a row in signups and one email to an address they typed. The caps
// below bound how many of those.
//
// What is deliberately NOT here: a tenant created at the moment of asking.
// A slug or a hostname reserved by an unverified request is a slug somebody
// else cannot have, held by nobody.

var (
	ErrNotWorkEmail   = errors.New("directory: sign-up needs a work email address")
	ErrTooManySignups = errors.New("directory: too many sign-ups from this address or domain today")
	ErrNoSuchSignup   = errors.New("directory: that sign-up link is not valid")
	ErrSignupExpired  = errors.New("directory: that sign-up link has expired")
	ErrSignupFinished = errors.New("directory: that sign-up has already been used")
)

const (
	// SignupTTL is how long a link stays usable. A day: long enough for a
	// mail filter and a lunch break, short enough that a leaked link is not
	// a standing invitation.
	SignupTTL = 24 * time.Hour
	// The caps. Per domain because a company has a handful of people who
	// might reasonably try this; per address because an abuser has one.
	MaxSignupsPerDomainPerDay = 5
	MaxSignupsPerIPPerDay     = 10
)

// The providers anyone can get an address at live in freemail.go: a tenant
// is a company, and the address that creates it has to be one the company
// controls, or the proof proves nothing about who is asking.

// WorkEmail checks and tidies the address a stranger typed. It returns the
// address and its domain, lower-cased, or why it is not acceptable.
func WorkEmail(s string) (addr, domain string, err error) {
	s = strings.TrimSpace(s)
	a, perr := mail.ParseAddress(s)
	if perr != nil || a.Name != "" || a.Address != s {
		// A display name, or anything that did not round-trip, is not a
		// bare address and is refused rather than tidied.
		return "", "", ErrNotWorkEmail
	}
	at := strings.LastIndex(a.Address, "@")
	if at <= 0 || at == len(a.Address)-1 {
		return "", "", ErrNotWorkEmail
	}
	addr = strings.ToLower(a.Address)
	domain = addr[at+1:]
	if !strings.Contains(domain, ".") || IsFreeMail(domain) {
		return "", "", ErrNotWorkEmail
	}
	return addr, domain, nil
}

type Signup struct {
	ID        uuid.UUID
	Email     string
	Domain    string
	Company   string
	Slug      string
	ExpiresAt time.Time
	Verified  bool
	Finished  bool
	TenantID  uuid.UUID
}

// StartSignup records a request and returns its id. tokenHash is the SHA-256
// of the token the link will carry; the token itself never reaches this
// package. A second request from the same address replaces the first, so
// "I never got the email" is answered by asking again rather than by a
// support ticket, and so an address can hold at most one open link.
func (d *Directory) StartSignup(ctx context.Context, email, company, ip string,
	tokenHash []byte) (uuid.UUID, error) {

	addr, domain, err := WorkEmail(email)
	if err != nil {
		return uuid.Nil, err
	}
	company = strings.TrimSpace(company)
	if company == "" || len(company) > 120 {
		return uuid.Nil, errors.New("directory: sign-up needs the company's name")
	}
	if len(tokenHash) != 32 {
		return uuid.Nil, errors.New("directory: the token hash is not a SHA-256")
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = "unknown"
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	// The caps, counted inside the transaction so two requests racing
	// cannot both squeeze under them. Replaced requests still count: a
	// request that was made is a request that was made.
	var byDomain, byIP int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE email_domain = $1),
		       count(*) FILTER (WHERE requested_ip = $2)
		  FROM signups
		 WHERE requested_at > now() - interval '24 hours'`, domain, ip).Scan(&byDomain, &byIP); err != nil {
		return uuid.Nil, err
	}
	if byDomain >= MaxSignupsPerDomainPerDay || byIP >= MaxSignupsPerIPPerDay {
		return uuid.Nil, ErrTooManySignups
	}

	// Replace any open link for this address: the old token stops working
	// the moment the new one is issued.
	if _, err := tx.Exec(ctx, `
		UPDATE signups SET expires_at = now()
		 WHERE email = $1 AND finished_at IS NULL AND expires_at > now()`, addr); err != nil {
		return uuid.Nil, err
	}

	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO signups (email, email_domain, company, requested_ip, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, now() + $6::interval)
		RETURNING id`, addr, domain, company, ip, tokenHash, SignupTTL.String()).Scan(&id); err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}

// OpenSignup is what happens when the link is followed: the address is now
// proven. It returns the sign-up, or why the link does not work, in words
// the page can show. An expired or used link says so rather than "not
// found", because the person holding it did get it from us.
func (d *Directory) OpenSignup(ctx context.Context, tokenHash []byte) (Signup, error) {
	s, err := d.signupByHash(ctx, d.pool, tokenHash)
	if err != nil {
		return Signup{}, err
	}
	if !s.Verified {
		if _, err := d.pool.Exec(ctx,
			`UPDATE signups SET verified_at = now() WHERE id = $1`, s.ID); err != nil {
			return Signup{}, err
		}
		s.Verified = true
	}
	return s, nil
}

// SetSignupSlug saves the slug chosen on the first page, so the second can
// show the redirect URL the provider must be told. It is a draft: whether
// the slug is free is decided when the tenant is created.
func (d *Directory) SetSignupSlug(ctx context.Context, tokenHash []byte, slug string) (Signup, error) {
	s, err := d.signupByHash(ctx, d.pool, tokenHash)
	if err != nil {
		return Signup{}, err
	}
	if strings.TrimSpace(slug) == "" {
		// "Change it": the draft is cleared and the first page comes back.
		if _, err := d.pool.Exec(ctx,
			`UPDATE signups SET slug = NULL WHERE id = $1`, s.ID); err != nil {
			return Signup{}, err
		}
		s.Slug = ""
		return s, nil
	}
	slug, err = cleanSlug(slug)
	if err != nil {
		return Signup{}, err
	}
	var taken bool
	if err := d.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM tenants WHERE slug = $1)`, slug).Scan(&taken); err != nil {
		return Signup{}, err
	}
	if taken {
		return Signup{}, ErrSlugTaken
	}
	if _, err := d.pool.Exec(ctx,
		`UPDATE signups SET slug = $2 WHERE id = $1`, s.ID, slug); err != nil {
		return Signup{}, err
	}
	s.Slug = slug
	return s, nil
}

// FinishSignup creates the tenant and spends the link, in one transaction.
//
// The UPDATE is the single-use guard. It matches only a row that is still
// open, and if it matches nothing the whole thing rolls back, including the
// tenant: two people racing on the same link get one tenant and one
// refusal, never two tenants.
func (d *Directory) FinishSignup(ctx context.Context, tokenHash []byte, in NewTenant) (uuid.UUID, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	s, err := d.signupByHash(ctx, tx, tokenHash)
	if err != nil {
		return uuid.Nil, err
	}
	if in.Slug == "" {
		in.Slug = s.Slug
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = s.Company
	}
	id, err := createTenant(ctx, tx, in)
	if err != nil {
		return uuid.Nil, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE signups SET finished_at = now(), tenant_id = $2
		 WHERE id = $1 AND finished_at IS NULL AND expires_at > now()`, s.ID, id)
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() != 1 {
		return uuid.Nil, ErrSignupFinished
	}
	return id, tx.Commit(ctx)
}

// SignupResult is what the done page shows after a finish: the host and
// the group, read back from the record rather than remembered in a cookie.
func (d *Directory) SignupResult(ctx context.Context, tokenHash []byte) (Signup, Summary, error) {
	var s Signup
	var expires time.Time
	var verified, finished *time.Time
	var tenant *uuid.UUID
	var slug *string
	err := d.pool.QueryRow(ctx, `
		SELECT id, email, email_domain, company, slug, expires_at, verified_at, finished_at, tenant_id
		  FROM signups WHERE token_hash = $1`, tokenHash).Scan(
		&s.ID, &s.Email, &s.Domain, &s.Company, &slug, &expires, &verified, &finished, &tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return Signup{}, Summary{}, ErrNoSuchSignup
	}
	if err != nil {
		return Signup{}, Summary{}, err
	}
	if finished == nil || tenant == nil {
		return Signup{}, Summary{}, ErrNoSuchSignup
	}
	s.Finished, s.TenantID = true, *tenant
	if slug != nil {
		s.Slug = *slug
	}
	var sum Summary
	err = d.pool.QueryRow(ctx, `
		SELECT t.id, t.name, t.slug, t.plan, t.status, t.created_at,
		       coalesce(array_agg(h.host ORDER BY h.host)
		                FILTER (WHERE h.host IS NOT NULL), '{}')
		  FROM tenants t
		  LEFT JOIN tenant_domains h ON h.tenant_id = t.id
		 WHERE t.id = $1
		 GROUP BY t.id`, *tenant).Scan(&sum.ID, &sum.Name, &sum.Slug, &sum.Plan,
		&sum.Status, &sum.CreatedAt, &sum.Hosts)
	return s, sum, err
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// signupByHash reads an OPEN sign-up: not finished, not expired. The order
// of the checks is the order of the messages: a used link says "used"
// even when it has also since expired.
func (d *Directory) signupByHash(ctx context.Context, q querier, tokenHash []byte) (Signup, error) {
	var s Signup
	var expires time.Time
	var verified, finished *time.Time
	var tenant *uuid.UUID
	var slug *string
	err := q.QueryRow(ctx, `
		SELECT id, email, email_domain, company, slug, expires_at, verified_at, finished_at, tenant_id
		  FROM signups WHERE token_hash = $1`, tokenHash).Scan(
		&s.ID, &s.Email, &s.Domain, &s.Company, &slug, &expires, &verified, &finished, &tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return Signup{}, ErrNoSuchSignup
	}
	if err != nil {
		return Signup{}, err
	}
	if finished != nil {
		return Signup{}, ErrSignupFinished
	}
	if !expires.After(time.Now()) {
		return Signup{}, ErrSignupExpired
	}
	s.ExpiresAt = expires
	s.Verified = verified != nil
	if slug != nil {
		s.Slug = *slug
	}
	return s, nil
}

// ------------------------------------------------------------ the view

// SignupRow is one sign-up as the operator sees it. There is no token and
// no hash in it: the view is for finding a stuck sign-up, and a listing
// that could be pasted into a browser would be a listing of working links.
type SignupRow struct {
	Email       string
	Domain      string
	Company     string
	Slug        string
	RequestedIP string
	RequestedAt time.Time
	ExpiresAt   time.Time
	Verified    bool
	// State is one of: waiting (link sent, not opened), opened (address
	// proven, not finished), finished, expired, replaced.
	State      string
	TenantSlug string
}

// ListSignups lists sign-ups, open ones only unless all is set. Open means
// the link still works: not finished, not expired. Newest first, because
// the one somebody is asking about is the one they just made.
func (d *Directory) ListSignups(ctx context.Context, all bool) ([]SignupRow, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT s.email, s.email_domain, s.company, coalesce(s.slug, ''), s.requested_ip,
		       s.requested_at, s.expires_at, s.verified_at IS NOT NULL,
		       s.finished_at IS NOT NULL, coalesce(t.slug, ''),
		       EXISTS (SELECT 1 FROM signups n
		                WHERE n.email = s.email AND n.requested_at > s.requested_at)
		  FROM signups s
		  LEFT JOIN tenants t ON t.id = s.tenant_id
		 WHERE $1 OR (s.finished_at IS NULL AND s.expires_at > now())
		 ORDER BY s.requested_at DESC`, all)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SignupRow{}
	for rows.Next() {
		var r SignupRow
		var finished, replaced bool
		if err := rows.Scan(&r.Email, &r.Domain, &r.Company, &r.Slug, &r.RequestedIP,
			&r.RequestedAt, &r.ExpiresAt, &r.Verified, &finished, &r.TenantSlug, &replaced); err != nil {
			return nil, err
		}
		switch {
		case finished:
			r.State = "finished"
		case replaced && !r.ExpiresAt.After(time.Now()):
			r.State = "replaced"
		case !r.ExpiresAt.After(time.Now()):
			r.State = "expired"
		case r.Verified:
			r.State = "opened"
		default:
			r.State = "waiting"
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CancelSignup ends an open link for an address. It is the operator's one
// move against a sign-up they do not like the look of: the link stops
// working and the row stays, so the request is still counted against the
// caps and still visible with --all.
func (d *Directory) CancelSignup(ctx context.Context, email string) error {
	addr, _, err := WorkEmail(email)
	if err != nil {
		return err
	}
	tag, err := d.pool.Exec(ctx, `
		UPDATE signups SET expires_at = now()
		 WHERE email = $1 AND finished_at IS NULL AND expires_at > now()`, addr)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSignup
	}
	return nil
}
