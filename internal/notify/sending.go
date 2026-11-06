package notify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"platform/internal/data"
)

// A tenant's own sending domain.
//
// Until now mail left through the operator's server with a From address the
// tenant chose, which fails SPF and carries no DKIM signature. At a customer
// running DMARC with p=reject that mail does not arrive; at one running
// p=none it lands in a spam folder and nobody reads the notification about
// their stolen laptop.
//
// THE CONTROL. Nothing signs mail as a domain until the tenant has proven
// they control it, and the proof is the DKIM record itself: this platform
// generates a key, the tenant publishes the public half in their own DNS,
// and we look it up. Publishing at selector._domainkey.theirdomain requires
// control of that zone.
//
// Without that check a form field would let any tenant have this platform
// sign mail as any domain in the world, which is a phishing service with an
// enrolment flow.

const (
	// DKIMKeyBits is 2048. RFC 8301 made 1024 too weak to accept, and 4096
	// does not fit a single DNS TXT string without splitting, which every
	// administrator gets wrong at least once.
	DKIMKeyBits = 2048
	// DKIMSelector is fixed per tenant rather than rotated, because
	// rotation means publishing a second record and retiring the first,
	// and neither is built. It is named for the thing doing the signing so
	// a tenant's DNS stays legible.
	DKIMSelector = "mdm"
)

var (
	ErrNoSendingDomain   = errors.New("notify: no sending domain")
	ErrDomainNotVerified = errors.New("notify: that domain has not been verified yet")
	ErrBadDomain         = errors.New("notify: that is not a domain name")
	ErrRecordMissing     = errors.New("notify: the DKIM record is not published yet")
	ErrRecordMismatch    = errors.New("notify: the published DKIM record is for a different key")
)

type SendingDomain struct {
	Domain      string
	Selector    string
	FromLocal   string
	PublicKey   string
	Verified    bool
	VerifiedAt  *time.Time
	LastChecked *time.Time
	LastError   string
	CreatedBy   string
	CreatedAt   time.Time
}

func (d SendingDomain) From() string { return d.FromLocal + "@" + d.Domain }

// RecordName is where the tenant publishes it.
func (d SendingDomain) RecordName() string {
	return d.Selector + "._domainkey." + d.Domain
}

// RecordValue is what goes in it.
func (d SendingDomain) RecordValue() string {
	return "v=DKIM1; k=rsa; p=" + d.PublicKey
}

// RecordValueSplit is the same value in the form a DNS server will actually
// accept.
//
// A TXT string is limited to 255 characters and a 2048-bit key is about four
// hundred, so the record has to be published as several quoted strings that
// the resolver joins back together. Every administrator meets this once, and
// usually by the record silently not working, so the console shows the split
// form rather than leaving them to discover it.
func (d SendingDomain) RecordValueSplit() []string {
	v := d.RecordValue()
	var out []string
	for len(v) > 255 {
		out = append(out, v[:255])
		v = v[255:]
	}
	return append(out, v)
}

// WhyNoSPFRecord is shown on the console beside the DKIM record, because the
// obvious question on that page is "and what about SPF".
//
// The honest answer is that SPF is not what makes this work, and telling a
// tenant to add an include would be advice that does nothing. SPF
// authenticates the ENVELOPE sender, and the envelope sender stays the
// operator's address so that bounces come back to the platform rather than
// disappearing into a tenant's mailbox. That means SPF authenticates the
// operator's domain and does not align with the From domain.
//
// DMARC passes when EITHER SPF or DKIM authenticates and aligns. Here it is
// DKIM: d= is the tenant's domain, the From header is at the tenant's
// domain, so they align and DMARC passes on that leg. Adding an include to
// the tenant's SPF record would change nothing, because nothing is ever sent
// with their domain in the envelope.
const WhyNoSPFRecord = "No SPF change is needed. Replies and bounces come " +
	"back to this platform, so the envelope stays ours and SPF checks our " +
	"domain, not yours. What makes your mail pass DMARC is the DKIM " +
	"signature below, which is signed as your domain and matches the " +
	"address it is sent from."

// SenderIdentity is what a message is signed as. It carries the private key,
// so it exists only for the length of one delivery and is never stored on
// anything long-lived.
type SenderIdentity struct {
	Domain     string
	Selector   string
	From       string
	PrivateKey *rsa.PrivateKey
}

// ---------------------------------------------------------------- the store

// Register generates a key and records the domain, unverified.
//
// The key is generated here rather than asked for, because a tenant pasting
// a private key into a form is a tenant emailing a private key to somebody,
// and because a key we generated is one we know the strength of.
func (s *Service) Register(ctx context.Context, tx *data.Tx, domain, by string) (SendingDomain, error) {
	domain, err := cleanDomain(domain)
	if err != nil {
		return SendingDomain{}, err
	}
	key, err := rsa.GenerateKey(rand.Reader, DKIMKeyBits)
	if err != nil {
		return SendingDomain{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return SendingDomain{}, err
	}
	sealed, err := s.sealer.Seal(ctx, tx, der)
	if err != nil {
		return SendingDomain{}, err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return SendingDomain{}, err
	}
	public := base64.StdEncoding.EncodeToString(pub)

	var d SendingDomain
	err = tx.QueryRow(ctx, `
		INSERT INTO sending_domains
		  (tenant_id, domain, selector, dkim_private_sealed, dkim_public, created_by)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, domain) DO UPDATE SET
		  selector = excluded.selector,
		  dkim_private_sealed = excluded.dkim_private_sealed,
		  dkim_public = excluded.dkim_public,
		  -- Re-registering generates a new key, so whatever was verified
		  -- before was verified against a key that no longer signs
		  -- anything. Clearing it is the honest answer; the alternative is
		  -- a green tick beside a record that no longer matches.
		  verified_at = NULL, last_error = NULL, last_checked_at = NULL,
		  created_by = excluded.created_by, created_at = now()
		RETURNING domain, selector, from_local, dkim_public, verified_at,
		          last_checked_at, coalesce(last_error,''), created_by, created_at`,
		domain, DKIMSelector, sealed, public, by).Scan(
		&d.Domain, &d.Selector, &d.FromLocal, &d.PublicKey, &d.VerifiedAt,
		&d.LastChecked, &d.LastError, &d.CreatedBy, &d.CreatedAt)
	if err != nil {
		return SendingDomain{}, err
	}
	d.Verified = d.VerifiedAt != nil
	return d, data.AppendAudit(ctx, tx, "sending_domain.registered", domain)
}

// SetFromLocal changes the part before the at sign. It does not re-open
// verification: the proof was about the domain, and it still holds.
func (s *Service) SetFromLocal(ctx context.Context, tx *data.Tx, domain, local string) error {
	local = strings.TrimSpace(local)
	if local == "" || strings.ContainsAny(local, "@ \t\r\n") {
		return fmt.Errorf("%w: %q is not the part before an at sign", ErrBadEndpoint, local)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE sending_domains SET from_local = $2 WHERE domain = $1`, domain, local)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSendingDomain
	}
	return nil
}

func (s *Service) RemoveDomain(ctx context.Context, tx *data.Tx, domain string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM sending_domains WHERE domain = $1`, domain)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSendingDomain
	}
	return data.AppendAudit(ctx, tx, "sending_domain.removed", domain)
}

func (s *Service) Domains(ctx context.Context, tx *data.Tx) ([]SendingDomain, error) {
	rows, err := tx.Query(ctx, `
		SELECT domain, selector, from_local, dkim_public, verified_at,
		       last_checked_at, coalesce(last_error,''), created_by, created_at
		  FROM sending_domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SendingDomain{}
	for rows.Next() {
		var d SendingDomain
		if err := rows.Scan(&d.Domain, &d.Selector, &d.FromLocal, &d.PublicKey,
			&d.VerifiedAt, &d.LastChecked, &d.LastError, &d.CreatedBy,
			&d.CreatedAt); err != nil {
			return nil, err
		}
		d.Verified = d.VerifiedAt != nil
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- the proof

// LookupTXT is how the DNS check is made. It is a field so a test can answer
// it, and so a deployment behind a split-horizon resolver can point it
// somewhere that sees the public internet.
type LookupTXT func(ctx context.Context, name string) ([]string, error)

func defaultLookupTXT(ctx context.Context, name string) ([]string, error) {
	var r net.Resolver
	return r.LookupTXT(ctx, name)
}

// Verify checks that the tenant has published our public key in their own
// DNS, which is the proof that they control the domain.
//
// It compares the KEY, not the presence of a record. A record that exists
// but carries somebody else's key is not proof of anything: it is what a
// tenant would have if they pointed us at a domain already running DKIM for
// a different service.
func (s *Service) Verify(ctx context.Context, tx *data.Tx, domain string) (SendingDomain, error) {
	d, err := s.domain(ctx, tx, domain)
	if err != nil {
		return SendingDomain{}, err
	}

	lookup := s.LookupTXT
	if lookup == nil {
		lookup = defaultLookupTXT
	}
	records, lerr := lookup(ctx, d.RecordName())

	var problem string
	switch {
	case lerr != nil:
		problem = "the record could not be looked up: " + lerr.Error()
	case len(records) == 0:
		problem = ErrRecordMissing.Error()
	default:
		found := false
		for _, r := range records {
			if keyIn(r) == d.PublicKey {
				found = true
				break
			}
		}
		if !found {
			problem = ErrRecordMismatch.Error()
		}
	}

	if problem != "" {
		if _, err := tx.Exec(ctx, `
			UPDATE sending_domains
			   SET last_checked_at = now(), last_error = $2, verified_at = NULL
			 WHERE domain = $1`, domain, problem); err != nil {
			return SendingDomain{}, err
		}
		d.LastError = problem
		d.Verified = false
		return d, errors.New(problem)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE sending_domains
		   SET verified_at = now(), last_checked_at = now(), last_error = NULL
		 WHERE domain = $1`, domain); err != nil {
		return SendingDomain{}, err
	}
	d.Verified = true
	now := time.Now().UTC()
	d.VerifiedAt = &now
	d.LastError = ""
	return d, data.AppendAudit(ctx, tx, "sending_domain.verified", domain)
}

// keyIn pulls p= out of a DKIM record, ignoring the tags around it and the
// whitespace a DNS console may have folded in.
func keyIn(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			return strings.Join(strings.Fields(part[2:]), "")
		}
	}
	return ""
}

func (s *Service) domain(ctx context.Context, tx *data.Tx, domain string) (SendingDomain, error) {
	var d SendingDomain
	err := tx.QueryRow(ctx, `
		SELECT domain, selector, from_local, dkim_public, verified_at,
		       last_checked_at, coalesce(last_error,''), created_by, created_at
		  FROM sending_domains WHERE domain = $1`, domain).Scan(
		&d.Domain, &d.Selector, &d.FromLocal, &d.PublicKey, &d.VerifiedAt,
		&d.LastChecked, &d.LastError, &d.CreatedBy, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SendingDomain{}, ErrNoSendingDomain
	}
	if err != nil {
		return SendingDomain{}, err
	}
	d.Verified = d.VerifiedAt != nil
	return d, nil
}

// identity returns what to sign this tenant's mail as, or nil.
//
// The WHERE clause is the control, and it is one clause: verified_at IS NOT
// NULL. An unverified domain has no identity, so mail falls back to the
// operator's address rather than being signed as a domain nobody proved.
func (s *Service) identity(ctx context.Context, tx *data.Tx) (*SenderIdentity, error) {
	var (
		domain, selector, local string
		sealed                  []byte
	)
	err := tx.QueryRow(ctx, `
		SELECT domain, selector, from_local, dkim_private_sealed
		  FROM sending_domains
		 WHERE verified_at IS NOT NULL
		 ORDER BY verified_at
		 LIMIT 1`).Scan(&domain, &selector, &local, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	der, err := s.sealer.Open(ctx, tx, sealed)
	if err != nil {
		return nil, fmt.Errorf("notify: the signing key for %s cannot be opened: %w", domain, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("notify: the signing key for %s is not RSA", domain)
	}
	return &SenderIdentity{
		Domain: domain, Selector: selector,
		From: local + "@" + domain, PrivateKey: key,
	}, nil
}

func cleanDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	if d == "" || strings.ContainsAny(d, "@/ \t\r\n:") || !strings.Contains(d, ".") {
		return "", fmt.Errorf("%w: %q", ErrBadDomain, d)
	}
	if strings.HasPrefix(d, ".") || strings.Contains(d, "..") {
		return "", fmt.Errorf("%w: %q", ErrBadDomain, d)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("%w: %q", ErrBadDomain, d)
		}
	}
	if len(d) > 253 {
		return "", fmt.Errorf("%w: too long", ErrBadDomain)
	}
	return d, nil
}
