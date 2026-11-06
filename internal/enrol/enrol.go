// Package enrol turns a one-time invitation into a device this platform
// knows, holding an identity certificate it can prove.
//
// The shape: an administrator creates an enrolment, which produces a token
// shown exactly once. The device presents that token together with a
// certificate signing request. If the token is good, the device gets a row
// and a certificate signed by its tenant's own authority, and the token is
// spent.
//
// What the token is and is not. It is a bearer credential: whoever holds it
// can enrol a device into that tenant, so it is short-lived, single use,
// stored only as a hash, and revocable. It is NOT an identity: it does not
// say who the person carrying it is, and nothing downstream treats it as if
// it did. The identity of the resulting device is the certificate, which is
// issued here and checked on every later request.
package enrol

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

	"platform/internal/data"
	"platform/internal/pki"
	"platform/internal/secrets"
)

// DefaultLife is how long an invitation is good for. A week covers posting
// a laptop to someone, and is short enough that a token found later in a
// chat log is already dead.
const DefaultLife = 7 * 24 * time.Hour

// MaxLife is the longest an administrator may ask for. Without a ceiling,
// "make it not expire" becomes the default setting on every enrolment and
// the expiry stops being a control.
const MaxLife = 30 * 24 * time.Hour

var (
	// ErrNoSuchToken is deliberately the same answer for a token that never
	// existed, one that belongs to another tenant, one already spent and one
	// revoked. Telling them apart would let someone with a list of guesses
	// learn which were real.
	ErrNoSuchToken = errors.New("enrol: this enrolment link is not valid")

	ErrExpired = errors.New("enrol: this enrolment link has expired")
	// ErrDeviceCap is the plan's device cap. Refused at invitation time
	// with the numbers, and again by a database trigger at the row.
	ErrDeviceCap    = errors.New("enrol: the plan's device cap is reached")
	ErrNotPending   = errors.New("enrol: this enrolment has already been used")
	ErrNoCSR        = errors.New("enrol: the device sent no certificate signing request")
	ErrBadInput     = errors.New("enrol: the enrolment details are incomplete")
	ErrLifeTooLong  = fmt.Errorf("enrol: an enrolment may last at most %d days", int(MaxLife.Hours()/24))
	ErrNoAuthority  = errors.New("enrol: this tenant has no certificate authority")
	ErrDeviceSerial = errors.New("enrol: the device did not report a serial number")
)

type Enrolment struct {
	ID    uuid.UUID
	Label string
	// AssignedTo is who the device is for. The device inherits it when the
	// invitation is redeemed, which is the only moment anyone knows: by the
	// time a machine is reporting, nothing on it says whose desk it is on.
	AssignedTo string
	// PersonID is the person the address resolved to (0040); the device
	// inherits it with the assignment.
	PersonID    *uuid.UUID
	Ownership   string
	OSFamily    string
	State       string
	CreatedBy   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	OpenedAt    *time.Time
	CompletedAt *time.Time
	DeviceID    *uuid.UUID
}

// Expired is computed rather than stored. A stored "expired" state would
// need something to go round setting it, and until that something ran the
// row would claim to be usable.
func (e Enrolment) Expired(now time.Time) bool {
	return e.State == "pending" && now.After(e.ExpiresAt)
}

// Usable is what the console shows and what Redeem enforces, in one place so
// the two cannot disagree.
func (e Enrolment) Usable(now time.Time) bool {
	return e.State == "pending" && !e.Expired(now)
}

func (e Enrolment) Status(now time.Time) string {
	switch {
	case e.State == "completed":
		return "enrolled"
	case e.State == "revoked":
		return "revoked"
	case e.Expired(now):
		return "expired"
	default:
		return "waiting for the device"
	}
}

// Service holds what enrolment needs beyond a transaction: the sealer, for
// the tenant authority's private key.
type Service struct {
	sealer secrets.Sealer
	// Now is the clock, a field for the same reason it is one on the
	// session signer: expiry rules should be testable without sleeping.
	Now func() time.Time
}

func New(sealer secrets.Sealer) *Service {
	return &Service{sealer: sealer, Now: func() time.Time { return time.Now().UTC() }}
}

// ---------------------------------------------------------------- creating

type CreateInput struct {
	Label      string
	Ownership  string // company | personal
	OSFamily   string
	AssignedTo string
	Life       time.Duration
}

// Create makes an invitation and returns the token ONCE.
//
// The token is not stored and cannot be shown again. That is the same rule
// as a password, for the same reason, and it is worth the small support cost
// of someone having to make a second enrolment when they lose the first.
func (s *Service) Create(ctx context.Context, tx *data.Tx, in CreateInput) (Enrolment, string, error) {
	in.Label = strings.TrimSpace(in.Label)
	if in.Label == "" {
		return Enrolment{}, "", fmt.Errorf("%w: a label is required so the device can be recognised before it reports a name", ErrBadInput)
	}
	if in.Ownership != "company" && in.Ownership != "personal" {
		return Enrolment{}, "", fmt.Errorf("%w: ownership must be company or personal", ErrBadInput)
	}
	switch in.OSFamily {
	case "macos", "ios", "ipados", "android", "windows":
	default:
		return Enrolment{}, "", fmt.Errorf("%w: unknown operating system %q", ErrBadInput, in.OSFamily)
	}
	if in.Life <= 0 {
		in.Life = DefaultLife
	}
	if in.Life > MaxLife {
		return Enrolment{}, "", ErrLifeTooLong
	}

	if err := checkCap(ctx, tx); err != nil {
		return Enrolment{}, "", err
	}

	token, err := newToken()
	if err != nil {
		return Enrolment{}, "", err
	}
	sum := sha256.Sum256([]byte(token))
	now := s.Now()

	// Who it is for, as a person the platform has met, made now if the
	// address is new: the device will be theirs before their first
	// sign-in.
	personID, err := data.PersonFor(ctx, tx, in.AssignedTo, now)
	if err != nil {
		return Enrolment{}, "", err
	}
	var e Enrolment
	err = tx.QueryRow(ctx, `
		INSERT INTO enrolments
		  (tenant_id, token_hash, label, ownership, os_family, created_by,
		   expires_at, assigned_to, person_id)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, label, ownership, os_family, state, created_by, created_at,
		          expires_at, assigned_to, person_id`,
		sum[:], in.Label, in.Ownership, in.OSFamily, tx.Claim().Subject,
		now.Add(in.Life), strings.TrimSpace(in.AssignedTo), personID).Scan(
		&e.ID, &e.Label, &e.Ownership, &e.OSFamily, &e.State,
		&e.CreatedBy, &e.CreatedAt, &e.ExpiresAt, &e.AssignedTo, &e.PersonID)
	if err != nil {
		return Enrolment{}, "", err
	}
	// The audit records that an invitation was made and by whom. It does not
	// record the token, which would put the credential in the one table
	// nobody is allowed to delete from.
	if err := data.AppendAudit(ctx, tx, "enrolment.create", "enrolment:"+e.ID.String()); err != nil {
		return Enrolment{}, "", err
	}
	return e, token, nil
}

// ---------------------------------------------------------------- redeeming

type RedeemInput struct {
	Token string
	CSR   []byte // DER
	// Serial is the hardware serial the device reports. It is how a
	// re-enrolment is recognised as the same machine.
	Serial string
	Name   string
}

type Redeemed struct {
	Enrolment   Enrolment
	Device      data.Device
	Certificate []byte // PEM, the device's own
	Authority   []byte // PEM, so the device can verify its chain
	NotAfter    time.Time
	// Reenrolled says the serial was already known and its old certificates
	// have been revoked. The console shows it, because a device enrolling
	// twice is either a rebuild or something worth asking about.
	Reenrolled bool
}

// Redeem spends a token and issues a certificate.
//
// Everything happens in the caller's single transaction. If the certificate
// cannot be recorded the token is not spent, and if the token cannot be
// spent the certificate is not recorded, because the one thing worse than a
// failed enrolment is a device holding a valid certificate this platform has
// no record of.
func (s *Service) Redeem(ctx context.Context, tx *data.Tx, in RedeemInput) (Redeemed, error) {
	if len(in.CSR) == 0 {
		return Redeemed{}, ErrNoCSR
	}
	if strings.TrimSpace(in.Serial) == "" {
		return Redeemed{}, ErrDeviceSerial
	}
	now := s.Now()

	// FOR UPDATE, so two devices arriving with the same token at the same
	// moment are serialised here rather than both reading 'pending'. The
	// database trigger refuses the second transition as well; this is the
	// half that makes the second request wait rather than fail.
	sum := sha256.Sum256([]byte(in.Token))
	var e Enrolment
	err := tx.QueryRow(ctx, `
		SELECT id, label, ownership, os_family, state, created_by, created_at,
		       expires_at, opened_at, completed_at, device_id, assigned_to, person_id
		  FROM enrolments
		 WHERE token_hash = $1
		   FOR UPDATE`, sum[:]).Scan(
		&e.ID, &e.Label, &e.Ownership, &e.OSFamily, &e.State, &e.CreatedBy,
		&e.CreatedAt, &e.ExpiresAt, &e.OpenedAt, &e.CompletedAt, &e.DeviceID,
		&e.AssignedTo, &e.PersonID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Redeemed{}, ErrNoSuchToken
	}
	if err != nil {
		return Redeemed{}, err
	}
	if e.State != "pending" {
		return Redeemed{}, ErrNotPending
	}
	if e.Expired(now) {
		return Redeemed{}, ErrExpired
	}

	auth, err := s.authority(ctx, tx, now)
	if err != nil {
		return Redeemed{}, err
	}

	deviceID, reenrolled, err := s.deviceFor(ctx, tx, e, in)
	if err != nil {
		return Redeemed{}, err
	}

	tenantID := tx.Claim().TenantID
	issued, err := auth.Issue(in.CSR, tenantID, deviceID, now)
	if err != nil {
		return Redeemed{}, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO device_certificates
		  (tenant_id, device_id, serial, fingerprint, not_before, not_after)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5)`,
		deviceID, issued.Serial, issued.Fingerprint,
		issued.NotBefore, issued.NotAfter); err != nil {
		return Redeemed{}, err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE enrolments
		   SET state = 'completed', completed_at = $2, device_id = $3,
		       opened_at = coalesce(opened_at, $2)
		 WHERE id = $1`, e.ID, now, deviceID); err != nil {
		return Redeemed{}, err
	}

	if err := data.AppendAudit(ctx, tx, "enrolment.complete",
		"device:"+deviceID.String()); err != nil {
		return Redeemed{}, err
	}
	if err := data.AppendAudit(ctx, tx, "certificate.issue",
		"device:"+deviceID.String()+" serial:"+issued.Serial); err != nil {
		return Redeemed{}, err
	}

	device, err := data.GetDevice(ctx, tx, deviceID)
	if err != nil {
		return Redeemed{}, err
	}
	e.State = "completed"
	e.DeviceID = &deviceID
	e.CompletedAt = &now

	return Redeemed{
		Enrolment: e, Device: device,
		Certificate: issued.PEM, Authority: auth.CertificatePEM(),
		NotAfter: issued.NotAfter, Reenrolled: reenrolled,
	}, nil
}

// deviceFor finds or makes the device row.
//
// A hardware serial already known to this tenant is the same machine coming
// back: wiped and rebuilt, or re-enrolled after a support call. It keeps its
// row, its history and its audit trail, and every certificate it used to
// hold is revoked here. Issuing a second valid certificate for one machine
// without retiring the first would mean a stolen laptop's credential still
// worked after the replacement was enrolled.
func (s *Service) deviceFor(ctx context.Context, tx *data.Tx, e Enrolment,
	in RedeemInput) (uuid.UUID, bool, error) {

	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = e.Label
	}

	var existing uuid.UUID
	err := tx.QueryRow(ctx,
		`SELECT id FROM devices WHERE serial = $1`, in.Serial).Scan(&existing)
	switch {
	case err == nil:
		if _, err := tx.Exec(ctx, `
			UPDATE device_certificates
			   SET revoked_at = now(), revoked_reason = 'the device was enrolled again'
			 WHERE device_id = $1 AND revoked_at IS NULL`, existing); err != nil {
			return uuid.Nil, false, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE devices
			   SET name = $2, ownership = $3, state = 'awaiting_first_boot',
			       assigned_to = coalesce(nullif($4,''), assigned_to),
			       person_id = coalesce($5, person_id)
			 WHERE id = $1`, existing, name, e.Ownership, e.AssignedTo, e.PersonID); err != nil {
			return uuid.Nil, false, err
		}
		if err := data.AppendAudit(ctx, tx, "certificate.revoke",
			"device:"+existing.String()+" reason:re-enrolled"); err != nil {
			return uuid.Nil, false, err
		}
		return existing, true, nil

	case errors.Is(err, pgx.ErrNoRows):
		id, err := data.InsertDevice(ctx, tx, name, in.Serial, e.OSFamily)
		if err != nil {
			return uuid.Nil, false, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE devices SET ownership = $2, assigned_to = $3, person_id = $4 WHERE id = $1`,
			id, e.Ownership, e.AssignedTo, e.PersonID); err != nil {
			return uuid.Nil, false, err
		}
		return id, false, nil

	default:
		return uuid.Nil, false, err
	}
}

// authority loads this tenant's certificate authority, making one the first
// time it is needed.
//
// Lazily rather than at tenant creation, because a tenant that never enrols
// a device never needs one, and a key that exists is a key that has to be
// protected.
func (s *Service) authority(ctx context.Context, tx *data.Tx, now time.Time) (*pki.Authority, error) {
	var certDER, keySealed []byte
	err := tx.QueryRow(ctx,
		`SELECT certificate, private_key_sealed FROM tenant_ca`).Scan(&certDER, &keySealed)
	if err == nil {
		if s.sealer == nil {
			return nil, ErrNoAuthority
		}
		keyDER, err := s.sealer.Open(ctx, tx, keySealed)
		if err != nil {
			return nil, fmt.Errorf("enrol: this tenant's authority key cannot be opened: %w", err)
		}
		return pki.Load(certDER, keyDER)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if s.sealer == nil {
		return nil, ErrNoAuthority
	}

	var tenantName string
	if err := tx.QueryRow(ctx,
		`SELECT coalesce(max(product_name), '') FROM tenant_branding`).Scan(&tenantName); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenantName) == "" {
		tenantName = "Managed Devices"
	}

	created, err := pki.Create(tx.Claim().TenantID, tenantName, now)
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealer.Seal(ctx, tx, created.PrivateDER)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_ca
		  (tenant_id, certificate, private_key_sealed, subject, not_before, not_after)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5)`,
		created.CertDER, sealed, created.Subject,
		created.NotBefore, created.NotAfter); err != nil {
		return nil, err
	}
	if err := data.AppendAudit(ctx, tx, "authority.create", created.Subject); err != nil {
		return nil, err
	}
	return created.Authority, nil
}

// ---------------------------------------------------------------- the rest

func List(ctx context.Context, tx *data.Tx, limit int) ([]Enrolment, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := tx.Query(ctx, `
		SELECT id, label, ownership, os_family, state, created_by, created_at,
		       expires_at, opened_at, completed_at, device_id, assigned_to, person_id
		  FROM enrolments ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Enrolment{}
	for rows.Next() {
		var e Enrolment
		if err := rows.Scan(&e.ID, &e.Label, &e.Ownership, &e.OSFamily, &e.State,
			&e.CreatedBy, &e.CreatedAt, &e.ExpiresAt, &e.OpenedAt,
			&e.CompletedAt, &e.DeviceID, &e.AssignedTo, &e.PersonID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Revoke withdraws an invitation that has not been used. It does not touch a
// completed one: the device is already enrolled, and taking its certificate
// away is RevokeCertificate, which is a different decision with a different
// consequence.
func (s *Service) Revoke(ctx context.Context, tx *data.Tx, id uuid.UUID, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("%w: a reason is required", ErrBadInput)
	}
	tag, err := tx.Exec(ctx,
		`UPDATE enrolments SET state = 'revoked' WHERE id = $1 AND state = 'pending'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotPending
	}
	return data.AppendAudit(ctx, tx, "enrolment.revoke",
		"enrolment:"+id.String()+" reason:"+reason)
}

// RevokeCertificates withdraws a device's identity. The next request it
// makes is refused, because the gateway checks the revocation on every one.
func RevokeCertificates(ctx context.Context, tx *data.Tx, deviceID uuid.UUID, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("%w: a reason is required", ErrBadInput)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE device_certificates
		   SET revoked_at = now(), revoked_reason = $2
		 WHERE device_id = $1 AND revoked_at IS NULL`, deviceID, reason); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "certificate.revoke",
		"device:"+deviceID.String()+" reason:"+reason)
}

// newToken is 32 bytes of randomness, url-safe so it survives being pasted
// into a link, an email and a terminal.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ------------------------------------------------------------- renewal
//
// A device certificate lasts a year. Without this, the first device enrolled
// stops being able to authenticate exactly a year later, and so does every
// device after it, one at a time, for the rest of the product's life.
//
// Renewal lives in this package rather than its own because this is where
// the tenant's certificate authority is: splitting it out would mean a
// second thing that can open a signing key, and one is enough.
//
// WHAT AUTHENTICATES A RENEWAL is the certificate the device already holds,
// presented over mutual TLS. That has three consequences worth stating:
//
//   - no enrolment token is involved, so renewal cannot be used to put a
//     device into a tenant
//   - a REVOKED certificate cannot renew, because a revoked certificate
//     cannot reach this code at all: the gateway refuses it during
//     resolution, before any route runs. A renewal path that authenticated
//     some other way would be a way around revocation, which would make
//     revocation decorative
//   - an EXPIRED certificate cannot renew either, for the same reason. Past
//     that point the device must enrol again, which is a person's decision
//     and the correct one: a machine nobody has heard from in a year is not
//     a machine to quietly re-admit

const (
	// RenewalWindow is how long before expiry a device may renew.
	//
	// It is also the rate limit, and that is the neat part: a certificate
	// issued today is not in its own window, so a device that has just
	// renewed cannot renew again. Without that, a device holding a valid
	// certificate could mint an unbounded number of them.
	RenewalWindow = 30 * 24 * time.Hour

	// ExpiringSoon is when an administrator is told. Wider than the renewal
	// window on purpose: by the time a certificate is inside its window and
	// has NOT renewed, something is already wrong, and the point of the
	// warning is to arrive while there is still time to act.
	ExpiringSoon = 45 * 24 * time.Hour
)

var (
	ErrNotDueForRenewal = fmt.Errorf(
		"enrol: this certificate is not due for renewal yet (it may be renewed in its last %d days)",
		int(RenewalWindow.Hours()/24))
	ErrUnknownCertificate = errors.New("enrol: that certificate was not issued here")
)

type Renewed struct {
	Certificate []byte // PEM
	Authority   []byte // PEM
	NotAfter    time.Time
	// PreviousNotAfter is what the old one would have expired at, so an
	// agent can log what it just avoided.
	PreviousNotAfter time.Time
}

// Renew issues a fresh certificate to a device that already holds one.
//
// presented is the fingerprint of the certificate the device authenticated
// with. It is read from the TLS connection by the caller, never from the
// request body: a fingerprint in a body is a claim, and the whole point of
// this path is that the device is authenticated by what it holds.
func (s *Service) Renew(ctx context.Context, tx *data.Tx, deviceID uuid.UUID,
	presented []byte, csr []byte) (Renewed, error) {

	if len(csr) == 0 {
		return Renewed{}, ErrNoCSR
	}
	now := s.Now()

	// The certificate being renewed, read by fingerprint so this is the
	// certificate that was actually presented rather than the newest one
	// the device happens to own.
	var (
		certDevice uuid.UUID
		notAfter   time.Time
		revokedAt  *time.Time
	)
	err := tx.QueryRow(ctx, `
		SELECT device_id, not_after, revoked_at
		  FROM device_certificates WHERE fingerprint = $1`, presented).Scan(
		&certDevice, &notAfter, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Renewed{}, ErrUnknownCertificate
	}
	if err != nil {
		return Renewed{}, err
	}
	// Belt to the gateway's braces. The gateway has already refused a
	// revoked or foreign certificate during resolution; checking again here
	// means a future caller of this function cannot skip that by arriving
	// from somewhere else.
	if certDevice != deviceID {
		return Renewed{}, ErrUnknownCertificate
	}
	if revokedAt != nil {
		return Renewed{}, ErrUnknownCertificate
	}
	if now.After(notAfter) {
		return Renewed{}, ErrUnknownCertificate
	}
	if notAfter.Sub(now) > RenewalWindow {
		return Renewed{}, ErrNotDueForRenewal
	}

	auth, err := s.authority(ctx, tx, now)
	if err != nil {
		return Renewed{}, err
	}
	issued, err := auth.Issue(csr, tx.Claim().TenantID, deviceID, now)
	if err != nil {
		return Renewed{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_certificates
		  (tenant_id, device_id, serial, fingerprint, not_before, not_after)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5)`,
		deviceID, issued.Serial, issued.Fingerprint,
		issued.NotBefore, issued.NotAfter); err != nil {
		return Renewed{}, err
	}

	// The old certificate is NOT revoked here, deliberately.
	//
	// Revoking it the moment the new one is signed would brick any device
	// that fails to write the answer to disk: it would be holding a
	// certificate the server has just refused, with no way to ask for
	// another. Letting it expire naturally means a device has two valid
	// certificates for at most the renewal window, once a year, which is
	// bounded and recoverable. Revoking a device outright still revokes
	// every certificate it holds, so this does not weaken that.
	if err := data.AppendAudit(ctx, tx, "certificate.renewed",
		"device:"+deviceID.String()+" serial:"+issued.Serial); err != nil {
		return Renewed{}, err
	}

	return Renewed{
		Certificate: issued.PEM, Authority: auth.CertificatePEM(),
		NotAfter: issued.NotAfter, PreviousNotAfter: notAfter,
	}, nil
}

// Expiring is the sweep: devices whose certificate runs out soon and which
// have not renewed.
//
// "Have not renewed" is the whole question. A device that renewed last week
// still has an old certificate expiring soon, and warning about that would
// be a false alarm every single time, which is how a warning stops being
// read. So this asks for devices whose NEWEST valid certificate is running
// out, not for certificates that are running out.
type ExpiringDevice struct {
	DeviceID uuid.UUID
	Name     string
	NotAfter time.Time
}

func Expiring(ctx context.Context, tx *data.Tx, within time.Duration,
	now time.Time) ([]ExpiringDevice, error) {

	rows, err := tx.Query(ctx, `
		SELECT d.id, d.name, max(c.not_after) AS newest
		  FROM devices d
		  JOIN device_certificates c
		    ON c.device_id = d.id AND c.revoked_at IS NULL
		 WHERE d.state <> 'retired'
		 GROUP BY d.id, d.name
		HAVING max(c.not_after) <= $1
		 ORDER BY newest`, now.Add(within))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ExpiringDevice{}
	for rows.Next() {
		var e ExpiringDevice
		if err := rows.Scan(&e.DeviceID, &e.Name, &e.NotAfter); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// checkCap refuses an invitation that could not be honoured: every device
// slot the plan allows is in use. The database trigger refuses the row
// too, for any writer that forgets to ask; this is the one that says the
// numbers.
func checkCap(ctx context.Context, tx *data.Tx) error {
	var have, cap int
	if err := tx.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM devices WHERE state <> 'retired'),
		       (SELECT device_cap FROM tenants WHERE id = app.current_tenant())`).Scan(&have, &cap); err != nil {
		return err
	}
	if have >= cap {
		return fmt.Errorf("%w: %d of %d devices are in use. Retire a device, or ask for a larger plan", ErrDeviceCap, have, cap)
	}
	return nil
}
