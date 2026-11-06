package data

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Local accounts (0044): people of a tenant that has no identity provider.
// What is stored here is the minimum a sign-in needs, and nothing that
// would be of use to anyone who read it: the password is a hash, the
// second-factor secret is sealed, the recovery codes are hashes, and a
// token is the hash of a link.

type LocalAccount struct {
	ID            uuid.UUID
	Email         string
	Name          string
	Role          string
	Status        string
	PasswordHash  string
	PasswordSetAt *time.Time
	TOTPSealed    []byte
	TOTPEnabled   bool
	TOTPLastStep  int64
	RecoveryLeft  int
	FailedCount   int
	LockedUntil   *time.Time
	CreatedBy     string
	CreatedAt     time.Time
	LastSignInAt  *time.Time
}

// Subject is what a local account is to the rest of the platform: the
// session's subject, the seat, the person record, the audit actor. The id
// is a UUID that is never reused, which is the property a provider's
// subject has and an email address does not.
func (a LocalAccount) Subject() string { return LocalSubject(a.ID) }

func LocalSubject(id uuid.UUID) string { return "local:" + id.String() }

// IsLocalSubject says a session's subject is a local account's.
func IsLocalSubject(s string) bool { return strings.HasPrefix(s, "local:") }

// Locked says the account is refusing sign-ins until a time.
func (a LocalAccount) Locked(now time.Time) bool {
	return a.LockedUntil != nil && a.LockedUntil.After(now)
}

var (
	ErrNoSuchAccount  = errors.New("data: no such account")
	ErrAccountExists  = errors.New("data: that address already has an account here")
	ErrLastSuperAdmin = errors.New("data: that would leave nobody who can manage access")
	ErrBadRole        = errors.New("data: that is not a role")
	ErrTokenNotUsable = errors.New("data: that link has expired or was already used")
)

const localColumns = `id, email, name, role, status, password_hash, password_set_at,
	totp_secret_sealed, totp_enabled, totp_last_step, cardinality(recovery_hashes),
	failed_count, locked_until, created_by, created_at, last_sign_in_at`

func scanLocal(row pgx.Row, a *LocalAccount) error {
	return row.Scan(&a.ID, &a.Email, &a.Name, &a.Role, &a.Status, &a.PasswordHash, &a.PasswordSetAt,
		&a.TOTPSealed, &a.TOTPEnabled, &a.TOTPLastStep, &a.RecoveryLeft,
		&a.FailedCount, &a.LockedUntil, &a.CreatedBy, &a.CreatedAt, &a.LastSignInAt)
}

// LocalRoles are the roles an account may hold: the six a tenant has.
var LocalRoles = []string{"super_admin", "it_admin", "security_manager", "helpdesk", "auditor", "employee"}

func validLocalRole(r string) bool {
	for _, x := range LocalRoles {
		if x == r {
			return true
		}
	}
	return false
}

// NormaliseEmail is how an address is compared: trimmed and lower-cased.
func NormaliseEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func LocalAccountByEmail(ctx context.Context, tx *Tx, email string) (LocalAccount, bool, error) {
	var a LocalAccount
	err := scanLocal(tx.QueryRow(ctx, `SELECT `+localColumns+` FROM local_accounts WHERE email = $1`,
		NormaliseEmail(email)), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalAccount{}, false, nil
	}
	return a, err == nil, err
}

func LocalAccountByID(ctx context.Context, tx *Tx, id uuid.UUID) (LocalAccount, error) {
	var a LocalAccount
	err := scanLocal(tx.QueryRow(ctx, `SELECT `+localColumns+` FROM local_accounts WHERE id = $1`, id), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalAccount{}, ErrNoSuchAccount
	}
	return a, err
}

func ListLocalAccounts(ctx context.Context, tx *Tx) ([]LocalAccount, error) {
	rows, err := tx.Query(ctx, `SELECT `+localColumns+` FROM local_accounts ORDER BY status = 'disabled', lower(email)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LocalAccount{}
	for rows.Next() {
		var a LocalAccount
		if err := scanLocal(rows, &a); err != nil {
			return nil, err
		}
		// The list is for a page: nothing in it a page could leak.
		a.PasswordHash, a.TOTPSealed = "", nil
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateLocalAccount makes an invited account. It has no password until
// its holder follows the link.
func CreateLocalAccount(ctx context.Context, tx *Tx, email, name, role, by string) (uuid.UUID, error) {
	email = NormaliseEmail(email)
	if !validLocalRole(role) {
		return uuid.Nil, ErrBadRole
	}
	id := uuid.New()
	_, err := tx.Exec(ctx, `
		INSERT INTO local_accounts (id, tenant_id, email, name, role, status, created_by)
		VALUES ($1, app.current_tenant(), $2, $3, $4, 'invited', $5)`,
		id, email, strings.TrimSpace(name), role, by)
	if err != nil {
		if strings.Contains(err.Error(), "local_accounts_tenant_id_email_key") {
			return uuid.Nil, ErrAccountExists
		}
		return uuid.Nil, err
	}
	return id, AppendAudit(ctx, tx, "local.invited", "account:"+id.String()+" role:"+role)
}

// ---------------------------------------------------------------- tokens

const (
	InviteLife = 7 * 24 * time.Hour
	ResetLife  = time.Hour
)

// IssueLocalToken makes a link for an account and retires any earlier
// unspent one of the same kind: asking again replaces the first link
// rather than adding to it.
func IssueLocalToken(ctx context.Context, tx *Tx, accountID uuid.UUID, purpose string, hash []byte, expires, now time.Time) error {
	if _, err := tx.Exec(ctx, `
		UPDATE local_tokens SET used_at = $3
		 WHERE account_id = $1 AND purpose = $2 AND used_at IS NULL`, accountID, purpose, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO local_tokens (tenant_id, account_id, purpose, token_hash, expires_at)
		VALUES (app.current_tenant(), $1, $2, $3, $4)`, accountID, purpose, hash, expires)
	return err
}

// PeekLocalToken finds the account a link is for, without spending it, so
// the page can say whom it is for before they choose a password.
func PeekLocalToken(ctx context.Context, tx *Tx, hash []byte, purpose string, now time.Time) (LocalAccount, bool, error) {
	var a LocalAccount
	err := scanLocal(tx.QueryRow(ctx, `
		SELECT `+prefixed("a", localColumns)+`
		  FROM local_tokens t JOIN local_accounts a ON a.id = t.account_id AND a.tenant_id = t.tenant_id
		 WHERE t.token_hash = $1 AND t.purpose = $2 AND t.used_at IS NULL AND t.expires_at > $3
		   AND a.status <> 'disabled'`, hash, purpose, now), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalAccount{}, false, nil
	}
	return a, err == nil, err
}

// prefixed puts a table alias on each column of a list.
func prefixed(alias, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "(") {
			p = strings.Replace(p, "recovery_hashes", alias+".recovery_hashes", 1)
		} else {
			p = alias + "." + p
		}
		parts[i] = p
	}
	return strings.Join(parts, ", ")
}

// SpendLocalToken uses a link up, once. Called after the new password has
// been checked, in the same transaction that sets it, so a password the
// policy refuses does not cost the person their link.
func SpendLocalToken(ctx context.Context, tx *Tx, hash []byte, purpose string, now time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
		UPDATE local_tokens SET used_at = $3
		 WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3
		 RETURNING account_id`, hash, purpose, now).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrTokenNotUsable
	}
	return id, err
}

// ------------------------------------------------------------- passwords

// SetLocalPassword stores a new password hash and clears the lock. An
// invited account becomes active; a disabled one stays disabled.
func SetLocalPassword(ctx context.Context, tx *Tx, id uuid.UUID, hash string, now time.Time) error {
	tag, err := tx.Exec(ctx, `
		UPDATE local_accounts
		   SET password_hash = $2, password_set_at = $3, failed_count = 0, locked_until = NULL,
		       status = CASE WHEN status = 'invited' THEN 'active' ELSE status END
		 WHERE id = $1`, id, hash, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchAccount
	}
	return AppendAudit(ctx, tx, "local.password_set", "account:"+id.String())
}

// Lockout: five wrong answers lock the account for fifteen minutes. The
// count restarts when a lock has run out, so the first mistake after it is
// the first of five rather than the sixth of five. Locking the account and
// not only the address is deliberate: a guesser who rotates addresses is
// the one the per-address limit cannot stop.
const (
	LockAfter = 5
	LockFor   = 15 * time.Minute
)

// RecordLocalFailure counts a wrong password or code and locks when the
// count is reached. It says whether this failure locked the account.
// The control --break-lockout never locks.
func RecordLocalFailure(ctx context.Context, tx *Tx, id uuid.UUID, now time.Time) (bool, error) {
	var count int
	err := tx.QueryRow(ctx, `
		UPDATE local_accounts
		   SET failed_count = CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN 1 ELSE failed_count + 1 END,
		       locked_until = CASE
		         WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN 1 ELSE failed_count + 1 END) >= $3
		         THEN $2::timestamptz + $4::interval ELSE
		           CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN NULL ELSE locked_until END
		       END
		 WHERE id = $1
		 RETURNING failed_count`, id, now, LockAfter, LockFor.String()).Scan(&count)
	if err != nil {
		return false, err
	}
	if count >= LockAfter {
		return true, AppendAudit(ctx, tx, "local.locked", "account:"+id.String())
	}
	return false, nil
}

func RecordLocalSuccess(ctx context.Context, tx *Tx, id uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `
		UPDATE local_accounts SET failed_count = 0, locked_until = NULL, last_sign_in_at = $2 WHERE id = $1`, id, now)
	return err
}

// UnlockLocalAccount is a Super Admin lifting a lock.
func UnlockLocalAccount(ctx context.Context, tx *Tx, id uuid.UUID) error {
	if _, err := tx.Exec(ctx, `UPDATE local_accounts SET failed_count = 0, locked_until = NULL WHERE id = $1`, id); err != nil {
		return err
	}
	return AppendAudit(ctx, tx, "local.unlocked", "account:"+id.String())
}

// ------------------------------------------------------------- second factor

// SetPendingTOTP stores the sealed secret of an enrolment that has not yet
// been confirmed with a code. Only where none is held: the page is opened
// twice and the second must not replace the secret the first has already
// put in somebody's phone. It says whether this call is the one that set it.
func SetPendingTOTP(ctx context.Context, tx *Tx, id uuid.UUID, sealed []byte) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE local_accounts SET totp_secret_sealed = $2
		 WHERE id = $1 AND NOT totp_enabled AND totp_secret_sealed IS NULL`, id, sealed)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// EnableTOTP turns the second factor on once a code has proved the app has
// the secret, and keeps the recovery codes' hashes.
func EnableTOTP(ctx context.Context, tx *Tx, id uuid.UUID, step uint64, recoveryHashes []string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE local_accounts
		   SET totp_enabled = true, totp_last_step = $2, recovery_hashes = $3
		 WHERE id = $1 AND NOT totp_enabled AND totp_secret_sealed IS NOT NULL`, id, int64(step), recoveryHashes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchAccount
	}
	return AppendAudit(ctx, tx, "local.mfa_enrolled", "account:"+id.String())
}

// AcceptTOTPStep records that a code for this step was used. It says false
// when that step, or a later one, has already been accepted: a code is
// good once. The control --break-totpreplay accepts the same step twice.
func AcceptTOTPStep(ctx context.Context, tx *Tx, id uuid.UUID, step uint64) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE local_accounts SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2`, id, int64(step))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// UseRecoveryCode spends one recovery code. One statement, so two people
// holding the same code cannot both spend it.
func UseRecoveryCode(ctx context.Context, tx *Tx, id uuid.UUID, hash string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE local_accounts SET recovery_hashes = array_remove(recovery_hashes, $2)
		 WHERE id = $1 AND $2 = ANY(recovery_hashes)`, id, hash)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, AppendAudit(ctx, tx, "local.recovery_used", "account:"+id.String())
	}
	return false, nil
}

// ResetMFA clears the second factor, for somebody who has lost their phone
// and their recovery codes. The next sign-in enrols again.
func ResetMFA(ctx context.Context, tx *Tx, id uuid.UUID) error {
	if _, err := tx.Exec(ctx, `
		UPDATE local_accounts
		   SET totp_secret_sealed = NULL, totp_enabled = false, totp_last_step = 0, recovery_hashes = '{}'
		 WHERE id = $1`, id); err != nil {
		return err
	}
	return AppendAudit(ctx, tx, "local.mfa_reset", "account:"+id.String())
}

// ---------------------------------------------------------- role and status

// guardLastSuperAdmin refuses a change that would leave no active Super
// Admin: the one role that can invite people, so a tenant without one has
// nobody who can fix it. The active Super Admins are locked first, so two
// of them demoting each other at the same moment cannot both succeed.
// The control --break-lastadmin skips it.
func guardLastSuperAdmin(ctx context.Context, tx *Tx, id uuid.UUID) error {
	rows, err := tx.Query(ctx, `
		SELECT id FROM local_accounts WHERE role = 'super_admin' AND status = 'active' FOR UPDATE`)
	if err != nil {
		return err
	}
	var others int
	var targetIsOne bool
	for rows.Next() {
		var other uuid.UUID
		if err := rows.Scan(&other); err != nil {
			rows.Close()
			return err
		}
		if other == id {
			targetIsOne = true
		} else {
			others++
		}
	}
	rows.Close()
	if targetIsOne && others == 0 {
		return ErrLastSuperAdmin
	}
	return nil
}

// ChangeLocalRole sets an account's role.
func ChangeLocalRole(ctx context.Context, tx *Tx, id uuid.UUID, role string) error {
	if !validLocalRole(role) {
		return ErrBadRole
	}
	cur, err := LocalAccountByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if cur.Role == "super_admin" && role != "super_admin" {
		if err := guardLastSuperAdmin(ctx, tx, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE local_accounts SET role = $2 WHERE id = $1`, id, role); err != nil {
		return err
	}
	return AppendAudit(ctx, tx, "local.role_changed", "account:"+id.String()+" from:"+cur.Role+" to:"+role)
}

// SetLocalStatus disables or enables an account. An account that was never
// activated goes back to invited rather than active, so enabling cannot
// skip the password.
func SetLocalStatus(ctx context.Context, tx *Tx, id uuid.UUID, disable bool) error {
	cur, err := LocalAccountByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if disable {
		if cur.Role == "super_admin" && cur.Status == "active" {
			if err := guardLastSuperAdmin(ctx, tx, id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE local_accounts SET status = 'disabled' WHERE id = $1`, id); err != nil {
			return err
		}
		return AppendAudit(ctx, tx, "local.disabled", "account:"+id.String())
	}
	if _, err := tx.Exec(ctx, `
		UPDATE local_accounts
		   SET status = CASE WHEN password_hash = '' THEN 'invited' ELSE 'active' END
		 WHERE id = $1 AND status = 'disabled'`, id); err != nil {
		return err
	}
	return AppendAudit(ctx, tx, "local.enabled", "account:"+id.String())
}

// LocalMFAPolicy reads who must have the second factor.
func LocalMFAPolicy(ctx context.Context, tx *Tx) (string, error) {
	var p string
	err := tx.QueryRow(ctx, `SELECT local_mfa FROM tenant_identity`).Scan(&p)
	if errors.Is(err, pgx.ErrNoRows) {
		return "admins", nil
	}
	return p, err
}

func SetLocalMFAPolicy(ctx context.Context, tx *Tx, policy string) error {
	if policy != "admins" && policy != "everyone" {
		return errors.New("data: the second-factor policy is admins or everyone")
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_identity SET local_mfa = $1`, policy); err != nil {
		return err
	}
	return AppendAudit(ctx, tx, "local.mfa_policy", policy)
}

// MFARequired says whether a role must have the second factor under the
// tenant's policy: the roles that can lock, wipe, approve and read keys, or
// everybody. The control --break-mfarequired says no.
func MFARequired(policy, role string) bool {
	if policy == "everyone" {
		return true
	}
	switch role {
	case "super_admin", "it_admin", "security_manager":
		return true
	}
	return false
}

// LocalModeOn says whether the tenant signs in with accounts held here.
func LocalModeOn(ctx context.Context, tx *Tx) (bool, error) {
	var p string
	err := tx.QueryRow(ctx, `SELECT protocol FROM tenant_identity`).Scan(&p)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return p == "local", err
}
