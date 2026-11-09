package directory

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/localauth"
)

// The platform owner's own accounts (0048). They belong to no organisation, so
// none of this goes through a tenant transaction: it is the operator role,
// the same one the command-line tool uses, on tables nothing else may read.

// Lockout, the same shape as an organisation's own accounts: five wrong
// answers lock the account for fifteen minutes.
const (
	OperatorLockAfter = 5
	OperatorLockFor   = 15 * time.Minute
)

// How long a link works: an invitation a week, a password reset an hour.
const (
	OperatorInviteLife = 7 * 24 * time.Hour
	OperatorResetLife  = time.Hour
)

var (
	ErrNoSuchOperator     = errors.New("directory: no such operator")
	ErrOperatorExists     = errors.New("directory: an operator with that address already exists")
	ErrOperatorLink       = errors.New("directory: that link cannot be used")
	ErrLastOperator       = errors.New("directory: that is the last active operator")
	ErrBadOperatorAddress = errors.New("directory: that is not an email address")
)

// Operator is one person who can sign in to the owner's console.
type Operator struct {
	ID           uuid.UUID
	Email        string
	Name         string
	Status       string // invited, active, disabled
	PasswordHash string
	TOTPSealed   []byte
	TOTPEnabled  bool
	TOTPLastStep int64
	FailedCount  int
	LockedUntil  *time.Time
	CreatedBy    string
	CreatedAt    time.Time
	LastSignInAt *time.Time
	// SessionsInvalidBefore ends every session that began before it: set when
	// the account is disabled, its password changes or its second factor is reset.
	SessionsInvalidBefore *time.Time
}

// Locked says whether the account is refusing sign-ins at a moment.
func (o Operator) Locked(now time.Time) bool {
	return o.LockedUntil != nil && now.Before(*o.LockedUntil)
}

const operatorColumns = `id, email, name, status, password_hash, totp_secret_sealed, totp_enabled,
	totp_last_step, failed_count, locked_until, created_by, created_at, last_sign_in_at, sessions_invalid_before`

func scanOperator(row pgx.Row, o *Operator) error {
	return row.Scan(&o.ID, &o.Email, &o.Name, &o.Status, &o.PasswordHash, &o.TOTPSealed, &o.TOTPEnabled,
		&o.TOTPLastStep, &o.FailedCount, &o.LockedUntil, &o.CreatedBy, &o.CreatedAt, &o.LastSignInAt, &o.SessionsInvalidBefore)
}

// NormaliseOperatorEmail lower-cases and trims an address, so one person
// cannot be two accounts by capital letters.
func NormaliseOperatorEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func validOperatorEmail(s string) bool {
	at := strings.Index(s, "@")
	return at > 0 && at == strings.LastIndex(s, "@") && strings.Contains(s[at:], ".") &&
		!strings.ContainsAny(s, " \t\r\n,;<>") && len(s) <= 254
}

// CreateOperator makes an account that has been invited and has nothing else:
// no password and no second factor. It cannot sign in until a link has set both.
func (d *Directory) CreateOperator(ctx context.Context, email, name, by string) (Operator, error) {
	email = NormaliseOperatorEmail(email)
	if !validOperatorEmail(email) {
		return Operator{}, ErrBadOperatorAddress
	}
	var o Operator
	err := scanOperator(d.pool.QueryRow(ctx, `
		INSERT INTO operator_accounts (email, name, created_by)
		VALUES ($1, $2, $3) RETURNING `+operatorColumns, email, strings.TrimSpace(name), by), &o)
	if isUnique(err) {
		return Operator{}, ErrOperatorExists
	}
	if err != nil {
		return Operator{}, err
	}
	return o, d.OperatorEvent(ctx, by, "operator.invited", o.Email, "")
}

func (d *Directory) OperatorByEmail(ctx context.Context, email string) (Operator, error) {
	var o Operator
	err := scanOperator(d.pool.QueryRow(ctx, `SELECT `+operatorColumns+` FROM operator_accounts WHERE email = $1`,
		NormaliseOperatorEmail(email)), &o)
	if errors.Is(err, pgx.ErrNoRows) {
		return Operator{}, ErrNoSuchOperator
	}
	return o, err
}

func (d *Directory) OperatorByID(ctx context.Context, id uuid.UUID) (Operator, error) {
	var o Operator
	err := scanOperator(d.pool.QueryRow(ctx, `SELECT `+operatorColumns+` FROM operator_accounts WHERE id = $1`, id), &o)
	if errors.Is(err, pgx.ErrNoRows) {
		return Operator{}, ErrNoSuchOperator
	}
	return o, err
}

func (d *Directory) ListOperators(ctx context.Context) ([]Operator, error) {
	rows, err := d.pool.Query(ctx, `SELECT `+operatorColumns+` FROM operator_accounts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Operator{}
	for rows.Next() {
		var o Operator
		if err := scanOperator(rows, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ links

// IssueOperatorToken makes a link's token, replacing any earlier one that was
// never used: only the newest link works.
func (d *Directory) IssueOperatorToken(ctx context.Context, id uuid.UUID, purpose string, hash []byte, expires, now time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE operator_tokens SET used_at = $3
		WHERE account_id = $1 AND purpose = $2 AND used_at IS NULL`, id, purpose, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO operator_tokens (account_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`, id, purpose, hash, expires); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PeekOperatorToken finds whom a link is for without spending it.
func (d *Directory) PeekOperatorToken(ctx context.Context, hash []byte, purpose string, now time.Time) (Operator, bool, error) {
	var o Operator
	err := scanOperator(d.pool.QueryRow(ctx, `
		SELECT a.id, a.email, a.name, a.status, a.password_hash, a.totp_secret_sealed, a.totp_enabled,
		       a.totp_last_step, a.failed_count, a.locked_until, a.created_by, a.created_at, a.last_sign_in_at, a.sessions_invalid_before
		  FROM operator_tokens t JOIN operator_accounts a ON a.id = t.account_id
		 WHERE t.token_hash = $1 AND t.purpose = $2 AND t.used_at IS NULL AND t.expires_at > $3
		   AND a.status <> 'disabled'`, hash, purpose, now), &o)
	if errors.Is(err, pgx.ErrNoRows) {
		return Operator{}, false, nil
	}
	return o, err == nil, err
}

// SpendOperatorToken uses a link up, once. One statement, so two uses at the
// same moment cannot both succeed.
func (d *Directory) SpendOperatorToken(ctx context.Context, hash []byte, purpose string, now time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := d.pool.QueryRow(ctx, `
		UPDATE operator_tokens SET used_at = $3
		 WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3
		 RETURNING account_id`, hash, purpose, now).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrOperatorLink
	}
	return id, err
}

// ---------------------------------------------------------- the password

// SetOperatorPassword sets a password and clears a lock. An invited account
// stays invited: it becomes active only when its second factor is enrolled.
func (d *Directory) SetOperatorPassword(ctx context.Context, id uuid.UUID, hash string, now time.Time) error {
	tag, err := d.pool.Exec(ctx, `UPDATE operator_accounts
		SET password_hash = $2, password_set_at = $3, sessions_invalid_before = $3, failed_count = 0, locked_until = NULL
		WHERE id = $1 AND status <> 'disabled'`, id, hash, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchOperator
	}
	return nil
}

// RecordOperatorFailure counts a wrong answer and, at the fifth, locks the
// account. The count starts again after a lock has lapsed. It reports whether
// the account is now locked.
func (d *Directory) RecordOperatorFailure(ctx context.Context, id uuid.UUID, now time.Time) (bool, error) {
	var count int
	err := d.pool.QueryRow(ctx, `
		UPDATE operator_accounts
		   SET failed_count = CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN 1 ELSE failed_count + 1 END,
		       locked_until = CASE
		         WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN 1 ELSE failed_count + 1 END) >= $3
		         THEN $2::timestamptz + $4::interval ELSE
		           CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 THEN NULL ELSE locked_until END
		       END
		 WHERE id = $1
		 RETURNING failed_count`, id, now, OperatorLockAfter, OperatorLockFor.String()).Scan(&count)
	if err != nil {
		return false, err
	}
	if count >= OperatorLockAfter {
		return true, d.OperatorEvent(ctx, "system", "operator.locked", id.String(), "")
	}
	return false, nil
}

// RecordOperatorSuccess clears the count at the END of a full sign-in, never
// after the password alone: a guesser who has the password must not get a fresh
// five tries at the second factor each time.
func (d *Directory) RecordOperatorSuccess(ctx context.Context, id uuid.UUID, now time.Time) error {
	_, err := d.pool.Exec(ctx, `UPDATE operator_accounts
		SET failed_count = 0, locked_until = NULL, last_sign_in_at = $2 WHERE id = $1`, id, now)
	return err
}

// --------------------------------------------------- the second factor

// SetPendingOperatorTOTP stores a secret while it is being enrolled, only if
// none is there: opening the enrolment page twice must not replace a secret a
// phone has already scanned.
func (d *Directory) SetPendingOperatorTOTP(ctx context.Context, id uuid.UUID, sealed []byte) (bool, error) {
	tag, err := d.pool.Exec(ctx, `UPDATE operator_accounts SET totp_secret_sealed = $2
		WHERE id = $1 AND NOT totp_enabled AND totp_secret_sealed IS NULL`, id, sealed)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// EnableOperatorTOTP turns the second factor on, stores the hashes of the
// recovery codes, and makes the account active. The database requires an
// active account to have both factors, so this is the only way to become one.
func (d *Directory) EnableOperatorTOTP(ctx context.Context, id uuid.UUID, step uint64, recoveryHashes []string) error {
	if recoveryHashes == nil {
		recoveryHashes = []string{} // an empty set, never NULL
	}
	tag, err := d.pool.Exec(ctx, `UPDATE operator_accounts
		SET totp_enabled = true, totp_last_step = $2, recovery_hashes = $3,
		    status = CASE WHEN status = 'invited' THEN 'active' ELSE status END
		WHERE id = $1 AND NOT totp_enabled AND totp_secret_sealed IS NOT NULL AND password_hash <> ''`,
		id, int64(step), recoveryHashes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchOperator
	}
	return d.OperatorEvent(ctx, "system", "operator.mfa_enrolled", id.String(), "")
}

// AcceptOperatorTOTPStep spends a code's time step once, so a code seen over a
// shoulder cannot be used again within its window.
func (d *Directory) AcceptOperatorTOTPStep(ctx context.Context, id uuid.UUID, step uint64) (bool, error) {
	tag, err := d.pool.Exec(ctx, `UPDATE operator_accounts SET totp_last_step = $2
		WHERE id = $1 AND totp_last_step < $2`, id, int64(step))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// UseOperatorRecovery spends one recovery code, once.
func (d *Directory) UseOperatorRecovery(ctx context.Context, id uuid.UUID, hash string) (bool, error) {
	tag, err := d.pool.Exec(ctx, `UPDATE operator_accounts SET recovery_hashes = array_remove(recovery_hashes, $2)
		WHERE id = $1 AND $2 = ANY(recovery_hashes)`, id, hash)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, d.OperatorEvent(ctx, "system", "operator.recovery_used", id.String(), "")
	}
	return false, nil
}

// ResetOperatorMFA removes the second factor, so the account has to enrol
// again. It goes back to invited, because an active account must have one.
func (d *Directory) ResetOperatorMFA(ctx context.Context, id uuid.UUID, by string) error {
	tag, err := d.pool.Exec(ctx, `UPDATE operator_accounts
		SET totp_enabled = false, totp_secret_sealed = NULL, totp_last_step = 0, recovery_hashes = '{}',
		    status = CASE WHEN status = 'active' THEN 'invited' ELSE status END,
		    sessions_invalid_before = $2
		WHERE id = $1 AND status <> 'disabled'`, id, time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchOperator
	}
	return d.OperatorEvent(ctx, by, "operator.mfa_reset", id.String(), "")
}

// SetOperatorStatus disables or re-enables an account. The last active owner
// cannot be disabled, because that would leave nobody who can sign in.
func (d *Directory) SetOperatorStatus(ctx context.Context, id uuid.UUID, disable bool, by string) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM operator_accounts WHERE id = $1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchOperator
		}
		return err
	}
	if disable {
		if status == "active" {
			var others int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM operator_accounts WHERE status = 'active' AND id <> $1`, id).Scan(&others); err != nil {
				return err
			}
			if others == 0 {
				return ErrLastOperator
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE operator_accounts SET status = 'disabled', sessions_invalid_before = $2 WHERE id = $1`, id, time.Now().UTC()); err != nil {
			return err
		}
	} else {
		// Re-enabled, it is as it was: active if it has both factors, otherwise
		// invited, and either way it needs a fresh link or its own password.
		if _, err := tx.Exec(ctx, `UPDATE operator_accounts
			SET status = CASE WHEN totp_enabled AND password_hash <> '' THEN 'active' ELSE 'invited' END
			WHERE id = $1 AND status = 'disabled'`, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	action := "operator.enabled"
	if disable {
		action = "operator.disabled"
	}
	return d.OperatorEvent(ctx, by, action, id.String(), "")
}

// ------------------------------------------------------------ the record

// OperatorEvent adds a line to the record of what owners do. It can be added
// to and read, and nothing in this package, or in the role, can change or
// remove one.
func (d *Directory) OperatorEvent(ctx context.Context, actor, action, target, detail string) error {
	_, err := d.pool.Exec(ctx, `INSERT INTO operator_events (actor, action, target, detail) VALUES ($1, $2, $3, $4)`,
		actor, action, target, detail)
	return err
}

// OperatorEventRow is one line of that record.
type OperatorEventRow struct {
	At                            time.Time
	Actor, Action, Target, Detail string
}

func (d *Directory) OperatorEvents(ctx context.Context, limit int) ([]OperatorEventRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.pool.Query(ctx, `SELECT at, actor, action, target, detail FROM operator_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OperatorEventRow{}
	for rows.Next() {
		var e OperatorEventRow
		if err := rows.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// IssueOperatorLink makes the one link an owner needs next and returns its
// token, shown once and kept only as a hash. An owner with no authenticator
// yet (a new one, or one whose second factor was reset) gets an invitation,
// which sets a password and then the authenticator. An owner who has both gets
// a reset, which changes the password and leaves the second factor alone: a
// link in an inbox must never be a way round it.
func (d *Directory) IssueOperatorLink(ctx context.Context, id uuid.UUID, by string, now time.Time) (token, purpose string, expires time.Time, err error) {
	o, err := d.OperatorByID(ctx, id)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if o.Status == "disabled" {
		return "", "", time.Time{}, ErrNoSuchOperator
	}
	purpose, life := "invite", OperatorInviteLife
	if o.TOTPEnabled && o.PasswordHash != "" {
		purpose, life = "reset", OperatorResetLife
	}
	token, hash, err := localauth.NewToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires = now.Add(life)
	if err := d.IssueOperatorToken(ctx, id, purpose, hash, expires, now); err != nil {
		return "", "", time.Time{}, err
	}
	return token, purpose, expires, d.OperatorEvent(ctx, by, "operator.link_issued", o.Email, purpose)
}
