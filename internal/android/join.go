package android

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/data"
	"platform/internal/localauth"
)

// Join links (0046): a link anyone can open, a six-digit code sent by another
// route, and limits on how many devices and for how long.

// The limits. The wrong-guess rule is per link and not per person because the
// people holding a bulk link are strangers to each other: ten wrong tries in
// an hour pause the link for an hour. Six digits is a million possibilities,
// so ten tries an hour is a hundred thousand hours of guessing.
const (
	JoinMaxUses  = 5000
	JoinMaxWrong = 10
	JoinWindow   = time.Hour
	JoinLockFor  = time.Hour
	// JoinTokenLife is how long the Google token made for one successful
	// entry lasts. It is shown on a screen being looked at.
	JoinTokenLife = time.Hour
)

// JoinLifetimes are the choices for how long a link lasts, in hours. A fixed
// list, not a free number: a link nobody remembers making and that never
// expires is the one that gets found later.
var JoinLifetimes = []int{24, 48, 168, 336, 720}

var (
	ErrBadJoinLimit  = errors.New("android: a join link is for between 1 and 5000 devices")
	ErrBadJoinLife   = errors.New("android: that is not one of the lifetimes on offer")
	ErrJoinName      = errors.New("android: a join link needs a name, up to 80 characters")
	ErrJoinNotUsable = errors.New("android: that join link cannot be used")
)

// JoinLink is a link as an administrator sees it. Neither the secret nor the
// code is here: neither can be read back.
type JoinLink struct {
	ID          uuid.UUID
	Name        string
	Ownership   string
	AssignedTo  string
	MaxUses     int
	Uses        int
	ExpiresAt   time.Time
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
	LockedUntil *time.Time
}

// State is what to call the link at a moment: the first that applies.
func (j JoinLink) State(now time.Time) string {
	switch {
	case j.Status == "cancelled":
		return "cancelled"
	case !now.Before(j.ExpiresAt):
		return "expired"
	case j.Uses >= j.MaxUses:
		return "full"
	case j.LockedUntil != nil && now.Before(*j.LockedUntil):
		return "paused"
	}
	return "active"
}

// JoinInput is what an administrator chooses.
type JoinInput struct {
	Name       string
	Ownership  string
	AssignedTo string
	MaxUses    int
	LifeHours  int
	By         string
}

// CreateJoin makes a link and returns the secret and the code, once. Nothing
// stored lets either be read back.
func CreateJoin(ctx context.Context, tx *data.Tx, in JoinInput) (id uuid.UUID, secret, code string, err error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > 80 {
		return uuid.Nil, "", "", ErrJoinName
	}
	if in.MaxUses < 1 || in.MaxUses > JoinMaxUses {
		return uuid.Nil, "", "", ErrBadJoinLimit
	}
	okLife := false
	for _, h := range JoinLifetimes {
		if h == in.LifeHours {
			okLife = true
		}
	}
	if !okLife {
		return uuid.Nil, "", "", ErrBadJoinLife
	}
	if in.Ownership != "personal" && in.Ownership != "company" {
		in.Ownership = "personal"
	}
	secret, secretHash, err := localauth.NewToken()
	if err != nil {
		return uuid.Nil, "", "", err
	}
	code, err = newCode()
	if err != nil {
		return uuid.Nil, "", "", err
	}
	codeHash, err := localauth.Hash(code)
	if err != nil {
		return uuid.Nil, "", "", err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO join_links (tenant_id, name, secret_hash, code_hash, ownership, assigned_to, max_uses, expires_at, created_by)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6, now() + make_interval(hours => $7), $8)
		RETURNING id`,
		in.Name, secretHash, codeHash, in.Ownership, strings.TrimSpace(in.AssignedTo), in.MaxUses, in.LifeHours, in.By).Scan(&id)
	if err != nil {
		return uuid.Nil, "", "", err
	}
	return id, secret, code, data.AppendAudit(ctx, tx, "android.join_created",
		fmt.Sprintf("link:%s uses:%d hours:%d ownership:%s", id, in.MaxUses, in.LifeHours, in.Ownership))
}

// newCode is six digits, uniformly, from the system's random source.
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

const joinColumns = `id, name, ownership, assigned_to, max_uses, uses, expires_at, status, created_by, created_at, locked_until`

func scanJoin(row pgx.Row, j *JoinLink) error {
	return row.Scan(&j.ID, &j.Name, &j.Ownership, &j.AssignedTo, &j.MaxUses, &j.Uses,
		&j.ExpiresAt, &j.Status, &j.CreatedBy, &j.CreatedAt, &j.LockedUntil)
}

// JoinBySecret finds the link a secret belongs to, and the hash of its code.
// found is false for a secret that is not one of ours.
func JoinBySecret(ctx context.Context, tx *data.Tx, secret string) (j JoinLink, codeHash string, found bool, err error) {
	h, ok := localauth.TokenHash(secret)
	if !ok {
		return JoinLink{}, "", false, nil
	}
	var j2 JoinLink
	err = tx.QueryRow(ctx, `SELECT `+joinColumns+`, code_hash FROM join_links WHERE secret_hash = $1`, h).
		Scan(&j2.ID, &j2.Name, &j2.Ownership, &j2.AssignedTo, &j2.MaxUses, &j2.Uses,
			&j2.ExpiresAt, &j2.Status, &j2.CreatedBy, &j2.CreatedAt, &j2.LockedUntil, &codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return JoinLink{}, "", false, nil
	}
	if err != nil {
		return JoinLink{}, "", false, err
	}
	return j2, codeHash, true, nil
}

// Joins lists the newest links, for the administrator's page.
func Joins(ctx context.Context, tx *data.Tx) ([]JoinLink, error) {
	rows, err := tx.Query(ctx, `SELECT `+joinColumns+` FROM join_links ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JoinLink{}
	for rows.Next() {
		var j JoinLink
		if err := scanJoin(rows, &j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CancelJoin ends a link at once. Devices already enrolled through it stay.
func CancelJoin(ctx context.Context, tx *data.Tx, id uuid.UUID, by string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE join_links SET status = 'cancelled', cancelled_by = $2, cancelled_at = now()
		 WHERE id = $1 AND status = 'active'`, id, by)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	return true, data.AppendAudit(ctx, tx, "android.join_cancelled", "link:"+id.String())
}

// JoinWrongCode counts a wrong guess against the link and, at the tenth in an
// hour, pauses it for an hour. The row is locked while it is counted so that
// a burst of guesses cannot all be counted as the first.
func JoinWrongCode(ctx context.Context, tx *data.Tx, id uuid.UUID, now time.Time) error {
	var count int
	var since *time.Time
	if err := tx.QueryRow(ctx, `SELECT failed_count, failed_since FROM join_links WHERE id = $1 FOR UPDATE`, id).
		Scan(&count, &since); err != nil {
		return err
	}
	if since == nil || now.Sub(*since) > JoinWindow {
		count, since = 0, &now
	}
	count++
	var lock *time.Time
	if count >= JoinMaxWrong {
		t := now.Add(JoinLockFor)
		lock = &t
		count, since = 0, nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE join_links SET failed_count = $2, failed_since = $3,
		       locked_until = COALESCE($4, locked_until)
		 WHERE id = $1`, id, count, since, lock); err != nil {
		return err
	}
	if lock != nil {
		return data.AppendAudit(ctx, tx, "android.join_paused", "link:"+id.String())
	}
	return nil
}

// UseJoin spends one use, if the link can still be used. It is one statement
// that checks every rule and counts, so two people entering the last valid
// code at once cannot both get it.
func UseJoin(ctx context.Context, tx *data.Tx, id uuid.UUID, now time.Time) (JoinLink, error) {
	var j JoinLink
	err := scanJoin(tx.QueryRow(ctx, `
		UPDATE join_links SET uses = uses + 1, failed_count = 0, failed_since = NULL
		 WHERE id = $1 AND status = 'active' AND expires_at > $2 AND uses < max_uses
		   AND (locked_until IS NULL OR locked_until <= $2)
		RETURNING `+joinColumns, id, now), &j)
	if errors.Is(err, pgx.ErrNoRows) {
		return JoinLink{}, ErrJoinNotUsable
	}
	return j, err
}

// VerifyJoinCode checks a typed code against a link's stored hash. Only
// digits of the right length are even tried: anything else is wrong without
// the cost of hashing it.
func VerifyJoinCode(typed, codeHash string) bool {
	typed = strings.TrimSpace(strings.ReplaceAll(typed, " ", ""))
	if len(typed) != 6 {
		return false
	}
	for _, r := range typed {
		if r < '0' || r > '9' {
			return false
		}
	}
	return localauth.Verify(typed, codeHash) == nil
}

// RecordJoinToken writes down a token made for one successful entry of a join
// link's code, with the link it came from, so a device that enrols with it can
// be traced back to the link.
func RecordJoinToken(ctx context.Context, tx *data.Tx, t EnrollmentToken, label, assignedTo, ownership string, link uuid.UUID) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO android_enrollment_tokens
		  (tenant_id, name, label, assigned_to, ownership, created_by, expires_at, source, join_id)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6, 'join', $7)`,
		t.Name, strings.TrimSpace(label), strings.TrimSpace(assignedTo), ownership, "join:"+link.String(), t.ExpiresAt, link); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "android.token.created", t.Name+" via join link:"+link.String())
}
