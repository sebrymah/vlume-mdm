package android

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"platform/internal/data"
)

// Self-service enrolment (0045): a person gets a code for their own phone.
//
// The three modes are the tenant's choice, made by an administrator, and the
// default is the safe one. The functions here only read and write the
// setting and count what a person has asked for; the rules that use them
// (whose address the code is for, how many, whether they have left) live in
// the gateway handler, where each one has a test.

// Self-enrolment modes.
const (
	SelfOff      = "off"
	SelfPersonal = "personal"
	SelfAny      = "any"
)

// ErrBadSelfMode is a setting this platform does not have.
var ErrBadSelfMode = errors.New("android: self-enrolment is off, personal or any")

// SelfLimit is how many codes one person may ask for in SelfWindow. A code
// that is never used expires by itself; the limit is there so a script, or a
// person with a stuck button, cannot make Google issue thousands.
const (
	SelfLimit  = 5
	SelfWindow = 24 * time.Hour
	// SelfLifetime is short on purpose. The code is shown on a screen the
	// person is looking at, to be scanned in the next minute or two.
	SelfLifetime = time.Hour
)

// SelfMode is the tenant's setting. No row means off.
func SelfMode(ctx context.Context, tx *data.Tx) (string, error) {
	var mode string
	err := tx.QueryRow(ctx, `SELECT self_enrol FROM tenant_enrolment WHERE tenant_id = app.current_tenant()`).Scan(&mode)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SelfOff, nil
		}
		return "", err
	}
	return mode, nil
}

// SetSelfMode changes the setting and writes the change down, with who made it.
func SetSelfMode(ctx context.Context, tx *data.Tx, mode, by string) error {
	switch mode {
	case SelfOff, SelfPersonal, SelfAny:
	default:
		return ErrBadSelfMode
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_enrolment (tenant_id, self_enrol, updated_by, updated_at)
		VALUES (app.current_tenant(), $1, $2, now())
		ON CONFLICT (tenant_id) DO UPDATE
		   SET self_enrol = EXCLUDED.self_enrol, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		mode, by); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "android.self_enrol_mode", "mode:"+mode)
}

// SelfAsked is how many codes this person has asked for since a moment.
// Serialised per person, so two clicks at once are counted one after the
// other and cannot both slip in under the limit.
func SelfAsked(ctx context.Context, tx *data.Tx, subject string, since time.Time) (int, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "self-enrol:"+subject); err != nil {
		return 0, err
	}
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM android_enrollment_tokens
		 WHERE source = 'self' AND created_by = $1 AND created_at > $2`, subject, since).Scan(&n)
	return n, err
}

// HasLeft says whether the platform has been told this person left.
//
// By subject first, the identifier a provider never reuses: an address passes
// to the next hire, and the next hire is not the leaver.
//
// There is one case the subject cannot cover. HR can name somebody who has
// never signed in, and that record holds an address and no subject. Such a
// record cannot tell the leaver from a later hire given the same address, so
// it is read the cautious way: whoever signs in with that address is refused,
// and an administrator, who can tell them apart, makes the token by hand. A
// wrongly refused hire costs one message to IT; a wrongly admitted leaver
// enrols a phone into the organisation.
func HasLeft(ctx context.Context, tx *data.Tx, subject, email string) (bool, error) {
	var left bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM people WHERE left_at IS NOT NULL AND subject = $1)
		    OR EXISTS (SELECT 1 FROM people WHERE left_at IS NOT NULL AND subject = '' AND $2 <> '' AND email = lower($2))`,
		subject, email).Scan(&left)
	return left, err
}
