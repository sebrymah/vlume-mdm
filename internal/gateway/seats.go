package gateway

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/identity"
	"platform/internal/notify"
)

// T8: administrator seats.
//
// A seat is a person with an administrative role who has signed in within
// the last 30 days. The plan says how many there are. The check runs at
// sign-in, inside the same transaction as the role lookup, so there is no
// administrator who got a session without a seat, and no seat taken by a
// sign-in that then failed.
//
// Employees never take a seat. The self-service role is part of every
// plan; counting it would turn "three administrator seats" into "three
// people", which is not what anybody buying a plan was told.

// ErrNoSeat is a sign-in that worked, mapped to an administrative role,
// and found every seat taken.
var ErrNoSeat = errors.New("all administrator seats are in use")

const seatWindow = 30 * 24 * time.Hour

// takeSeat records the sign-in and says whether a seat was there for it.
// A person seen within the window keeps their seat and takes no new one.
// A person never seen, or not seen for longer than the window, needs a
// free seat and is refused without one.
func takeSeat(ctx context.Context, tx *data.Tx, seats int, claims identity.Claims, role authz.Role) (bool, error) {
	if role == authz.Employee {
		return true, nil
	}
	var kept bool
	err := tx.QueryRow(ctx, `
		UPDATE tenant_admins
		   SET last_seen_at = now(), email = $2, name = $3, role = $4
		 WHERE subject = $1 AND last_seen_at > now() - $5::interval
		 RETURNING true`,
		claims.Subject, claims.Email, claims.Name, string(role), seatWindow.String()).Scan(&kept)
	if err == nil && kept {
		return true, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var used int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM tenant_admins WHERE last_seen_at > now() - $1::interval`,
		seatWindow.String()).Scan(&used); err != nil {
		return false, err
	}
	if used >= seats {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_admins (tenant_id, subject, email, name, role)
		VALUES (app.current_tenant(), $1, $2, $3, $4)
		ON CONFLICT (tenant_id, subject) DO UPDATE SET
		  last_seen_at = now(), email = excluded.email, name = excluded.name, role = excluded.role`,
		claims.Subject, claims.Email, claims.Name, string(role)); err != nil {
		return false, err
	}
	return true, data.AppendAudit(ctx, tx, "seat.taken", claims.Subject)
}

// seatRefused writes down the refusal, so the audit log says who was turned
// away and the people who can fix it are told once a day.
func seatRefused(ctx context.Context, tx *data.Tx, seats int, claims identity.Claims, role authz.Role) error {
	if err := data.AppendAudit(ctx, tx, "session.seat_refused", claims.Subject+" role:"+string(role)); err != nil {
		return err
	}
	return notify.Enqueue(ctx, tx, notify.Message{
		Topic:   notify.QuotaReached,
		Subject: "An administrator could not sign in: every seat is in use",
		Body: "Somebody whose group maps to the " + string(role) + " role signed in and was turned away, " +
			"because this plan's administrator seats are all in use. Release a seat on the Sign-in page, " +
			"or ask for a plan with more seats.",
		ObjectRef: "quota:seats", DedupeKey: "quota.seats:" + time.Now().UTC().Format("2006-01-02"),
		Once: true,
	})
}
