package data

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The network's view of the fleet, and the credential it holds to ask.
//
// What the network gets is one bit per device, allow or deny, with the
// reason. Deny means one of two things:
//
//   held      the platform has put the device somewhere a person must get
//             it out of: quarantined (by a person or by F9) or retired.
//   unknown   the device has not shown it is clean: it has never reported,
//             its last report is older than the platform tolerates, or it
//             was just released from quarantine and has not reported since.
//             The rule the engine applies everywhere, that not knowing is
//             never a pass, applies at the door as well (ruling 2026-11-04).
//
// Two things deliberately do NOT deny:
//
//   not_compliant   the verdict alone. If a tenant wants failing devices
//                   kept off the network, that is exactly what "on_failure":
//                   "quarantine" in the policy means, and then they are.
//   reported lost   the lost report executes nothing, by design (0009), and
//                   a device that is lost and still on the network is a
//                   device that can still be located and locked.

type IntegrationToken struct {
	ID   uuid.UUID
	Name string
	// Scope is what the token may do: "network" reads the access feed,
	// "hr" says a person has left. One token, one job.
	Scope      string
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	RevokedBy  string
}

func (t IntegrationToken) Live() bool { return t.RevokedAt == nil }

var ErrNoSuchToken = errors.New("data: no such integration token")

func CreateIntegrationToken(ctx context.Context, tx *Tx, name, scope string, hash []byte, by string) (IntegrationToken, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return IntegrationToken{}, errors.New("data: an integration needs a name")
	}
	if scope == "" {
		scope = "network"
	}
	if scope != "network" && scope != "hr" {
		return IntegrationToken{}, errors.New("data: a token's scope is network or hr")
	}
	if len(hash) != 32 {
		return IntegrationToken{}, errors.New("data: the token hash is not a SHA-256")
	}
	var t IntegrationToken
	err := tx.QueryRow(ctx, `
		INSERT INTO integration_tokens (tenant_id, name, scope, token_hash, created_by)
		VALUES (app.current_tenant(), $1, $2, $3, $4)
		RETURNING id, name, scope, created_by, created_at`, name, scope, hash, by).Scan(
		&t.ID, &t.Name, &t.Scope, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		return IntegrationToken{}, err
	}
	return t, AppendAudit(ctx, tx, "integration.created", "integration:"+t.Name+" scope:"+t.Scope+" by:"+by)
}

func ListIntegrationTokens(ctx context.Context, tx *Tx) ([]IntegrationToken, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, name, scope, created_by, created_at, last_used_at, revoked_at, coalesce(revoked_by,'')
		  FROM integration_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IntegrationToken{}
	for rows.Next() {
		var t IntegrationToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Scope, &t.CreatedBy, &t.CreatedAt,
			&t.LastUsedAt, &t.RevokedAt, &t.RevokedBy); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func RevokeIntegrationToken(ctx context.Context, tx *Tx, id uuid.UUID, by string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE integration_tokens SET revoked_at = now(), revoked_by = $2
		 WHERE id = $1 AND revoked_at IS NULL`, id, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchToken
	}
	return AppendAudit(ctx, tx, "integration.revoked", "integration:"+id.String()+" by:"+by)
}

// LookupIntegrationToken resolves a presented token's hash to the live
// token it belongs to. A revoked token is ErrNoSuchToken: revocation is
// the whole reason the row exists.
func LookupIntegrationToken(ctx context.Context, tx *Tx, hash []byte) (IntegrationToken, error) {
	var t IntegrationToken
	err := tx.QueryRow(ctx, `
		SELECT id, name, scope, created_by, created_at, last_used_at
		  FROM integration_tokens
		 WHERE token_hash = $1 AND revoked_at IS NULL`, hash).Scan(
		&t.ID, &t.Name, &t.Scope, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IntegrationToken{}, ErrNoSuchToken
	}
	if err != nil {
		return IntegrationToken{}, err
	}
	// last_used_at is for the page that shows a dead integration. Written
	// at most once a minute so a controller polling every few seconds is
	// not a write per request.
	if t.LastUsedAt == nil || time.Since(*t.LastUsedAt) > time.Minute {
		if _, err := tx.Exec(ctx,
			`UPDATE integration_tokens SET last_used_at = now() WHERE id = $1`, t.ID); err != nil {
			return IntegrationToken{}, err
		}
	}
	return t, nil
}

// NetworkVerdict is what the network is told about one device.
type NetworkVerdict struct {
	Serial string `json:"serial"`
	// MAC is the address the network asked by, when it asked by one.
	MAC    string     `json:"mac,omitempty"`
	Access string     `json:"access"` // allow, deny
	State  string     `json:"state"`
	Reason string     `json:"reason,omitempty"`
	Since  *time.Time `json:"since,omitempty"`
}

func networkVerdict(serial, state, reason string, since, lastReport *time.Time,
	maxAge time.Duration, now time.Time) NetworkVerdict {

	v := NetworkVerdict{Serial: serial, State: state, Access: "allow"}
	switch state {
	case "quarantined":
		v.Access, v.Reason, v.Since = "deny", reason, since
		if v.Reason == "" {
			v.Reason = "quarantined"
		}
	case "retired":
		v.Access, v.Reason = "deny", "retired"
	case "state_unknown", "awaiting_first_boot":
		v.Access, v.Reason = "deny", "has not reported clean"
		if lastReport == nil {
			v.Reason = "has never reported"
		}
	}
	// A clean verdict goes stale. The engine re-checks this when anyone
	// looks at a verdict; the door checks it when anyone knocks.
	if v.Access == "allow" && maxAge > 0 &&
		(lastReport == nil || now.Sub(*lastReport) > maxAge) {
		v.Access, v.Reason = "deny", "has never reported"
		if lastReport != nil {
			v.Reason = "no report for " + days(now.Sub(*lastReport))
		}
	}
	return v
}

func days(d time.Duration) string {
	n := int(d.Hours() / 24)
	if n == 1 {
		return "1 day"
	}
	return strconv.Itoa(n) + " days"
}

// NetworkAccess answers for one serial. A serial this tenant does not
// manage is not found, and the network's own policy decides what an
// unmanaged device gets. maxAge is how old a clean report may be and still
// count; the caller passes the engine's own limit so the two agree.
func NetworkAccess(ctx context.Context, tx *Tx, serial string, maxAge time.Duration) (NetworkVerdict, bool, error) {
	var state, reason string
	var since, lastReport *time.Time
	err := tx.QueryRow(ctx, `
		SELECT state, coalesce(quarantine_reason,''), quarantined_at, last_report_at
		  FROM devices WHERE serial = $1`, strings.TrimSpace(serial)).Scan(&state, &reason, &since, &lastReport)
	if errors.Is(err, pgx.ErrNoRows) {
		return NetworkVerdict{}, false, nil
	}
	if err != nil {
		return NetworkVerdict{}, false, err
	}
	return networkVerdict(serial, state, reason, since, lastReport, maxAge, time.Now().UTC()), true, nil
}

// NetworkAccessByID answers for a device found another way, by its MAC.
func NetworkAccessByID(ctx context.Context, tx *Tx, id uuid.UUID, maxAge time.Duration) (NetworkVerdict, bool, error) {
	var serial, state, reason string
	var since, lastReport *time.Time
	err := tx.QueryRow(ctx, `
		SELECT serial, state, coalesce(quarantine_reason,''), quarantined_at, last_report_at
		  FROM devices WHERE id = $1`, id).Scan(&serial, &state, &reason, &since, &lastReport)
	if errors.Is(err, pgx.ErrNoRows) {
		return NetworkVerdict{}, false, nil
	}
	if err != nil {
		return NetworkVerdict{}, false, err
	}
	return networkVerdict(serial, state, reason, since, lastReport, maxAge, time.Now().UTC()), true, nil
}

// NetworkDenied is the bulk form, for a controller that syncs a block list
// rather than asking per device. It is computed the same way as the single
// answer, over every device, so the two can never disagree.
func NetworkDenied(ctx context.Context, tx *Tx, maxAge time.Duration) ([]NetworkVerdict, error) {
	rows, err := tx.Query(ctx, `
		SELECT serial, state, coalesce(quarantine_reason,''), quarantined_at, last_report_at
		  FROM devices ORDER BY serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	out := []NetworkVerdict{}
	for rows.Next() {
		var serial, state, reason string
		var since, lastReport *time.Time
		if err := rows.Scan(&serial, &state, &reason, &since, &lastReport); err != nil {
			return nil, err
		}
		if v := networkVerdict(serial, state, reason, since, lastReport, maxAge, now); v.Access == "deny" {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}
