package android

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/data"
	"platform/internal/notify"
	"platform/internal/policy"
)

// The tenant's side: its binding, the tokens it handed out, and the sync
// that turns Google's device list into this platform's devices and
// verdicts. Everything here runs on a tenant transaction under row-level
// security, so the enterprise name read here is this tenant's and the
// devices written here are this tenant's.

var (
	ErrNotBound     = errors.New("android: this tenant has not bound an Android Enterprise")
	ErrAlreadyBound = errors.New("android: this tenant already has an Android Enterprise")
)

type Binding struct {
	Name          string
	DisplayName   string
	BoundBy       string
	BoundAt       time.Time
	LastSyncedAt  *time.Time
	LastSyncError string
}

// PolicyID is the one policy per enterprise this platform drives. The
// effective rules for Android devices are merged here and delivered as it.
const PolicyID = "default"

func (b Binding) PolicyName() string { return b.Name + "/policies/" + PolicyID }

func Bound(ctx context.Context, tx *data.Tx) (Binding, bool, error) {
	var b Binding
	err := tx.QueryRow(ctx, `
		SELECT name, display_name, bound_by, bound_at, last_synced_at, coalesce(last_sync_error,'')
		  FROM android_enterprises`).Scan(&b.Name, &b.DisplayName, &b.BoundBy, &b.BoundAt,
		&b.LastSyncedAt, &b.LastSyncError)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, false, nil
	}
	if err != nil {
		return Binding{}, false, err
	}
	return b, true, nil
}

func Bind(ctx context.Context, tx *data.Tx, e Enterprise, by string) error {
	if _, bound, err := Bound(ctx, tx); err != nil {
		return err
	} else if bound {
		return ErrAlreadyBound
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO android_enterprises (tenant_id, name, display_name, bound_by)
		VALUES (app.current_tenant(), $1, $2, $3)`, e.Name, e.DisplayName, by); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "android.bound", e.Name+" by:"+by)
}

func Unbind(ctx context.Context, tx *data.Tx, by string) (Binding, error) {
	b, bound, err := Bound(ctx, tx)
	if err != nil {
		return Binding{}, err
	}
	if !bound {
		return Binding{}, ErrNotBound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM android_enterprises`); err != nil {
		return Binding{}, err
	}
	return b, data.AppendAudit(ctx, tx, "android.unbound", b.Name+" by:"+by)
}

type TokenRecord struct {
	ID         uuid.UUID
	Name       string
	Label      string
	AssignedTo string
	Ownership  string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// RecordToken writes down a token Google issued. source is who asked for
// it: "admin" for an administrator, "self" for a person enrolling their own
// phone. The two are kept apart because the per-person limit counts only
// the second.
func RecordToken(ctx context.Context, tx *data.Tx, t EnrollmentToken, label, assignedTo, ownership, by, source string) error {
	if ownership == "" {
		ownership = "company"
	}
	if source == "" {
		source = "admin"
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO android_enrollment_tokens
		  (tenant_id, name, label, assigned_to, ownership, created_by, expires_at, source)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6, $7)`,
		t.Name, strings.TrimSpace(label), strings.TrimSpace(assignedTo), ownership, by, t.ExpiresAt, source); err != nil {
		return err
	}
	return data.AppendAudit(ctx, tx, "android.token.created", t.Name+" for:"+assignedTo)
}

func Tokens(ctx context.Context, tx *data.Tx) ([]TokenRecord, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, name, label, assigned_to, ownership, created_by, created_at, expires_at
		  FROM android_enrollment_tokens ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenRecord{}
	for rows.Next() {
		var t TokenRecord
		if err := rows.Scan(&t.ID, &t.Name, &t.Label, &t.AssignedTo, &t.Ownership,
			&t.CreatedBy, &t.CreatedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeliverPolicy merges the effective rules for Android devices and sends
// them to the tenant's enterprise. It returns the rules that are judged
// rather than enforced, so the caller can say so.
func DeliverPolicy(ctx context.Context, tx *data.Tx, p Provider) ([]string, error) {
	b, bound, err := Bound(ctx, tx)
	if err != nil || !bound {
		return nil, err
	}
	// Company-owned is the stricter merge; a personal device's work
	// profile gets the same policy, which is what a work profile is for.
	rules, _, err := policy.EffectiveFor(ctx, tx, "android", "company")
	if err != nil {
		return nil, err
	}
	body, undelivered := Translate(rules)
	if err := p.ApplyPolicy(ctx, b.Name, PolicyID, body); err != nil {
		return nil, err
	}
	return undelivered, data.AppendAudit(ctx, tx, "android.policy.delivered",
		fmt.Sprintf("%s rules:%d judged_only:%d", b.PolicyName(), len(rules), len(undelivered)))
}

// SyncResult is the in-vs-out block for one sync.
type SyncResult struct {
	Listed     int
	Created    int
	Judged     int
	Skipped    int
	SkipReason []string
}

// Sync reads the enterprise's devices and makes them this tenant's: a new
// device gets a row, every device gets judged by the engine from what
// Google reports, and the engine does what it always does from there,
// including F9.
func Sync(ctx context.Context, tx *data.Tx, p Provider, now time.Time) (SyncResult, error) {
	var res SyncResult
	b, bound, err := Bound(ctx, tx)
	if err != nil {
		return res, err
	}
	if !bound {
		return res, ErrNotBound
	}
	devices, err := p.ListDevices(ctx, b.Name)
	if err != nil {
		_, _ = tx.Exec(ctx, `UPDATE android_enterprises SET last_sync_error = $1`, err.Error())
		return res, err
	}
	res.Listed = len(devices)
	// What Google was given to enforce, for the one inference ReportFrom
	// makes. Re-derived here rather than remembered, so it is the policy
	// as it stands.
	rules, _, err := policy.EffectiveFor(ctx, tx, "android", "company")
	if err != nil {
		return res, err
	}
	delivered, _ := Translate(rules)

	for _, d := range devices {
		if d.State == "DELETED" || d.Serial == "" {
			res.Skipped++
			res.SkipReason = append(res.SkipReason, d.Name+": "+skipWhy(d))
			continue
		}
		id, err := deviceFor(ctx, tx, d)
		if err != nil {
			return res, err
		}
		if id == uuid.Nil {
			id, err = createDevice(ctx, tx, d)
			if err != nil {
				if strings.Contains(err.Error(), "device cap reached") {
					// A phone enrolled at Google that the plan has no
					// room for. Skipped with the reason, said once a
					// day, and the sync goes on with the rest.
					res.Skipped++
					res.SkipReason = append(res.SkipReason, d.Serial+": the plan's device cap is reached")
					if err := notify.Enqueue(ctx, tx, notify.Message{
						Topic:   notify.QuotaReached,
						Subject: "A device could not be enrolled: the plan's device cap is reached",
						Body: "An Android device (" + d.Serial + ") enrolled at Google but this plan has no " +
							"room for it. Retire a device, or ask for a larger plan. It will be picked up " +
							"by the next sync once there is room.",
						ObjectRef: "quota:devices", DedupeKey: "quota.devices:" + now.UTC().Format("2006-01-02"),
						Once: true,
					}); err != nil {
						return res, err
					}
					continue
				}
				return res, err
			}
			res.Created++
		}
		reportedAt := now
		if d.LastReportAt != nil {
			reportedAt = *d.LastReportAt
		}
		if _, err := policy.ApplyAt(ctx, tx, id, ReportFrom(d, delivered), reportedAt, now); err != nil {
			return res, err
		}
		res.Judged++
	}
	if _, err := tx.Exec(ctx,
		`UPDATE android_enterprises SET last_synced_at = $1, last_sync_error = NULL`, now); err != nil {
		return res, err
	}
	return res, data.AppendAudit(ctx, tx, "android.synced",
		fmt.Sprintf("listed:%d created:%d judged:%d skipped:%d", res.Listed, res.Created, res.Judged, res.Skipped))
}

func skipWhy(d Device) string {
	if d.State == "DELETED" {
		return "deleted at Google"
	}
	return "no serial number reported"
}

func deviceFor(ctx context.Context, tx *data.Tx, d Device) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE android_name = $1`, d.Name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

func createDevice(ctx context.Context, tx *data.Tx, d Device) (uuid.UUID, error) {
	// Who it is for, from the token it enrolled with.
	var assignedTo, ownership, label string
	err := tx.QueryRow(ctx, `
		SELECT assigned_to, ownership, label FROM android_enrollment_tokens WHERE name = $1`,
		d.EnrollmentToken).Scan(&assignedTo, &ownership, &label)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	name := d.Model
	if label != "" {
		name = label
	}
	if name == "" {
		name = "Android " + d.Serial
	}
	if ownership == "" {
		ownership = "company"
	}
	personID, err := data.PersonFor(ctx, tx, assignedTo, time.Now().UTC())
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	// A savepoint, so a refused insert (the device cap) does not poison
	// the sync's transaction for the devices after it.
	if _, err := tx.Exec(ctx, `SAVEPOINT device_insert`); err != nil {
		return uuid.Nil, err
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, name, serial, os_family, ownership, assigned_to, android_name, person_id)
		VALUES (app.current_tenant(), $1, $2, 'android', $3, $4, $5, $6)
		RETURNING id`, name, d.Serial, ownership, assignedTo, d.Name, personID).Scan(&id); err != nil {
		_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT device_insert`)
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT device_insert`); err != nil {
		return uuid.Nil, err
	}
	return id, data.AppendAudit(ctx, tx, "device.enrolled",
		"device:"+id.String()+" via:android_enterprise for:"+assignedTo)
}

// AndroidName is what a command to this device is addressed to.
func AndroidName(ctx context.Context, tx *data.Tx, deviceID uuid.UUID) (string, error) {
	var name *string
	if err := tx.QueryRow(ctx, `SELECT android_name FROM devices WHERE id = $1`, deviceID).Scan(&name); err != nil {
		return "", err
	}
	if name == nil {
		return "", errors.New("android: this device is not managed through Android Enterprise")
	}
	return *name, nil
}
