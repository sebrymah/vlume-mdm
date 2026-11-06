package data

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Device is the record the whole platform hangs off. The EDR sensor and the
// DLP module both register against this row rather than creating their own.
type Device struct {
	ID           uuid.UUID
	Name         string
	Serial       string
	OSFamily     string
	Ownership    string
	State        string
	LastReportAt *time.Time
	// AssignedTo is what an administrator typed when they invited the
	// device: a subject from the identity provider, or more usually an
	// email address. Empty means nobody, which is the state of every
	// device enrolled before this column existed.
	AssignedTo string
	// PersonID is who the device is assigned to, as a person the platform
	// has met (0040): the key beside the typed address. Nil is nobody.
	PersonID *uuid.UUID
	// The lost report. It executes nothing; see 0009_assignment.sql.
	ReportedLostAt   *time.Time
	ReportedLostBy   string
	ReportedLostNote string
	// The quarantine, when there is one: who (a person, or policy:<label>)
	// and why. See 0016_enforcement.sql.
	QuarantinedAt    *time.Time
	QuarantinedBy    string
	QuarantineReason string
	// Tags are the groups a device is in, for staged rollout (F7): plain
	// words, set by whoever may change policy.
	Tags []string
	// Offboarding (F4): asked for, by whom, and done.
	OffboardingAt *time.Time
	OffboardingBy string
	OffboardedAt  *time.Time
}

func (d Device) Offboarding() bool { return d.OffboardingAt != nil && d.OffboardedAt == nil }
func (d Device) Retired() bool     { return d.State == "retired" }

func (d Device) ReportedLost() bool { return d.ReportedLostAt != nil }
func (d Device) Quarantined() bool  { return d.State == "quarantined" }

// Note what is missing from every signature below: a tenant id.
//
// The tenant is ambient on the transaction, set from the verified claim. A
// repository function that accepted a tenant id would be a function a caller
// could pass the wrong value to, and row-level security would then be the
// only thing standing between a typo and a cross-tenant read. Two controls
// are better than one, and this is the cheaper of the two.

func ListDevices(ctx context.Context, tx *Tx) ([]Device, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, name, serial, os_family, ownership, state, last_report_at,
		       assigned_to, person_id, coalesce(reported_lost_by,''), coalesce(reported_lost_note,''),
		       reported_lost_at, quarantined_at, coalesce(quarantined_by,''), coalesce(quarantine_reason,''), tags,
		       offboarding_at, coalesce(offboarding_by,''), offboarded_at
		  FROM devices
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Serial, &d.OSFamily,
			&d.Ownership, &d.State, &d.LastReportAt,
			&d.AssignedTo, &d.PersonID, &d.ReportedLostBy, &d.ReportedLostNote, &d.ReportedLostAt, &d.QuarantinedAt, &d.QuarantinedBy, &d.QuarantineReason, &d.Tags,
			&d.OffboardingAt, &d.OffboardingBy, &d.OffboardedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func FindDeviceBySerial(ctx context.Context, tx *Tx, serial string) ([]Device, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, name, serial, os_family, ownership, state, last_report_at,
		       assigned_to, person_id, coalesce(reported_lost_by,''), coalesce(reported_lost_note,''),
		       reported_lost_at, quarantined_at, coalesce(quarantined_by,''), coalesce(quarantine_reason,''), tags,
		       offboarding_at, coalesce(offboarding_by,''), offboarded_at
		  FROM devices
		 WHERE serial = $1`, serial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Serial, &d.OSFamily,
			&d.Ownership, &d.State, &d.LastReportAt,
			&d.AssignedTo, &d.PersonID, &d.ReportedLostBy, &d.ReportedLostNote, &d.ReportedLostAt, &d.QuarantinedAt, &d.QuarantinedBy, &d.QuarantineReason, &d.Tags,
			&d.OffboardingAt, &d.OffboardingBy, &d.OffboardedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// InsertDevice takes the tenant from app.current_tenant() in the statement
// itself rather than from Go. Even a caller holding a raw transaction cannot
// write a row into another tenant through this path, and the row-level
// security WITH CHECK clause refuses it if they try another way.
func InsertDevice(ctx context.Context, tx *Tx, name, serial, osFamily string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, name, serial, os_family)
		VALUES (app.current_tenant(), $1, $2, $3)
		RETURNING id`, name, serial, osFamily).Scan(&id)
	return id, err
}

// AppendAudit writes one record. The hash chain is computed by the database
// trigger, so an application that forgets to chain cannot produce an unchained
// row, and the chain stays per tenant.
func AppendAudit(ctx context.Context, tx *Tx, action, objectRef string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO audit_events (tenant_id, actor, action, object_ref)
		VALUES (app.current_tenant(), $1, $2, $3)`,
		tx.claim.Subject, action, objectRef)
	return err
}

// GetDevice returns pgx.ErrNoRows both when the device does not exist and
// when it belongs to another tenant, because row-level security makes those
// two cases indistinguishable here. The gateway turns both into 404, which is
// the design rule: a forbidden answer would confirm the object exists.
func GetDevice(ctx context.Context, tx *Tx, id uuid.UUID) (Device, error) {
	var d Device
	err := tx.QueryRow(ctx, `
		SELECT id, name, serial, os_family, ownership, state, last_report_at,
		       assigned_to, person_id, coalesce(reported_lost_by,''), coalesce(reported_lost_note,''),
		       reported_lost_at, quarantined_at, coalesce(quarantined_by,''), coalesce(quarantine_reason,''), tags,
		       offboarding_at, coalesce(offboarding_by,''), offboarded_at
		  FROM devices WHERE id = $1`, id).Scan(
		&d.ID, &d.Name, &d.Serial, &d.OSFamily,
		&d.Ownership, &d.State, &d.LastReportAt,
		&d.AssignedTo, &d.PersonID, &d.ReportedLostBy, &d.ReportedLostNote, &d.ReportedLostAt, &d.QuarantinedAt, &d.QuarantinedBy, &d.QuarantineReason, &d.Tags,
		&d.OffboardingAt, &d.OffboardingBy, &d.OffboardedAt)
	return d, err
}

// StateCounts is the dashboard's four numbers. Not compliant and state
// unknown are kept apart deliberately: a device failing a rule and a device
// we have not heard from are different problems with different fixes, and
// summing them is how a dashboard stops being read.
type StateCounts struct {
	Total         int
	Compliant     int
	NotCompliant  int
	StateUnknown  int
	Quarantined   int
	AwaitingFirst int
}

func CountByState(ctx context.Context, tx *Tx) (StateCounts, error) {
	var c StateCounts
	rows, err := tx.Query(ctx, `SELECT state, count(*) FROM devices GROUP BY state`)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return c, err
		}
		c.Total += n
		switch state {
		case "compliant":
			c.Compliant = n
		case "not_compliant":
			c.NotCompliant = n
		case "state_unknown":
			c.StateUnknown = n
		case "quarantined":
			c.Quarantined = n
		case "awaiting_first_boot":
			c.AwaitingFirst = n
		}
	}
	return c, rows.Err()
}

type AuditEvent struct {
	OccurredAt time.Time
	Actor      string
	Action     string
	ObjectRef  string
	Hash       string
}

func RecentAudit(ctx context.Context, tx *Tx, limit int) ([]AuditEvent, error) {
	rows, err := tx.Query(ctx, `
		SELECT occurred_at, actor, action, coalesce(object_ref,''), hash
		  FROM audit_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.OccurredAt, &e.Actor, &e.Action, &e.ObjectRef, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ------------------------------------------------------- one person's own
//
// These three are the employee surface, and they are built the same way the
// tenant isolation is built: the person is taken from the verified claim on
// the transaction, never from an argument. There is no signature below that
// a caller could pass someone else's identity to, which is the whole reason
// they exist rather than ListDevices with a filter.
//
// It is worth being honest about the strength of this. Tenant isolation has
// two independent controls: these functions and row-level security, which
// would refuse a cross-tenant read even if the Go were wrong. Person
// isolation inside a tenant has ONE: the predicate below. Row-level security
// cannot help, because an administrator legitimately reads every row in the
// tenant and a policy strong enough to stop an employee would stop them too.
// So this predicate is the control, and it is tested directly.

// ErrNotYours is returned rather than a row for a device belonging to
// someone else. It is turned into a 404, never a 403, for the same reason
// everywhere else: a forbidden answer would confirm the device exists.
var ErrNotYours = errors.New("data: that device is not assigned to you")

var ErrNotQuarantined = errors.New("data: that device is not quarantined")

var ErrNoSuchDevice = errors.New("data: no such device")

// whoAmI reads the person from the claim. An empty subject can never match,
// which is what stops a device certificate or an unattributed call from
// being treated as "whoever owns the unassigned devices".
func (t *Tx) whoAmI() (subject, email string, ok bool) {
	subject = strings.TrimSpace(t.claim.Subject)
	email = strings.TrimSpace(t.claim.Email)
	return subject, email, subject != ""
}

// mineClause is written once and used by all three, so a change to what
// "mine" means cannot apply to the listing and miss the single read.
//
// assigned_to <> ” matters: without it, a caller with an empty subject
// would match every device nobody has been given.
const mineClause = `person_id IS NOT NULL
		   AND person_id IN (SELECT id FROM people WHERE ` + activePerson + `)`

func MyDevices(ctx context.Context, tx *Tx) ([]Device, error) {
	subject, email, ok := tx.whoAmI()
	if !ok {
		return nil, ErrNotYours
	}
	rows, err := tx.Query(ctx, `
		SELECT id, name, serial, os_family, ownership, state, last_report_at,
		       assigned_to, person_id, coalesce(reported_lost_by,''), coalesce(reported_lost_note,''),
		       reported_lost_at, quarantined_at, coalesce(quarantined_by,''), coalesce(quarantine_reason,''), tags,
		       offboarding_at, coalesce(offboarding_by,''), offboarded_at
		  FROM devices
		 WHERE `+mineClause+`
		 ORDER BY name`, subject, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Serial, &d.OSFamily,
			&d.Ownership, &d.State, &d.LastReportAt,
			&d.AssignedTo, &d.PersonID, &d.ReportedLostBy, &d.ReportedLostNote,
			&d.ReportedLostAt, &d.QuarantinedAt, &d.QuarantinedBy, &d.QuarantineReason, &d.Tags,
			&d.OffboardingAt, &d.OffboardingBy, &d.OffboardedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MyDevice reads one, and refuses a colleague's.
func MyDevice(ctx context.Context, tx *Tx, id uuid.UUID) (Device, error) {
	subject, email, ok := tx.whoAmI()
	if !ok {
		return Device{}, ErrNotYours
	}
	var d Device
	err := tx.QueryRow(ctx, `
		SELECT id, name, serial, os_family, ownership, state, last_report_at,
		       assigned_to, person_id, coalesce(reported_lost_by,''), coalesce(reported_lost_note,''),
		       reported_lost_at, quarantined_at, coalesce(quarantined_by,''), coalesce(quarantine_reason,''), tags,
		       offboarding_at, coalesce(offboarding_by,''), offboarded_at
		  FROM devices
		 WHERE id = $3 AND `+mineClause, subject, email, id).Scan(
		&d.ID, &d.Name, &d.Serial, &d.OSFamily, &d.Ownership, &d.State,
		&d.LastReportAt, &d.AssignedTo, &d.PersonID, &d.ReportedLostBy, &d.ReportedLostNote,
		&d.ReportedLostAt, &d.QuarantinedAt, &d.QuarantinedBy, &d.QuarantineReason, &d.Tags,
		&d.OffboardingAt, &d.OffboardingBy, &d.OffboardedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotYours
	}
	if err != nil {
		return Device{}, err
	}
	return d, nil
}

// ReportMyDeviceLost raises the flag. It changes no state, sends no command
// and wakes nothing: an administrator decides what happens, through the
// pipeline, with its approvals. See 0009_assignment.sql for why.
func ReportMyDeviceLost(ctx context.Context, tx *Tx, id uuid.UUID, note string) (Device, error) {
	d, err := MyDevice(ctx, tx, id)
	if err != nil {
		return Device{}, err
	}
	if d.ReportedLost() {
		// Already raised. Pressing it twice is not an error and must not
		// move the timestamp, because the time it was first reported is the
		// fact anyone investigating will want.
		return d, nil
	}
	subject, _, _ := tx.whoAmI()
	if _, err := tx.Exec(ctx, `
		UPDATE devices
		   SET reported_lost_at = now(), reported_lost_by = $2, reported_lost_note = $3
		 WHERE id = $1`, id, subject, strings.TrimSpace(note)); err != nil {
		return Device{}, err
	}
	if err := AppendAudit(ctx, tx, "device.reported_lost", "device:"+id.String()); err != nil {
		return Device{}, err
	}
	return MyDevice(ctx, tx, id)
}

// ClearLostReport is an administrator saying the device turned up. It is
// theirs to do, not the holder's: a person who has just been phished into
// reporting a laptop lost should not also be the one who can quietly clear
// it.
func ClearLostReport(ctx context.Context, tx *Tx, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `
		UPDATE devices
		   SET reported_lost_at = NULL, reported_lost_by = NULL, reported_lost_note = NULL
		 WHERE id = $1 AND reported_lost_at IS NOT NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return AppendAudit(ctx, tx, "device.lost_report_cleared", "device:"+id.String())
}

// ReleaseQuarantine is a person's act, and the only way out of quarantine
// other than retirement. It sets the one setting the database trigger looks
// for, so this function is the whole of the path: a writer that forgets it
// is refused by the trigger. The device comes back as state_unknown, not
// compliant, because nothing has been checked since; the next report
// decides.
func ReleaseQuarantine(ctx context.Context, tx *Tx, id uuid.UUID, by string) error {
	if strings.TrimSpace(by) == "" {
		return errors.New("data: a release names who did it")
	}
	if _, err := tx.Exec(ctx, `SET LOCAL app.release = 'yes'`); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE devices
		   SET state = 'state_unknown',
		       quarantined_at = NULL, quarantined_by = NULL, quarantine_reason = NULL
		 WHERE id = $1 AND state = 'quarantined'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotQuarantined
	}
	return AppendAudit(ctx, tx, "device.released", "device:"+id.String()+" by:"+by)
}

// SetTags replaces a device's tags. Lower-cased, trimmed, de-duplicated,
// each a short plain word, because a tag is typed into a policy's stage
// and has to match exactly.
func SetTags(ctx context.Context, tx *Tx, id uuid.UUID, tags []string) ([]string, error) {
	seen := map[string]bool{}
	clean := []string{}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		if len(t) > 32 {
			return nil, errors.New("data: a tag is at most 32 characters")
		}
		for _, r := range t {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				return nil, errors.New("data: a tag is letters, digits, hyphens and underscores")
			}
		}
		seen[t] = true
		clean = append(clean, t)
	}
	if len(clean) > 20 {
		return nil, errors.New("data: at most 20 tags on a device")
	}
	tag, err := tx.Exec(ctx, `UPDATE devices SET tags = $2 WHERE id = $1`, id, clean)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNoSuchDevice
	}
	return clean, AppendAudit(ctx, tx, "device.tags", "device:"+id.String()+" tags:"+strings.Join(clean, ","))
}

// MarkOffboarding says a device is on its way out. The wipe follows
// through the pipeline; retirement follows the wipe.
func MarkOffboarding(ctx context.Context, tx *Tx, id uuid.UUID, by string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE devices SET offboarding_at = now(), offboarding_by = $2
		 WHERE id = $1 AND state <> 'retired' AND offboarding_at IS NULL`, id, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchDevice
	}
	return AppendAudit(ctx, tx, "device.offboarding", "device:"+id.String()+" by:"+by)
}

// Retire is the end of a device: retired, dated, out of every count. The
// certificate is revoked by the caller, who holds the package that issued
// it. A retired device frees its slot under the plan's cap.
func Retire(ctx context.Context, tx *Tx, id uuid.UUID, why string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE devices SET state = 'retired', offboarded_at = now()
		 WHERE id = $1 AND state <> 'retired'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchDevice
	}
	return AppendAudit(ctx, tx, "device.retired", "device:"+id.String()+" "+why)
}

// DevicesAssignedTo is a leaver's devices: everything assigned to the
// address and not already retired.
func DevicesAssignedTo(ctx context.Context, tx *Tx, assignedTo string) ([]Device, error) {
	return devicesWhere(ctx, tx, `lower(assigned_to) = lower($1) AND state <> 'retired'`, strings.TrimSpace(assignedTo))
}

// devicesWhere is the one listing query, with its predicate supplied, so
// every list of devices reads the same columns.
func devicesWhere(ctx context.Context, tx *Tx, where string, args ...any) ([]Device, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, name, serial, os_family, ownership, state, last_report_at,
		       assigned_to, person_id, coalesce(reported_lost_by,''), coalesce(reported_lost_note,''),
		       reported_lost_at, quarantined_at, coalesce(quarantined_by,''), coalesce(quarantine_reason,''), tags,
		       offboarding_at, coalesce(offboarding_by,''), offboarded_at
		  FROM devices WHERE `+where+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Serial, &d.OSFamily,
			&d.Ownership, &d.State, &d.LastReportAt,
			&d.AssignedTo, &d.PersonID, &d.ReportedLostBy, &d.ReportedLostNote, &d.ReportedLostAt,
			&d.QuarantinedAt, &d.QuarantinedBy, &d.QuarantineReason, &d.Tags,
			&d.OffboardingAt, &d.OffboardingBy, &d.OffboardedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
