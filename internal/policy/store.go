package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/data"
	"platform/internal/notify"
)

// This file is the half of the package that touches the database. The other
// half is pure, which is why the merge and the evaluation can be tested
// exhaustively without one.

var (
	ErrNoSuchPolicy = errors.New("policy: no such policy")
	ErrBadScope     = errors.New("policy: unknown scope")
	ErrBadName      = errors.New("policy: a policy needs a name")
	ErrNoDevice     = errors.New("policy: no such device")
)

type Policy struct {
	ID        uuid.UUID
	Name      string
	Version   int
	Active    bool
	Scope     Scope
	Rules     Rules
	Body      []byte
	CreatedBy string
	CreatedAt time.Time
	// OnFailure is what this policy asks to happen to a device that fails
	// it: FailNone or FailQuarantine.
	OnFailure string
	// Remediate says this policy asks the device to put a failure right by
	// itself where it can. Off unless the body says so.
	Remediate bool
	// The stage (F7). A live version is 100% with no tag. A rolling
	// version applies to devices carrying RolloutTag, to RolloutPercent of
	// the rest by a stable hash, or both.
	RolloutPercent int
	RolloutTag     string
}

// Rolling says whether this version is a stage rather than the live one.
func (p Policy) Rolling() bool { return p.RolloutPercent < 100 || p.RolloutTag != "" }

// StageWords is how a stage reads on the page.
func (p Policy) StageWords() string {
	switch {
	case !p.Rolling():
		return ""
	case p.RolloutTag != "" && p.RolloutPercent > 0:
		return fmt.Sprintf("rolling out to devices tagged %q and %d%% of the rest", p.RolloutTag, p.RolloutPercent)
	case p.RolloutTag != "":
		return fmt.Sprintf("rolling out to devices tagged %q", p.RolloutTag)
	default:
		return fmt.Sprintf("rolling out to %d%% of devices", p.RolloutPercent)
	}
}

// InStage says whether a device is in this version's stage. The percent
// is decided by a hash of the device id, so widening a stage keeps every
// device that was already in it.
func (p Policy) InStage(deviceID uuid.UUID, tags []string) bool {
	if !p.Rolling() {
		return true
	}
	if p.RolloutTag != "" {
		for _, t := range tags {
			if t == p.RolloutTag {
				return true
			}
		}
	}
	return p.RolloutPercent > 0 && bucket(deviceID) < p.RolloutPercent
}

func bucket(id uuid.UUID) int {
	h := fnv.New32a()
	h.Write(id[:])
	return int(h.Sum32() % 100)
}

// Quarantines says whether any of the policies that applied asked for
// quarantine on failure, and which one first. Strictest wins, as with the
// rules themselves: one policy asking is enough.
func Quarantines(applied []Policy) (bool, string) {
	asking := quarantining(applied)
	if len(asking) == 0 {
		return false, ""
	}
	return true, asking[0].Label()
}

func quarantining(applied []Policy) []Policy {
	var out []Policy
	for _, p := range applied {
		if p.OnFailure == FailQuarantine {
			out = append(out, p)
		}
	}
	return out
}

// Label is how a requirement names where it came from, so a finding can be
// traced to a policy and a version rather than to "policy".
func (p Policy) Label() string { return fmt.Sprintf("%s v%d", p.Name, p.Version) }

// rulesToMerge is this policy's rules carrying its remediate answer, so the
// mark travels through the merge with whichever requirement wins. It is set
// here and nowhere else: a requirement is never marked for the device to
// act on except by the policy that asked for it.
func (p Policy) rulesToMerge() Rules {
	if !p.Remediate {
		return p.Rules
	}
	out := make(Rules, len(p.Rules))
	for k, r := range p.Rules {
		r.Fix = true
		out[k] = r
	}
	return out
}

// ---------------------------------------------------------------- reading

func scan(rows pgx.Rows) ([]Policy, error) {
	out := []Policy{}
	for rows.Next() {
		var (
			p         Policy
			osFamily  *string
			ownership *string
		)
		if err := rows.Scan(&p.ID, &p.Name, &p.Version, &p.Active, &osFamily,
			&ownership, &p.Body, &p.CreatedBy, &p.CreatedAt, &p.RolloutPercent, &p.RolloutTag); err != nil {
			return nil, err
		}
		if osFamily != nil {
			p.Scope.OSFamily = *osFamily
		}
		if ownership != nil {
			p.Scope.Ownership = *ownership
		}
		rules, set, err := ParseBody(p.Label(), p.Body)
		if err != nil {
			// A stored policy that no longer parses. It is not skipped: a
			// policy the engine cannot read is a requirement nobody is
			// being held to, and failing loudly is the only way that gets
			// noticed before an audit does.
			return nil, fmt.Errorf("policy %s is stored in a form this version cannot read: %w",
				p.Label(), err)
		}
		p.Rules, p.OnFailure, p.Remediate = rules, set.OnFailure, set.Remediate
		out = append(out, p)
	}
	return out, rows.Err()
}

const policyColumns = `id, name, version, active, scope_os_family, scope_ownership,
                       body, created_by, created_at, rollout_percent, coalesce(rollout_tag,'')`

// List returns every policy, live and superseded, newest first. The old
// versions are the answer to "what did we require in March".
func List(ctx context.Context, tx *data.Tx) ([]Policy, error) {
	rows, err := tx.Query(ctx, `SELECT `+policyColumns+`
		  FROM policies ORDER BY name, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scan(rows)
}

// Active returns only the live version of each policy.
func Active(ctx context.Context, tx *data.Tx) ([]Policy, error) {
	rows, err := tx.Query(ctx, `SELECT `+policyColumns+`
		  FROM policies WHERE active ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scan(rows)
}

// EffectiveFor is the question an administrator actually asks: what does
// THIS laptop have to do.
//
// It returns the merged rules and the policies that produced them, so the
// answer can be shown with its reasoning rather than as a bare list.
func EffectiveFor(ctx context.Context, tx *data.Tx, osFamily, ownership string) (Rules, []Policy, error) {
	all, err := Active(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	var (
		sets    []Rules
		applied []Policy
	)
	for _, p := range all {
		// The live merge: stages do not count here. A vendor policy
		// delivered enterprise-wide (Android) is the live one until the
		// stage is promoted.
		if p.Rolling() || !p.Scope.Matches(osFamily, ownership) {
			continue
		}
		sets = append(sets, p.rulesToMerge())
		applied = append(applied, p)
	}
	return Merge(sets...), applied, nil
}

// EffectiveForDevice is EffectiveFor with stages: for each policy name, the
// rolling version if this device is in its stage, else the live one.
func EffectiveForDevice(ctx context.Context, tx *data.Tx, deviceID uuid.UUID,
	osFamily, ownership string, tags []string) (Rules, []Policy, error) {

	all, err := Active(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	chosen := map[string]Policy{}
	order := []string{}
	for _, p := range all {
		if !p.Scope.Matches(osFamily, ownership) {
			continue
		}
		if _, seen := chosen[p.Name]; !seen {
			order = append(order, p.Name)
		}
		switch {
		case p.Rolling() && p.InStage(deviceID, tags):
			chosen[p.Name] = p // the stage wins for a device in it
		case !p.Rolling():
			if cur, ok := chosen[p.Name]; !ok || !cur.Rolling() {
				chosen[p.Name] = p
			}
		}
	}
	var (
		sets    []Rules
		applied []Policy
	)
	for _, name := range order {
		p, ok := chosen[name]
		if !ok {
			continue
		}
		sets = append(sets, p.rulesToMerge())
		applied = append(applied, p)
	}
	return Merge(sets...), applied, nil
}

// ---------------------------------------------------------------- writing

type SaveInput struct {
	Name      string
	Scope     Scope
	Body      []byte
	CreatedBy string
	// Stage, when set, saves this version as a rolling one rather than
	// replacing the live one. Percent 0 with a tag means the tag alone.
	Stage *Stage
}

type Stage struct {
	Percent int
	Tag     string
}

var ErrBadStage = errors.New("policy: a stage is a percentage from 1 to 99, a tag, or both")

// Save writes a policy as a NEW VERSION and switches the previous one off.
//
// Nothing is edited in place. A compliance verdict reached last month was
// reached against a particular set of requirements, and if those
// requirements can be rewritten underneath it then the verdict cannot be
// explained afterwards. Versions make the history answerable from the table.
func Save(ctx context.Context, tx *data.Tx, in SaveInput) (Policy, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return Policy{}, ErrBadName
	}
	if in.Scope.OSFamily != "" {
		switch in.Scope.OSFamily {
		case "macos", "ios", "ipados", "android", "windows":
		default:
			return Policy{}, fmt.Errorf("%w: %q is not an operating system this platform manages",
				ErrBadScope, in.Scope.OSFamily)
		}
	}
	if in.Scope.Ownership != "" && in.Scope.Ownership != "company" && in.Scope.Ownership != "personal" {
		return Policy{}, fmt.Errorf("%w: ownership is company or personal", ErrBadScope)
	}
	if len(in.Body) == 0 {
		in.Body = []byte("{}")
	}
	// Parsed before it is stored, so an unknown rule name is refused at the
	// point someone typed it rather than discovered by the engine later.
	if _, err := Parse(in.Name, in.Body); err != nil {
		return Policy{}, err
	}

	percent, tag := 100, ""
	if in.Stage != nil {
		percent, tag = in.Stage.Percent, strings.TrimSpace(in.Stage.Tag)
		if percent < 0 || percent > 99 || (percent == 0 && tag == "") {
			return Policy{}, ErrBadStage
		}
		// A new stage replaces the previous stage, and leaves the live
		// version standing for everyone outside it.
		if _, err := tx.Exec(ctx, `
			UPDATE policies SET active = false
			 WHERE name = $1 AND active AND (rollout_percent < 100 OR rollout_tag IS NOT NULL)`, in.Name); err != nil {
			return Policy{}, err
		}
	} else {
		// A full save replaces everything live for the name, the stage
		// included: what was being tried is now what is.
		if _, err := tx.Exec(ctx,
			`UPDATE policies SET active = false WHERE name = $1 AND active`, in.Name); err != nil {
			return Policy{}, err
		}
	}

	var next int
	if err := tx.QueryRow(ctx,
		`SELECT coalesce(max(version), 0) + 1 FROM policies WHERE name = $1`,
		in.Name).Scan(&next); err != nil {
		return Policy{}, err
	}

	var (
		p         Policy
		osFamily  = nullable(in.Scope.OSFamily)
		ownership = nullable(in.Scope.Ownership)
	)
	err := tx.QueryRow(ctx, `
		INSERT INTO policies
		  (tenant_id, name, version, body, scope_os_family, scope_ownership, active, created_by,
		   rollout_percent, rollout_tag)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, true, $6, $7, $8)
		RETURNING `+policyColumns, in.Name, next, in.Body, osFamily, ownership,
		in.CreatedBy, percent, nullable(tag)).Scan(&p.ID, &p.Name, &p.Version, &p.Active, &osFamily,
		&ownership, &p.Body, &p.CreatedBy, &p.CreatedAt, &p.RolloutPercent, &p.RolloutTag)
	if err != nil {
		return Policy{}, err
	}
	p.Scope = in.Scope
	var set Settings
	p.Rules, set, _ = ParseBody(p.Label(), p.Body)
	p.OnFailure, p.Remediate = set.OnFailure, set.Remediate

	if p.Rolling() {
		return p, data.AppendAudit(ctx, tx, "policy.stage", "policy:"+p.Label()+" "+p.StageWords())
	}
	return p, data.AppendAudit(ctx, tx, "policy.save", "policy:"+p.Label())
}

// Promote makes the rolling version live. Devices outside the stage move
// to it at their next report; the version number does not change, because
// nothing about the rules did.
func Promote(ctx context.Context, tx *data.Tx, name, by string) (Policy, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM policies
		 WHERE name = $1 AND active AND (rollout_percent < 100 OR rollout_tag IS NOT NULL)`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNoSuchPolicy
	}
	if err != nil {
		return Policy{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE policies SET active = false
		 WHERE name = $1 AND active AND rollout_percent = 100 AND rollout_tag IS NULL`, name); err != nil {
		return Policy{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE policies SET rollout_percent = 100, rollout_tag = NULL WHERE id = $1`, id); err != nil {
		return Policy{}, err
	}
	p, err := byID(ctx, tx, id)
	if err != nil {
		return Policy{}, err
	}
	return p, data.AppendAudit(ctx, tx, "policy.promote", "policy:"+p.Label()+" by:"+by)
}

// Halt withdraws the rolling version. The live one stands.
func Halt(ctx context.Context, tx *data.Tx, name, by string) (Policy, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM policies
		 WHERE name = $1 AND active AND (rollout_percent < 100 OR rollout_tag IS NOT NULL)`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNoSuchPolicy
	}
	if err != nil {
		return Policy{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE policies SET active = false WHERE id = $1`, id); err != nil {
		return Policy{}, err
	}
	p, err := byID(ctx, tx, id)
	if err != nil {
		return Policy{}, err
	}
	return p, data.AppendAudit(ctx, tx, "policy.halt", "policy:"+p.Label()+" by:"+by)
}

func byID(ctx context.Context, tx *data.Tx, id uuid.UUID) (Policy, error) {
	rows, err := tx.Query(ctx, `SELECT `+policyColumns+` FROM policies WHERE id = $1`, id)
	if err != nil {
		return Policy{}, err
	}
	defer rows.Close()
	ps, err := scan(rows)
	if err != nil {
		return Policy{}, err
	}
	if len(ps) == 0 {
		return Policy{}, ErrNoSuchPolicy
	}
	return ps[0], nil
}

// Retire switches a policy off without replacing it. Its versions stay in
// the table.
func Retire(ctx context.Context, tx *data.Tx, name string) error {
	tag, err := tx.Exec(ctx,
		`UPDATE policies SET active = false WHERE name = $1 AND active`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchPolicy
	}
	return data.AppendAudit(ctx, tx, "policy.retire", "policy:"+name)
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ------------------------------------------------------------- the verdict

type Compliance struct {
	DeviceID    uuid.UUID
	ReportedAt  time.Time
	EvaluatedAt time.Time
	State       string
	Findings    []Finding
	Policies    []string
	Report      Report
	// Enforcement is what this evaluation DID, beyond judging: "" for
	// nothing, EnforcedQuarantine when the device was quarantined,
	// EnforcementHalted when a policy asked for it and the brake refused.
	Enforcement string
	// DeviceState is the device's own state afterwards, which is the
	// verdict unless an administrative hold or an enforcement overrides it.
	DeviceState string
}

const (
	EnforcedQuarantine = "quarantined"
	EnforcementHalted  = "halted"
)

// The brake. Automatic quarantine stops when more than this share of the
// fleet is failing, with an absolute floor so a fleet of two is not frozen
// by one bad laptop. Above it, a mass failure is far more likely a policy
// change or an agent fault than a fleet gone bad at once, and the right
// move is to stop and say so (standing directive 1).
const (
	BrakeShare = 5 // per cent of the fleet
	BrakeFloor = 3 // failing devices always tolerated before the brake can trip
)

// brakeLimit is the most failing devices automatic quarantine will act on.
func brakeLimit(fleet int) int {
	limit := (fleet*BrakeShare + 99) / 100
	if limit < BrakeFloor {
		limit = BrakeFloor
	}
	return limit
}

// Apply records what a device said and decides on it, in one transaction.
//
// Report and verdict are written together because a verdict without the
// report it came from cannot be explained to the person whose laptop was
// just marked non-compliant, and that explanation is the entire difference
// between a compliance product and a list of red rows.
func Apply(ctx context.Context, tx *data.Tx, deviceID uuid.UUID,
	rep Report, now time.Time) (Compliance, error) {
	return ApplyAt(ctx, tx, deviceID, rep, now, now)
}

// ApplyAt is Apply for a report made at reportedAt rather than now: a sync
// from a vendor that holds the device's last status report. A report older
// than MaxReportAge is judged stale here exactly as it would be at read.
func ApplyAt(ctx context.Context, tx *data.Tx, deviceID uuid.UUID,
	rep Report, reportedAt, now time.Time) (Compliance, error) {

	var osFamily, ownership, deviceState string
	var tags []string
	err := tx.QueryRow(ctx,
		`SELECT os_family, ownership, state, tags FROM devices WHERE id = $1`,
		deviceID).Scan(&osFamily, &ownership, &deviceState, &tags)
	if errors.Is(err, pgx.ErrNoRows) {
		return Compliance{}, ErrNoDevice
	}
	if err != nil {
		return Compliance{}, err
	}

	rules, applied, err := EffectiveForDevice(ctx, tx, deviceID, osFamily, ownership, tags)
	if err != nil {
		return Compliance{}, err
	}
	verdict := Evaluate(rules, rep, reportedAt, now)

	labels := make([]string, 0, len(applied))
	for _, p := range applied {
		labels = append(labels, p.Label())
	}
	reportJSON, err := json.Marshal(rep)
	if err != nil {
		return Compliance{}, err
	}
	findingsJSON, err := json.Marshal(verdict.Findings)
	if err != nil {
		return Compliance{}, err
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return Compliance{}, err
	}
	// What the verdict was before this one, so the history (0041) gets a
	// row only when the answer changes.
	before, err := data.PreviousVerdictFingerprint(ctx, tx, deviceID)
	if err != nil {
		return Compliance{}, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO device_compliance
		  (tenant_id, device_id, reported_at, report, evaluated_at, state, findings, policies)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, device_id) DO UPDATE SET
		  reported_at = excluded.reported_at, report = excluded.report,
		  evaluated_at = excluded.evaluated_at, state = excluded.state,
		  findings = excluded.findings, policies = excluded.policies`,
		deviceID, reportedAt, reportJSON, now, verdict.State, findingsJSON, labelsJSON); err != nil {
		return Compliance{}, err
	}
	if _, err := data.RecordVerdictIfChanged(ctx, tx, deviceID, before,
		data.VerdictFingerprint(verdict.State, findingsJSON), reportedAt, now, verdict.State, findingsJSON, labelsJSON); err != nil {
		return Compliance{}, err
	}

	// The device's own state follows the verdict, but ONLY from a state
	// evaluation owns. A quarantined or retired device was put there by a
	// person, and a cheerful report from a laptop that has just been wiped
	// must not undo that. The database trigger refuses it as well; this is
	// the half that avoids asking.
	newState := deviceState
	switch deviceState {
	case "quarantined", "retired":
		// Left alone, deliberately.
	default:
		if _, err := tx.Exec(ctx,
			`UPDATE devices SET state = $2, last_report_at = $3 WHERE id = $1`,
			deviceID, verdict.State, reportedAt); err != nil {
			return Compliance{}, err
		}
		newState = verdict.State
	}

	if err := data.AppendAudit(ctx, tx, "device.report",
		"device:"+deviceID.String()+" state:"+verdict.State); err != nil {
		return Compliance{}, err
	}
	if rep.Apps != nil {
		if err := data.ReplaceApps(ctx, tx, deviceID, toApps(rep.Apps), now); err != nil {
			return Compliance{}, err
		}
	}
	if rep.MACAddresses != nil {
		if err := data.ReplaceMACs(ctx, tx, deviceID, rep.MACAddresses, now, MaxReportAge); err != nil {
			return Compliance{}, err
		}
	}

	out := Compliance{
		DeviceID: deviceID, ReportedAt: reportedAt, EvaluatedAt: now,
		State: verdict.State, Findings: verdict.Findings,
		Policies: labels, Report: rep, DeviceState: newState,
	}

	// F9. Three conditions, in the order they are cheapest to refuse: a
	// policy asked, the device failed (not "did not say"), and the device
	// is in a state evaluation owns.
	ask, by := Quarantines(applied)
	if !ask || verdict.State != NotCompliant || newState != NotCompliant {
		return out, nil
	}
	enforcement, err := quarantine(ctx, tx, deviceID, by, quarantining(applied), verdict.Findings, now)
	if err != nil {
		return Compliance{}, err
	}
	out.Enforcement = enforcement
	if enforcement == EnforcedQuarantine {
		out.DeviceState = "quarantined"
	}
	return out, nil
}

// brakeTrips measures one population: the devices a scope covers, or the
// whole fleet when the scope is empty. It returns the counts so the halt
// can say them.
func brakeTrips(ctx context.Context, tx *data.Tx, scope Scope) (trips bool, failing, fleet int, err error) {
	err = tx.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'not_compliant'),
		       count(*) FILTER (WHERE state NOT IN ('retired', 'awaiting_first_boot'))
		  FROM devices
		 WHERE ($1 = '' OR os_family = $1)
		   AND ($2 = '' OR ownership = $2)`, scope.OSFamily, scope.Ownership).Scan(&failing, &fleet)
	if err != nil {
		return false, 0, 0, err
	}
	return failing > brakeLimit(fleet), failing, fleet, nil
}

// quarantine applies the brake and then acts, or records that it did not.
//
// The brake is measured twice: over the whole fleet, and over the devices
// each asking policy actually covers. A policy scoped to five iPads in a
// fleet of two hundred laptops can lose all five without moving the
// fleet-wide number, and five of five is exactly the mass failure the brake
// exists for. Either measure tripping halts.
func quarantine(ctx context.Context, tx *data.Tx, deviceID uuid.UUID, by string,
	asking []Policy, findings []Finding, now time.Time) (string, error) {

	trips, failing, fleet, err := brakeTrips(ctx, tx, Scope{})
	if err != nil {
		return "", err
	}
	population := "fleet"
	for _, p := range asking {
		if trips {
			break
		}
		if p.Scope == (Scope{}) {
			continue
		}
		t, f, n, err := brakeTrips(ctx, tx, p.Scope)
		if err != nil {
			return "", err
		}
		if t {
			trips, failing, fleet, population = true, f, n, p.Scope.Describe()
		}
	}
	if trips {
		// Halted. Said once per hour per tenant rather than once per
		// failing device, because the message is about the fleet.
		if err := data.AppendAudit(ctx, tx, "enforcement.halted",
			fmt.Sprintf("device:%s failing:%d of:%d population:%s", deviceID, failing, fleet, population)); err != nil {
			return "", err
		}
		if err := notify.Enqueue(ctx, tx, notify.Message{
			Topic:   notify.EnforcementHalted,
			Subject: fmt.Sprintf("Automatic quarantine halted: %d of %d devices (%s) are failing", failing, fleet, population),
			Body: fmt.Sprintf("%d of %d devices (%s) are not compliant, which is more than the %d%% "+
				"automatic quarantine will act on. Nothing has been quarantined automatically. "+
				"A failure this wide is far more likely a policy change or an agent fault than "+
				"a fleet gone bad at once; check the most recent policy version first. "+
				"Devices can still be quarantined one at a time from the console.",
				failing, fleet, population, BrakeShare),
			ObjectRef: "fleet", DedupeKey: "enforcement.halted:" + now.UTC().Format("2006-01-02T15"),
			Once: true,
		}); err != nil {
			return "", err
		}
		return EnforcementHalted, nil
	}

	reason := "failed " + by
	if len(findings) > 0 {
		reason = findings[0].Rule
		if len(findings) > 1 {
			reason += fmt.Sprintf(" (and %d more)", len(findings)-1)
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE devices
		   SET state = 'quarantined', quarantined_at = $2, quarantined_by = $3, quarantine_reason = $4
		 WHERE id = $1`, deviceID, now, "policy:"+by, reason); err != nil {
		return "", err
	}
	if err := data.AppendAudit(ctx, tx, "device.quarantined",
		"device:"+deviceID.String()+" by:policy:"+by); err != nil {
		return "", err
	}
	if err := notify.Enqueue(ctx, tx, notify.Message{
		Topic:   notify.DeviceQuarantined,
		Subject: "A device was quarantined automatically: " + reason,
		Body: "Device " + deviceID.String() + " failed " + by + " (" + reason + ") and that policy " +
			"asks for quarantine on failure. Nothing on the device has been erased. " +
			"An administrator can release it from the device's page once it is put right.",
		ObjectRef: "device:" + deviceID.String(),
	}); err != nil {
		return "", err
	}
	return EnforcedQuarantine, nil
}

// Of reads the stored verdict for one device, re-checking staleness at read
// time. A report that was fresh when it was evaluated is not fresh forever,
// and a console that showed a green row for a laptop last seen in March
// would be lying with a straight face.
func Of(ctx context.Context, tx *data.Tx, deviceID uuid.UUID, now time.Time) (Compliance, bool, error) {
	var (
		c            Compliance
		reportJSON   []byte
		findingsJSON []byte
		labelsJSON   []byte
	)
	err := tx.QueryRow(ctx, `
		SELECT device_id, reported_at, evaluated_at, state, report, findings, policies
		  FROM device_compliance WHERE device_id = $1`, deviceID).Scan(
		&c.DeviceID, &c.ReportedAt, &c.EvaluatedAt, &c.State,
		&reportJSON, &findingsJSON, &labelsJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return Compliance{}, false, nil
	}
	if err != nil {
		return Compliance{}, false, err
	}
	_ = json.Unmarshal(reportJSON, &c.Report)
	_ = json.Unmarshal(findingsJSON, &c.Findings)
	_ = json.Unmarshal(labelsJSON, &c.Policies)

	if now.Sub(c.ReportedAt) > MaxReportAge && c.State != Unknown {
		c.State = Unknown
		c.Findings = append(c.Findings, Finding{
			Rule:    maxAgeWords(),
			Saw:     "last reported " + c.ReportedAt.UTC().Format("2 Jan 2006"),
			From:    "this platform",
			Unknown: true,
		})
	}
	return c, true, nil
}

// Summary is the dashboard count, taken from the same column the device page
// reads so the two cannot disagree.
type Summary struct {
	Compliant    int
	NotCompliant int
	Unknown      int
	NeverSeen    int
}

// The four buckets are mutually exclusive and they are built in the same
// order a person would reason: a device nobody has heard from, then one we
// have heard from too long ago, then the verdict. Staleness outranks the
// stored verdict for the same reason Of re-checks it: a green row for a
// laptop last seen in March is a lie with a straight face.
//
// The age limit is passed in rather than written into the SQL, so it comes
// from MaxReportAge like everywhere else and cannot drift from it.
func Counts(ctx context.Context, tx *data.Tx) (Summary, error) {
	var s Summary
	err := tx.QueryRow(ctx, `
		WITH seen AS (
		  SELECT d.id,
		         c.device_id IS NULL                              AS never,
		         c.reported_at < now() - $1::interval             AS stale,
		         c.state                                          AS state
		    FROM devices d
		    LEFT JOIN device_compliance c ON c.device_id = d.id
		   WHERE d.state <> 'retired'
		)
		SELECT
		  count(*) FILTER (WHERE NOT never AND NOT stale AND state = 'compliant'),
		  count(*) FILTER (WHERE NOT never AND NOT stale AND state = 'not_compliant'),
		  count(*) FILTER (WHERE NOT never AND (stale OR state = 'state_unknown')),
		  count(*) FILTER (WHERE never)
		  FROM seen`, maxAgeInterval()).Scan(
		&s.Compliant, &s.NotCompliant, &s.Unknown, &s.NeverSeen)
	return s, err
}

func maxAgeInterval() string {
	return strconv.Itoa(int(MaxReportAge.Seconds())) + " seconds"
}

func maxAgeWords() string {
	return "the device must report at least every " +
		strconv.Itoa(int(MaxReportAge.Hours()/24)) + " days"
}

// Release is a person letting a quarantined device back in: the data
// layer's release, plus the announcement the network listens for. It lives
// here rather than in data because data cannot import notify.
func Release(ctx context.Context, tx *data.Tx, deviceID uuid.UUID, by string) error {
	if err := data.ReleaseQuarantine(ctx, tx, deviceID, by); err != nil {
		return err
	}
	return notify.Enqueue(ctx, tx, notify.Message{
		Topic:     notify.DeviceReleased,
		Subject:   "A device was released from quarantine by " + by,
		Body:      "Device " + deviceID.String() + " was released by " + by + ". It is unknown until its next report.",
		ObjectRef: "device:" + deviceID.String(),
		DedupeKey: "device.released:" + deviceID.String() + ":" + time.Now().UTC().Format(time.RFC3339),
	})
}

// Rollback makes an earlier version the live one, as a NEW version with
// that version's body and scope. History stays a straight line: a verdict
// reached against v2 still names v2, and the table shows "v4, restored
// from v2" rather than a v2 that was switched off and on again.
func Rollback(ctx context.Context, tx *data.Tx, name string, version int, by string) (Policy, error) {
	var body []byte
	var osFamily, ownership *string
	err := tx.QueryRow(ctx, `
		SELECT body, scope_os_family, scope_ownership FROM policies
		 WHERE name = $1 AND version = $2`, name, version).Scan(&body, &osFamily, &ownership)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNoSuchPolicy
	}
	if err != nil {
		return Policy{}, err
	}
	in := SaveInput{Name: name, Body: body, CreatedBy: by}
	if osFamily != nil {
		in.Scope.OSFamily = *osFamily
	}
	if ownership != nil {
		in.Scope.Ownership = *ownership
	}
	p, err := Save(ctx, tx, in)
	if err != nil {
		return Policy{}, err
	}
	return p, data.AppendAudit(ctx, tx, "policy.rollback",
		fmt.Sprintf("policy:%s restored_from:v%d by:%s", p.Label(), version, by))
}

// ---------------------------------------------------------------- templates

// Template is a starting point, not a policy: nothing exists until it is
// saved, under whatever name and scope the person chooses. The bodies are
// parsed by the same Parse as a typed one, and a test holds them to that.
type Template struct {
	Key, Title, Why string
	Scope           Scope
	Body            string
}

func Templates() []Template {
	return []Template{
		{Key: "baseline", Title: "Baseline for every device",
			Why:  "A passcode, encryption and a short screen lock. The least any managed device should meet.",
			Body: `{"passcode_required": true, "passcode_min_length": 8, "disk_encryption_required": true, "screen_lock_timeout_max": 300}`},
		{Key: "laptops", Title: "Company laptops",
			Why:   "Longer passcodes, the firewall on, and a current operating system, for machines that hold the most.",
			Scope: Scope{Ownership: "company"},
			Body:  `{"passcode_min_length": 12, "firewall_required": true, "os_version_min": "15.0", "screen_lock_timeout_max": 180}`},
		{Key: "phones", Title: "Phones and tablets, quarantined on failure",
			Why:   "No rooted or jailbroken devices, and a failing phone is kept off the network until it is put right.",
			Scope: Scope{},
			Body:  `{"jailbreak_blocked": true, "passcode_required": true, "on_failure": "quarantine"}`},
		{Key: "byod", Title: "Personal devices with a work profile",
			Why:   "The minimum for a device the company does not own: a passcode and nothing rooted. Nothing here reaches personal data.",
			Scope: Scope{Ownership: "personal"},
			Body:  `{"passcode_required": true, "jailbreak_blocked": true}`},
		{Key: "executives", Title: "Executive and finance Macs",
			Why:   "The machines that hold the most: a long passcode, a two-minute lock, encryption, the firewall, a current macOS, and quarantine the moment any of it slips.",
			Scope: Scope{OSFamily: "macos", Ownership: "company"},
			Body:  `{"passcode_required": true, "passcode_min_length": 14, "disk_encryption_required": true, "screen_lock_timeout_max": 120, "firewall_required": true, "os_version_min": "15.0", "on_failure": "quarantine"}`},
		{Key: "windows", Title: "Company Windows PCs",
			Why:   "BitLocker on, the firewall on, a ten-character passcode and a five-minute lock: the office PC standard.",
			Scope: Scope{OSFamily: "windows", Ownership: "company"},
			Body:  `{"passcode_required": true, "passcode_min_length": 10, "disk_encryption_required": true, "firewall_required": true, "screen_lock_timeout_max": 300}`},
		{Key: "android", Title: "Android work devices",
			Why:   "Encrypted, a six-digit code at least, nothing rooted, and quarantined on failure. Google enforces the code and the encryption; the root check is judged from its report.",
			Scope: Scope{OSFamily: "android"},
			Body:  `{"passcode_required": true, "passcode_min_length": 6, "disk_encryption_required": true, "jailbreak_blocked": true, "on_failure": "quarantine"}`},
		{Key: "field", Title: "Shared field devices",
			Why:   "Phones and tablets handed between people in the field: a code, a ten-minute lock so it is not in the way, nothing rooted. Pair it with lost mode and the lost-device contact.",
			Scope: Scope{Ownership: "company"},
			Body:  `{"passcode_required": true, "passcode_min_length": 6, "screen_lock_timeout_max": 600, "jailbreak_blocked": true}`},
	}
}

// TemplateCoverage says which operating systems and ownerships the
// templates address, so a tenant starting out finds a starting point for
// every kind of device the engine distinguishes.
func TemplateCoverage() (osFamilies, ownerships map[string]bool) {
	osFamilies, ownerships = map[string]bool{}, map[string]bool{}
	for _, t := range Templates() {
		if t.Scope.OSFamily != "" {
			osFamilies[t.Scope.OSFamily] = true
		}
		if t.Scope.Ownership != "" {
			ownerships[t.Scope.Ownership] = true
		}
	}
	return osFamilies, ownerships
}

func TemplateByKey(key string) (Template, bool) {
	for _, t := range Templates() {
		if t.Key == key {
			return t, true
		}
	}
	return Template{}, false
}

func toApps(in []App) []data.App {
	out := make([]data.App, 0, len(in))
	for _, a := range in {
		out = append(out, data.App{Identifier: a.Identifier, Name: a.Name, Version: a.Version})
	}
	return out
}
