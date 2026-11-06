package data

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Compliance over time (0041): a device's verdict whenever it changed, and
// the fleet's counts once a day.

// VerdictChange is one row of a device's history.
type VerdictChange struct {
	ReportedAt  time.Time       `json:"reported_at"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
	State       string          `json:"state"`
	Findings    json.RawMessage `json:"findings"`
	Policies    json.RawMessage `json:"policies"`
}

// RecordVerdictIfChanged writes a history row when the verdict differs
// from the one stored before this evaluation: a different state, or a
// different set of findings by rule and by whether it could be read. A
// device saying the same thing every quarter of an hour adds nothing; the
// report that changes the answer adds one row. The caller passes the
// previous verdict's fingerprint, read before the upsert, and this one's.
// The control --break-historychange writes a row on every report.
func RecordVerdictIfChanged(ctx context.Context, tx *Tx, deviceID uuid.UUID,
	previous, current string, reportedAt, evaluatedAt time.Time, state string, findings, policies []byte) (bool, error) {
	if previous == current {
		return false, nil
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO device_compliance_history
		  (tenant_id, device_id, reported_at, evaluated_at, state, findings, policies)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, device_id, evaluated_at) DO NOTHING`,
		deviceID, reportedAt, evaluatedAt, state, findings, policies)
	return err == nil, err
}

// PreviousVerdictFingerprint reads the stored verdict's fingerprint, or
// "" for a device that has never been judged.
func PreviousVerdictFingerprint(ctx context.Context, tx *Tx, deviceID uuid.UUID) (string, error) {
	var state string
	var findings []byte
	err := tx.QueryRow(ctx, `SELECT state, findings FROM device_compliance WHERE device_id = $1`, deviceID).
		Scan(&state, &findings)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return VerdictFingerprint(state, findings), nil
}

// VerdictFingerprint is what "the same verdict" means: the state and the
// findings by kind and readability, in a fixed order. The sentences in a
// finding (what the device said) are not part of it: a passcode of 6
// characters and then of 7 are the same failure.
func VerdictFingerprint(state string, findings []byte) string {
	var fs []struct {
		Kind    string `json:"kind"`
		Unknown bool   `json:"unknown"`
		Rule    string `json:"rule"`
	}
	_ = json.Unmarshal(findings, &fs)
	keys := make([]string, 0, len(fs))
	for _, f := range fs {
		k := f.Kind
		if k == "" {
			k = f.Rule
		}
		if f.Unknown {
			k += "?"
		}
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := state
	for _, k := range keys {
		out += "|" + k
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// VerdictHistory is a device's changes, newest first.
func VerdictHistory(ctx context.Context, tx *Tx, deviceID uuid.UUID, limit int) ([]VerdictChange, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := tx.Query(ctx, `
		SELECT reported_at, evaluated_at, state, findings, policies
		  FROM device_compliance_history WHERE device_id = $1
		 ORDER BY evaluated_at DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VerdictChange{}
	for rows.Next() {
		var v VerdictChange
		if err := rows.Scan(&v.ReportedAt, &v.EvaluatedAt, &v.State, &v.Findings, &v.Policies); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ComplianceSnapshot is the fleet on one day, as the dashboard counted it.
type ComplianceSnapshot struct {
	TakenOn      time.Time `json:"taken_on"`
	Total        int       `json:"total"`
	Compliant    int       `json:"compliant"`
	NotCompliant int       `json:"not_compliant"`
	StateUnknown int       `json:"state_unknown"`
	Quarantined  int       `json:"quarantined"`
	NeverSeen    int       `json:"never_seen"`
}

// TakeComplianceSnapshot writes today's counts, replacing an earlier one
// from the same day so the day ends with its last reading. The counts are
// the dashboard's own, from the same query, so the trend and the board
// cannot disagree. The control --break-trendcount counts something else.
func TakeComplianceSnapshot(ctx context.Context, tx *Tx, now time.Time) (ComplianceSnapshot, error) {
	c, err := CountByState(ctx, tx)
	if err != nil {
		return ComplianceSnapshot{}, err
	}
	s := ComplianceSnapshot{
		TakenOn: now.UTC().Truncate(24 * time.Hour), Total: c.Total,
		Compliant: c.Compliant, NotCompliant: c.NotCompliant,
		StateUnknown: c.StateUnknown, Quarantined: c.Quarantined, NeverSeen: c.AwaitingFirst,
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO compliance_snapshots
		  (tenant_id, taken_on, total, compliant, not_compliant, state_unknown, quarantined, never_seen)
		VALUES (app.current_tenant(), $1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, taken_on) DO UPDATE SET
		  total = excluded.total, compliant = excluded.compliant, not_compliant = excluded.not_compliant,
		  state_unknown = excluded.state_unknown, quarantined = excluded.quarantined, never_seen = excluded.never_seen`,
		s.TakenOn, s.Total, s.Compliant, s.NotCompliant, s.StateUnknown, s.Quarantined, s.NeverSeen)
	return s, err
}

// ComplianceTrend is the last days of snapshots, oldest first.
func ComplianceTrend(ctx context.Context, tx *Tx, days int) ([]ComplianceSnapshot, error) {
	if days <= 0 || days > 366 {
		days = 30
	}
	rows, err := tx.Query(ctx, `
		SELECT taken_on, total, compliant, not_compliant, state_unknown, quarantined, never_seen
		  FROM compliance_snapshots WHERE taken_on > current_date - $1::int
		 ORDER BY taken_on`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ComplianceSnapshot{}
	for rows.Next() {
		var s ComplianceSnapshot
		if err := rows.Scan(&s.TakenOn, &s.Total, &s.Compliant, &s.NotCompliant, &s.StateUnknown, &s.Quarantined, &s.NeverSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
