package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// T8 and T9: what a plan allows, and what a tenant has used.
//
// A plan is a named set of defaults. The row holds the numbers the plan
// gave it when it was set, so a plan can change its defaults later without
// quietly changing every tenant's invoice; the operator moves a tenant on
// purpose. Feature flags are the same: the plan's defaults, with the row's
// explicit switches laid over them.

type Plan struct {
	Name          string
	APIRatePerMin int
	DeviceCap     int
	AdminSeats    int
	Features      map[string]bool
}

// The flags this platform understands. A flag nobody understands is off.
const (
	FeatureAndroid      = "android"
	FeatureNetworkFeed  = "network_feed"
	FeatureWeeklyReport = "weekly_report"
)

func Features() []string { return []string{FeatureAndroid, FeatureNetworkFeed, FeatureWeeklyReport} }

func Plans() []Plan {
	return []Plan{
		{Name: "starter", APIRatePerMin: 120, DeviceCap: 50, AdminSeats: 3,
			Features: map[string]bool{FeatureAndroid: false, FeatureNetworkFeed: false, FeatureWeeklyReport: true}},
		{Name: "growth", APIRatePerMin: 600, DeviceCap: 500, AdminSeats: 10,
			Features: map[string]bool{FeatureAndroid: true, FeatureNetworkFeed: true, FeatureWeeklyReport: true}},
		{Name: "scale", APIRatePerMin: 2400, DeviceCap: 2000, AdminSeats: 50,
			Features: map[string]bool{FeatureAndroid: true, FeatureNetworkFeed: true, FeatureWeeklyReport: true}},
	}
}

func PlanByName(name string) (Plan, bool) {
	for _, p := range Plans() {
		if p.Name == name {
			return p, true
		}
	}
	return Plan{}, false
}

// Feature answers whether a tenant may use something: the row's explicit
// switch if it has one, else the plan's default, else no.
func (t Tenant) Feature(name string) bool {
	if v, ok := t.Features[name]; ok {
		return v
	}
	if p, ok := PlanByName(t.Plan); ok {
		return p.Features[name]
	}
	return false
}

var ErrNoSuchPlan = errors.New("directory: no such plan")

// SetPlan moves a tenant to a plan and takes the plan's numbers. Explicit
// feature switches are cleared: a tenant moved to a plan gets that plan.
func (d *Directory) SetPlan(ctx context.Context, slug, plan string) error {
	p, ok := PlanByName(plan)
	if !ok {
		return fmt.Errorf("%w: %q (starter, growth or scale)", ErrNoSuchPlan, plan)
	}
	tag, err := d.pool.Exec(ctx, `
		UPDATE tenants SET plan = $2, api_rate_per_min = $3, device_cap = $4, admin_seats = $5,
		       features = '{}'::jsonb
		 WHERE slug = $1`, slug, p.Name, p.APIRatePerMin, p.DeviceCap, p.AdminSeats)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSlug
	}
	return nil
}

// SetQuota overrides one tenant's numbers without changing its plan. Zero
// leaves a number as it is.
func (d *Directory) SetQuota(ctx context.Context, slug string, devices, seats, ratePerMin int) error {
	if devices < 0 || seats < 0 || ratePerMin < 0 {
		return errors.New("directory: a quota is not negative")
	}
	tag, err := d.pool.Exec(ctx, `
		UPDATE tenants
		   SET device_cap = CASE WHEN $2 > 0 THEN $2 ELSE device_cap END,
		       admin_seats = CASE WHEN $3 > 0 THEN $3 ELSE admin_seats END,
		       api_rate_per_min = CASE WHEN $4 > 0 THEN $4 ELSE api_rate_per_min END
		 WHERE slug = $1`, slug, devices, seats, ratePerMin)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSlug
	}
	return nil
}

// SetFeature switches one flag for one tenant, over the plan's default.
func (d *Directory) SetFeature(ctx context.Context, slug, name string, on bool) error {
	known := false
	for _, f := range Features() {
		if f == name {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("directory: unknown feature %q (%s)", name, strings.Join(Features(), ", "))
	}
	tag, err := d.pool.Exec(ctx, `
		UPDATE tenants SET features = features || jsonb_build_object($2::text, $3::boolean)
		 WHERE slug = $1`, slug, name, on)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSuchSlug
	}
	return nil
}

// ---------------------------------------------------------------- metering

// Usage is what a tenant has used: counts and bytes, nothing with a name
// in it. It comes from app.tenant_usage, which the operator may execute and
// which is the only path from the operator's role to anything inside a
// tenant.
type Usage struct {
	TenantID         uuid.UUID
	ActiveDevices    int
	Enrolled30d      int
	Commands30d      int
	Notifications30d int
	StorageBytes     int64
	DeviceCap        int
	AdminSeats       int
	SeatsUsed        int
	Plan             string
}

func (d *Directory) Usage(ctx context.Context, id uuid.UUID) (Usage, error) {
	u := Usage{TenantID: id}
	if err := d.pool.QueryRow(ctx, `
		SELECT u.active_devices, u.enrolled_30d, u.commands_30d, u.notifications_30d, u.storage_bytes,
		       u.admin_seats_used, t.device_cap, t.admin_seats, t.plan
		  FROM app.tenant_usage($1) u, tenants t WHERE t.id = $1`, id).Scan(
		&u.ActiveDevices, &u.Enrolled30d, &u.Commands30d, &u.Notifications30d, &u.StorageBytes,
		&u.SeatsUsed, &u.DeviceCap, &u.AdminSeats, &u.Plan); err != nil {
		return Usage{}, err
	}
	return u, nil
}

// RecordUsage takes today's snapshot for every tenant, once per day: a
// second run on the same day changes nothing, so the sweep's interval is a
// matter of latency rather than of count.
func (d *Directory) RecordUsage(ctx context.Context, now time.Time) (int, error) {
	ids, err := d.ActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	taken := 0
	for _, id := range ids {
		u, err := d.Usage(ctx, id)
		if err != nil {
			return taken, err
		}
		tag, err := d.pool.Exec(ctx, `
			INSERT INTO usage_snapshots
			  (tenant_id, taken_on, active_devices, enrolled_30d, commands_30d, notifications_30d,
			   storage_bytes, device_cap, plan, seats_used, admin_seats)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (tenant_id, taken_on) DO NOTHING`,
			id, now.UTC().Format("2006-01-02"), u.ActiveDevices, u.Enrolled30d, u.Commands30d,
			u.Notifications30d, u.StorageBytes, u.DeviceCap, u.Plan, u.SeatsUsed, u.AdminSeats)
		if err != nil {
			return taken, err
		}
		taken += int(tag.RowsAffected())
	}
	return taken, nil
}

type Snapshot struct {
	TakenOn       time.Time
	ActiveDevices int
	Commands30d   int
	StorageBytes  int64
	DeviceCap     int
	Plan          string
}

func (d *Directory) UsageHistory(ctx context.Context, id uuid.UUID, days int) ([]Snapshot, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT taken_on, active_devices, commands_30d, storage_bytes, device_cap, plan
		  FROM usage_snapshots WHERE tenant_id = $1 AND taken_on > current_date - $2::int
		 ORDER BY taken_on`, id, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Snapshot{}
	for rows.Next() {
		var s Snapshot
		if err := rows.Scan(&s.TakenOn, &s.ActiveDevices, &s.Commands30d, &s.StorageBytes, &s.DeviceCap, &s.Plan); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// BillingRow is one tenant's month, from the daily snapshots: what a
// billing system is handed (T9). Device-days is the sum of the daily
// active-device counts, which is what a per-device-per-day price is
// applied to; the peak is what a per-seat or per-tier price is applied to.
type BillingRow struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Plan        string    `json:"plan"`
	Days        int       `json:"days"`
	DeviceDays  int       `json:"device_days"`
	PeakDevices int       `json:"peak_devices"`
	PeakStorage int64     `json:"peak_storage_bytes"`
	Commands    int       `json:"commands_30d_at_end"`
	Enrolled    int       `json:"enrolled_30d_at_end"`
}

// Billing aggregates every tenant's snapshots from the first day (inclusive)
// to the last (exclusive). The plan is the one on the last snapshot in the
// range, so a tenant that changed plan mid-month is billed on the plan it
// ended on; the days say how much of the month there was data for.
func (d *Directory) Billing(ctx context.Context, from, to time.Time) ([]BillingRow, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT t.id, t.slug, t.name,
		       (SELECT plan FROM usage_snapshots l WHERE l.tenant_id = t.id AND l.taken_on >= $1 AND l.taken_on < $2 ORDER BY taken_on DESC LIMIT 1),
		       count(*), coalesce(sum(s.active_devices), 0), coalesce(max(s.active_devices), 0),
		       coalesce(max(s.storage_bytes), 0),
		       (SELECT commands_30d FROM usage_snapshots l WHERE l.tenant_id = t.id AND l.taken_on >= $1 AND l.taken_on < $2 ORDER BY taken_on DESC LIMIT 1),
		       (SELECT enrolled_30d FROM usage_snapshots l WHERE l.tenant_id = t.id AND l.taken_on >= $1 AND l.taken_on < $2 ORDER BY taken_on DESC LIMIT 1)
		  FROM tenants t JOIN usage_snapshots s ON s.tenant_id = t.id
		 WHERE s.taken_on >= $1 AND s.taken_on < $2
		 GROUP BY t.id, t.slug, t.name
		 ORDER BY t.slug`, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BillingRow{}
	for rows.Next() {
		var r BillingRow
		if err := rows.Scan(&r.TenantID, &r.Slug, &r.Name, &r.Plan, &r.Days, &r.DeviceDays, &r.PeakDevices,
			&r.PeakStorage, &r.Commands, &r.Enrolled); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
