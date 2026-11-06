package directory

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// T9: the operator gets counts and bytes, and still not rows.

func TestTheOperatorMetersATenantWithoutSeeingInsideIt(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	u, err := d.Usage(ctx, tenantA)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if u.ActiveDevices < 1 || u.Plan != "growth" || u.DeviceCap <= 0 || u.StorageBytes <= 0 {
		t.Fatalf("usage: %+v", u)
	}
	// Still no rows: the probe test alongside holds the line, and this is
	// the same question asked the direct way.
	if err := d.probe(ctx, `SELECT name FROM devices LIMIT 1`); err == nil {
		t.Fatal("metering opened the devices table to the operator")
	}
	// Snapshots: once a day, however often the sweep runs.
	n1, err := d.RecordUsage(ctx, time.Now())
	if err != nil || n1 < 1 {
		t.Fatalf("first snapshot: %d %v", n1, err)
	}
	n2, err := d.RecordUsage(ctx, time.Now())
	if err != nil || n2 != 0 {
		t.Fatalf("second snapshot the same day: %d %v", n2, err)
	}
	hs, err := d.UsageHistory(ctx, tenantA, 7)
	if err != nil || len(hs) != 1 || hs[0].ActiveDevices < 1 {
		t.Fatalf("history: %v %v", hs, err)
	}
}

func TestPlansAndQuotasAreTheOperatorsToSet(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	if err := d.SetPlan(ctx, "kalesi", "starter"); err != nil {
		t.Fatalf("set plan: %v", err)
	}
	got, err := d.ResolveID(ctx, tenantA)
	if err != nil || got.Plan != "starter" || got.DeviceCap != 50 || got.Feature(FeatureAndroid) {
		t.Fatalf("after set-plan: %+v %v", got, err)
	}
	if err := d.SetQuota(ctx, "kalesi", 75, 0, 0); err != nil {
		t.Fatalf("set quota: %v", err)
	}
	if err := d.SetFeature(ctx, "kalesi", FeatureAndroid, true); err != nil {
		t.Fatalf("set feature: %v", err)
	}
	got, _ = d.ResolveID(ctx, tenantA)
	if got.DeviceCap != 75 || got.AdminSeats != 3 || !got.Feature(FeatureAndroid) || got.Feature(FeatureNetworkFeed) {
		t.Fatalf("after quota and feature: %+v", got)
	}
	if err := d.SetPlan(ctx, "kalesi", "platinum"); err == nil {
		t.Fatal("an invented plan was accepted")
	}
	if err := d.SetFeature(ctx, "kalesi", "teleport", true); err == nil {
		t.Fatal("an unknown feature was accepted")
	}
	if err := d.SetPlan(ctx, "nobody", "growth"); err == nil {
		t.Fatal("an unknown tenant was accepted")
	}
}

// T9: the month as a billing system takes it. Device-days are the sum of
// the daily counts; the plan is the one the month ended on.
func TestTheMonthIsAggregatedForBilling(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, day := range []struct {
		on       string
		devices  int
		storage  int64
		plan     string
		commands int
	}{
		{"2026-10-01", 10, 1000, "starter", 5},
		{"2026-10-02", 12, 2000, "growth", 7},
		{"2026-10-31", 11, 1500, "growth", 9},
		{"2026-11-01", 50, 9000, "scale", 99}, // next month: not in October
	} {
		if _, err := conn.Exec(ctx, `
			INSERT INTO usage_snapshots (tenant_id, taken_on, active_devices, enrolled_30d, commands_30d, notifications_30d, storage_bytes, device_cap, plan)
			VALUES ($1, $2, $3, 1, $4, 0, $5, 100, $6)`, tenantA, day.on, day.devices, day.commands, day.storage, day.plan); err != nil {
			t.Fatal(err)
		}
	}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rows, err := d.Billing(ctx, from, from.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("billing: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Slug != "kalesi" || r.Days != 3 || r.DeviceDays != 33 || r.PeakDevices != 12 || r.PeakStorage != 2000 ||
		r.Plan != "growth" || r.Commands != 9 {
		t.Fatalf("october: %+v", r)
	}
	// A month with no snapshots is an empty export, not an error.
	empty, err := d.Billing(ctx, from.AddDate(0, -1, 0), from)
	if err != nil || len(empty) != 0 {
		t.Fatalf("september: %v %v", empty, err)
	}
}
