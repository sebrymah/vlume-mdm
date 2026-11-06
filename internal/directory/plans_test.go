package directory

import (
	"context"
	"testing"
	"time"
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
