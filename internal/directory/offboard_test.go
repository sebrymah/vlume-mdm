package directory

import (
	"context"
	"errors"
	"testing"
)

// T10. Deletion is deliberate (suspend first), complete (every table,
// every key), verified (the residue is counted inside the same
// transaction), and logged on the operator's side.

func TestATenantIsOffboardedOnlyAfterSuspensionAndLeavesNothing(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()

	// Tenant A has devices, a CA, an identity and more from the seed.
	before, err := d.Residue(ctx, tenantA)
	if err != nil || before["devices"] < 1 {
		t.Fatalf("residue before: %v %v", before, err)
	}
	// Active: refused.
	if _, err := d.Offboard(ctx, "kalesi", "ops"); !errors.Is(err, ErrNotSuspended) {
		t.Fatalf("an active tenant was offboarded: %v", err)
	}
	if err := d.SetStatus(ctx, "kalesi", "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	out, err := d.Offboard(ctx, "kalesi", "ops")
	if err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if out.Total() < 1 || out.Residue != 0 || out.Deleted["devices"] < 1 {
		t.Fatalf("offboarding: %+v", out)
	}
	after, _ := d.Residue(ctx, tenantA)
	for tbl, n := range after {
		if n != 0 {
			t.Fatalf("%d rows left in %s", n, tbl)
		}
	}
	// The hostname is gone; the tenant row remains, offboarded, as the record.
	if _, err := d.ResolveHost(ctx, "mdm.kalesi.example"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("the offboarded tenant's host still resolves: %v", err)
	}
	got, err := d.ResolveID(ctx, tenantA)
	if err != nil || got.Status != "offboarded" {
		t.Fatalf("after: %+v %v", got, err)
	}
	var logged int
	queryOne(t, `SELECT count(*) FROM offboarding_log WHERE tenant_id = $1 AND residue = 0`, &logged, tenantA)
	if logged != 1 {
		t.Fatal("the offboarding was not logged on the operator's side")
	}
	// Twice is refused: it is offboarded, not suspended.
	if _, err := d.Offboard(ctx, "kalesi", "ops"); !errors.Is(err, ErrNotSuspended) {
		t.Fatalf("offboarding twice: %v", err)
	}
	// And the operator still cannot read inside the tenant that remains.
	if err := d.probe(ctx, `SELECT name FROM devices LIMIT 1`); err == nil {
		t.Fatal("offboarding opened the devices table to the operator")
	}
}
