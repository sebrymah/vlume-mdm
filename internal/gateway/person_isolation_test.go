package gateway

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

// Person isolation, second control (0042): the database holds an
// employee's transaction to their own devices whatever the SQL asks for.
// The Go predicate is the first control and --break-mine removes it; this
// is the second, and --break-personsql removes it.

func claimFor(t *testing.T, f fixture, subject, email, role string) string {
	t.Helper()
	tok, err := f.g.signer.Mint(tenantclaim.Claim{
		TenantID: tenantA, Subject: subject, Email: email, Role: role, RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func countAs(t *testing.T, f fixture, claim, sql string) int {
	t.Helper()
	var n int
	err := f.g.store.WithTenant(context.Background(), claim, func(ctx context.Context, tx *data.Tx) error {
		return tx.QueryRow(ctx, sql).Scan(&n)
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func TestTheDatabaseHoldsAnEmployeeToTheirOwnDevices(t *testing.T) {
	f := newFixture(t)
	devs := f.devices[tenantA]
	assign(t, devs[0], "t.eze")
	assign(t, devs[1], "o.martins")
	for _, d := range devs[:2] {
		trustedCert(t, tenantA, d)
		if code, _ := reportAs(t, f, hostA, tenantA, d, map[string]any{"passcode_set": true}); code != 200 {
			t.Fatal("report")
		}
	}

	// Raw SQL, no predicate: an employee's transaction sees one device
	// and one verdict, theirs. The same SQL as an administrator sees all.
	employee := claimFor(t, f, "t.eze", "t.eze@kalesi.example", "employee")
	admin := claimFor(t, f, "o.martins", "o.martins@kalesi.example", "it_admin")
	if n := countAs(t, f, employee, `SELECT count(*) FROM devices`); n != 1 {
		t.Fatalf("an employee's transaction sees %d devices, want 1", n)
	}
	if n := countAs(t, f, employee, `SELECT count(*) FROM device_compliance`); n != 1 {
		t.Fatalf("an employee's transaction sees %d verdicts, want 1", n)
	}
	if n := countAs(t, f, admin, `SELECT count(*) FROM devices`); n != len(devs) {
		t.Fatalf("an administrator's transaction sees %d devices, want %d", n, len(devs))
	}
	// An employee with no person row sees nothing at all.
	nobody := claimFor(t, f, "nobody-yet", "", "employee")
	if n := countAs(t, f, nobody, `SELECT count(*) FROM devices`); n != 0 {
		t.Fatalf("an unknown employee's transaction sees %d devices", n)
	}
	// And an employee cannot write another's device, even by raw SQL.
	err := f.g.store.WithTenant(context.Background(), employee, func(ctx context.Context, tx *data.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE devices SET name = 'mine now' WHERE id = $1`, devs[1])
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Fatalf("an employee's transaction changed a colleague's device")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The first control on its own: an administrator asking for "my devices"
// is not held by the database (the role is not employee), so the Go
// predicate is all that narrows the answer. --break-mine shows here.
func TestAnAdministratorAskingForTheirOwnDevicesGetsOnlyTheirs(t *testing.T) {
	f := newFixture(t)
	devs := f.devices[tenantA]
	assign(t, devs[0], "t.eze")
	assign(t, devs[1], "o.martins")
	rec, body := do(t, f, req(t, "GET", hostA, "/api/me/devices", "a-itadmin"))
	ds, _ := body["devices"].([]any)
	if rec.Code != 200 || len(ds) != 1 || ds[0].(map[string]any)["id"] != devs[1].String() {
		t.Fatalf("an administrator's own page: %d %v", rec.Code, body)
	}

	// And the reused-address rule, for an administrator, is the Go
	// predicate's alone: a leaver's address on a new administrator's
	// session must find nothing. --break-emailreuse shows here, where the
	// database policy (employee only) cannot mask it.
	trustedCert(t, tenantA, devs[0])
	assign(t, devs[0], "kemi@kalesi.example")
	if rec, b := do(t, f, jsonReq(t, "POST", hostA, "/api/people/offboard", "a-itadmin", map[string]any{"email": "kemi@kalesi.example"})); rec.Code != http.StatusAccepted {
		t.Fatalf("offboard: %d %v", rec.Code, b)
	}
	tok, _, err := f.sessions.Start(session.Session{
		TenantID: tenantA, Subject: "new-kemi", Email: "kemi@kalesi.example", Name: "Kemi", Role: string(authz.ITAdmin),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, body = do(t, f, req(t, "GET", hostA, "/api/me/devices", tok))
	ds, _ = body["devices"].([]any)
	if rec.Code != 200 || len(ds) != 0 {
		t.Fatalf("a new administrator with a leaver's address inherited their devices: %d %v", rec.Code, body)
	}
}
