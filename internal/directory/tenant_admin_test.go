package directory

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Getting a locked-out customer back in: one new, invited Super Admin and one
// link, added by the operator's role through the two inserts it already has,
// reading nothing.

func recoveryTenant(t *testing.T) (*Directory, string) {
	t.Helper()
	seed(t)
	cleanNew(t)
	adminExec(t, `DELETE FROM operator_events`)
	d := open(t)
	in := NewTenant{
		Name: "Kalesi Foods", Slug: "kalesi-new", Plan: "growth", Host: "console.kalesi.example",
		Protocol: "local", OwnerEmail: "kemi@kalesi.example", OwnerName: "Kemi Adeleke",
		OwnerInviteHash: []byte("0123456789abcdef0123456789abcdef"), OwnerCreatedBy: "tenantctl",
	}
	if _, err := d.CreateTenant(context.Background(), in); err != nil {
		t.Fatalf("create: %v", err)
	}
	return d, in.Slug
}

func hash32(s string) []byte { return []byte((s + "................................")[:32]) }

func TestALockedOutCustomerGetsOneNewAdminAndNothingElseChanges(t *testing.T) {
	d, slug := recoveryTenant(t)
	ctx := context.Background()

	host, err := d.AddTenantAdmin(ctx, slug, "  Tobi@Kalesi.EXAMPLE ", "Tobi", hash32("recovery-a"), "", "tenantctl")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if host != "console.kalesi.example" {
		t.Fatalf("the link host is %q", host)
	}

	// The new account: invited, a Super Admin, no password, address folded.
	var status, role, pw string
	queryOne(t, `SELECT status FROM local_accounts WHERE email = 'tobi@kalesi.example'`, &status)
	queryOne(t, `SELECT role FROM local_accounts WHERE email = 'tobi@kalesi.example'`, &role)
	queryOne(t, `SELECT password_hash FROM local_accounts WHERE email = 'tobi@kalesi.example'`, &pw)
	if status != "invited" || role != "super_admin" || pw != "" {
		t.Fatalf("the new account: %s %s %q", status, role, pw)
	}

	// The account that was there is exactly as it was.
	var oldStatus string
	var accounts int
	queryOne(t, `SELECT status FROM local_accounts WHERE email = 'kemi@kalesi.example'`, &oldStatus)
	queryOne(t, `SELECT count(*) FROM local_accounts`, &accounts)
	if oldStatus != "invited" || accounts != 2 {
		t.Fatalf("the old account is %q, %d accounts in all", oldStatus, accounts)
	}

	// One link for the new account: one use, about a day, not a week.
	var day, week int
	queryOne(t, `SELECT count(*) FROM local_tokens t JOIN local_accounts a ON a.id = t.account_id
	              WHERE a.email = 'tobi@kalesi.example' AND t.purpose = 'invite' AND t.used_at IS NULL
	                AND t.expires_at > now() + interval '23 hours' AND t.expires_at < now() + interval '25 hours'`, &day)
	queryOne(t, `SELECT count(*) FROM local_tokens t JOIN local_accounts a ON a.id = t.account_id
	              WHERE a.email = 'tobi@kalesi.example' AND t.expires_at > now() + interval '2 days'`, &week)
	if day != 1 || week != 0 {
		t.Fatalf("the link lasts: %d within a day, %d beyond two days", day, week)
	}

	// And the owners' record says who did what, to whom.
	var action, target, detail string
	queryOne(t, `SELECT action FROM operator_events ORDER BY id DESC LIMIT 1`, &action)
	queryOne(t, `SELECT target FROM operator_events ORDER BY id DESC LIMIT 1`, &target)
	queryOne(t, `SELECT detail FROM operator_events ORDER BY id DESC LIMIT 1`, &detail)
	if action != "tenant.admin_added" || target != slug || detail != "tobi@kalesi.example" {
		t.Fatalf("the record: %q %q %q", action, target, detail)
	}
}

func TestTheRecoveryRefusesWhatItShouldAndLeavesNothingBehind(t *testing.T) {
	d, slug := recoveryTenant(t)
	ctx := context.Background()
	good := hash32("recovery-b")

	rows := func() (acc, tok, ev int) {
		queryOne(t, `SELECT count(*) FROM local_accounts`, &acc)
		queryOne(t, `SELECT count(*) FROM local_tokens`, &tok)
		queryOne(t, `SELECT count(*) FROM operator_events`, &ev)
		return
	}
	a0, t0, e0 := rows()

	cases := []struct {
		name  string
		slug  string
		email string
		hash  []byte
		host  string
		want  error
	}{
		{"an address the organisation already has", slug, "KEMI@kalesi.example", good, "", ErrAdminExists},
		{"a short name nobody has", "no-such-org", "x@kalesi.example", good, "", ErrNoSuchTenant},
		{"not an address", slug, "not-an-address", good, "", ErrBadAdminAddress},
		{"two addresses", slug, "a@kalesi.example, b@kalesi.example", good, "", ErrBadAdminAddress},
		{"a hostname that is somebody else's", slug, "x@kalesi.example", good, "console.other.example", ErrHostNotTheirs},
	}
	for _, c := range cases {
		if _, err := d.AddTenantAdmin(ctx, c.slug, c.email, "", c.hash, c.host, "tenantctl"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := d.AddTenantAdmin(ctx, slug, "x@kalesi.example", "", []byte("short"), "", "tenantctl"); err == nil {
		t.Error("a link that is not a SHA-256 was accepted")
	}

	// A suspended organisation gets nobody new.
	adminExec(t, `UPDATE tenants SET status = 'suspended' WHERE slug = 'kalesi-new'`)
	if _, err := d.AddTenantAdmin(ctx, slug, "x@kalesi.example", "", good, "", "tenantctl"); !errors.Is(err, ErrTenantNotActive) {
		t.Errorf("a suspended organisation: %v", err)
	}
	adminExec(t, `UPDATE tenants SET status = 'active' WHERE slug = 'kalesi-new'`)

	if a, tk, e := rows(); a != a0 || tk != t0 || e != e0 {
		t.Fatalf("refusals left rows behind: accounts %d->%d, links %d->%d, record %d->%d", a0, a, t0, tk, e0, e)
	}
}

// An organisation that signs in through its own identity provider cannot use
// an account held here, so none is added.
func TestTheRecoveryIsOnlyForOrganisationsWithAccountsHeldHere(t *testing.T) {
	seed(t)
	cleanNew(t)
	adminExec(t, `DELETE FROM operator_events`)
	d := open(t)
	ctx := context.Background()
	if _, err := d.CreateTenant(ctx, kalesi()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddTenantAdmin(ctx, "kalesi-new", "x@kalesi.example", "", hash32("recovery-c"), "", "tenantctl"); !errors.Is(err, ErrTenantNotLocal) {
		t.Fatalf("an organisation with its own identity provider: %v", err)
	}
	var n int
	queryOne(t, `SELECT count(*) FROM local_accounts WHERE email = 'x@kalesi.example'`, &n)
	if n != 0 {
		t.Fatal("an account was added to an organisation that cannot use it")
	}
}

// The role that does this still cannot read an account back: adding a door
// is not reading the house.
func TestTheRecoveryRoleStillCannotReadAnAccount(t *testing.T) {
	d, slug := recoveryTenant(t)
	_ = d
	_ = slug
	dsn := os.Getenv("MDM_TEST_OPERATOR_DSN")
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM local_accounts`).Scan(&n); err == nil {
		t.Fatalf("the operator's role read local_accounts (%d rows)", n)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM local_tokens`).Scan(&n); err == nil {
		t.Fatalf("the operator's role read local_tokens (%d rows)", n)
	}
}
