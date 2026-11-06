package directory

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Operator-assisted onboarding, through the operator's own role. The point
// of every test here is the boundary: the role can write the four rows a new
// tenant needs, and the probe test alongside proves it still cannot read a
// device.

func sealedStandIn() []byte { return []byte{0x9a, 0x01, 0xff, 0x42} }

func kalesi() NewTenant {
	return NewTenant{
		Name: "Kalesi Foods", Slug: "kalesi-new", Plan: "growth",
		Host:   "console.kalesi.example",
		Issuer: "https://login.microsoftonline.com/kalesi/v2.0", ClientID: "kalesi-console",
		ClientSecretSealed: sealedStandIn(), RoleClaim: "groups", AdminGroup: "MDM-Owners",
	}
}

func cleanNew(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	for _, s := range []string{
		`DELETE FROM local_tokens WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'kalesi-new%' OR slug = 'arbor-new')`,
		`DELETE FROM local_accounts WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'kalesi-new%' OR slug = 'arbor-new')`,
		`DELETE FROM tenant_role_map WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'kalesi-new%' OR slug = 'arbor-new')`,
		`DELETE FROM tenant_identity WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'kalesi-new%' OR slug = 'arbor-new')`,
		`DELETE FROM tenant_domains WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'kalesi-new%' OR slug = 'arbor-new')`,
		`DELETE FROM command_signing_keys`,
		`DELETE FROM tenants WHERE slug LIKE 'kalesi-new%' OR slug = 'arbor-new'`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("clean: %v", err)
		}
	}
}

func TestTheOperatorCreatesATenantThatCanLetItsFirstAdminIn(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	id, err := d.CreateTenant(ctx, kalesi())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Everything the gateway needs on the first request is there: the
	// hostname resolves to it, and it is active.
	got, err := d.ResolveHost(ctx, "console.kalesi.example")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != id || !got.Active() {
		t.Fatalf("resolved to %+v", got)
	}

	// Sign-in is configured, and the redirect was derived from the host
	// rather than typed.
	cfg, err := d.Identity(ctx, id)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if cfg.RedirectURL != "https://console.kalesi.example/signin/callback" {
		t.Fatalf("redirect is %q", cfg.RedirectURL)
	}

	// The one mapping, so somebody can get in. Read with the admin
	// connection, because the operator deliberately cannot read it back.
	var role string
	queryOne(t, `SELECT role FROM tenant_role_map WHERE tenant_id = $1 AND claim_value = 'MDM-Owners'`,
		&role, id)
	if role != "super_admin" {
		t.Fatalf("the admin group maps to %q", role)
	}
}

// All or nothing. A tenant with no hostname, or a hostname with no tenant,
// is a half-created row somebody will find later.
func TestACreationThatFailsLeavesNothingBehind(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	// The seeded tenant already owns mdm.kalesi.example, so the domain
	// insert fails after the tenant insert has succeeded.
	in := kalesi()
	in.Host = "mdm.kalesi.example"
	_, err := d.CreateTenant(ctx, in)
	if !errors.Is(err, ErrHostTaken) {
		t.Fatalf("got %v, want ErrHostTaken", err)
	}
	var n int
	queryOne(t, `SELECT count(*) FROM tenants WHERE slug = 'kalesi-new'`, &n)
	if n != 0 {
		t.Fatal("a tenant row survived a failed creation")
	}
}

func TestATenantCannotBeCreatedWithoutAWayIn(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	for name, mutate := range map[string]func(*NewTenant){
		"no admin group": func(n *NewTenant) { n.AdminGroup = "" },
		"no issuer":      func(n *NewTenant) { n.Issuer = "" },
		"no secret":      func(n *NewTenant) { n.ClientSecretSealed = nil },
		"http issuer":    func(n *NewTenant) { n.Issuer = "http://login.example" },
	} {
		in := kalesi()
		mutate(&in)
		if _, err := d.CreateTenant(ctx, in); err == nil {
			t.Fatalf("%s: a tenant nobody could sign in to was created", name)
		}
	}
}

func TestSlugsAndHostsAreTidiedAndChecked(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	in := kalesi()
	in.Slug = "  Kalesi-New  "
	in.Host = "Console.Kalesi.Example."
	if _, err := d.CreateTenant(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := d.ResolveHost(ctx, "console.kalesi.example"); err != nil {
		t.Fatalf("the tidied host does not resolve: %v", err)
	}

	for _, bad := range []string{"Kalesi Foods", "kalesi_new", "-kalesi", "kalesi/new", ""} {
		in := kalesi()
		in.Slug = bad
		in.Host = "other.kalesi.example"
		if _, err := d.CreateTenant(ctx, in); !errors.Is(err, ErrBadSlug) {
			t.Fatalf("slug %q: got %v", bad, err)
		}
	}
	for _, bad := range []string{"localhost", "https://a.example", "a.example/x", "a b.example"} {
		in := kalesi()
		in.Slug = "kalesi-new-2"
		in.Host = bad
		if _, err := d.CreateTenant(ctx, in); !errors.Is(err, ErrBadHost) {
			t.Fatalf("host %q: got %v", bad, err)
		}
	}
}

func TestSuspendingATenantIsTellingItsVisitorsSoRatherThanVanishing(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	if _, err := d.CreateTenant(ctx, kalesi()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.SetStatus(ctx, "kalesi-new", "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	// The hostname still resolves. The gateway turns an inactive tenant
	// into "not active", which is a billing conversation, rather than
	// "unknown host", which is a support ticket about a vanished product.
	got, err := d.ResolveHost(ctx, "console.kalesi.example")
	if err != nil {
		t.Fatalf("a suspended tenant's hostname stopped resolving: %v", err)
	}
	if got.Active() {
		t.Fatal("a suspended tenant reads as active")
	}
	if err := d.SetStatus(ctx, "kalesi-new", "resume"); err == nil {
		t.Fatal("an invented status was accepted")
	}
	if err := d.SetStatus(ctx, "nobody", "active"); !errors.Is(err, ErrNoSuchSlug) {
		t.Fatalf("got %v", err)
	}
}

func TestAddingAHostLetsBothAnswerDuringAChangeover(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	id, err := d.CreateTenant(ctx, kalesi())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.AddHost(ctx, "kalesi-new", "mdm.kalesifoods.example"); err != nil {
		t.Fatalf("add host: %v", err)
	}
	for _, h := range []string{"console.kalesi.example", "mdm.kalesifoods.example"} {
		got, err := d.ResolveHost(ctx, h)
		if err != nil || got.ID != id {
			t.Fatalf("%s does not resolve to the tenant: %v", h, err)
		}
	}
	if err := d.AddHost(ctx, "kalesi-new", "mdm.kalesi.example"); !errors.Is(err, ErrHostTaken) {
		t.Fatalf("another tenant's host was taken over: %v", err)
	}
}

func TestTheOperatorSeesTheShellAndNothingInside(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	if _, err := d.CreateTenant(ctx, kalesi()); err != nil {
		t.Fatalf("create: %v", err)
	}
	ts, err := d.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, s := range ts {
		if s.Slug == "kalesi-new" {
			found = true
			if !strings.Contains(strings.Join(s.Hosts, ","), "console.kalesi.example") {
				t.Fatalf("hosts: %v", s.Hosts)
			}
		}
	}
	if !found {
		t.Fatal("the new tenant is not listed")
	}
}

func queryOne(t *testing.T, sql string, into any, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if err := conn.QueryRow(ctx, sql, args...).Scan(into); err != nil {
		t.Fatalf("query: %v", err)
	}
}

// A tenant with no identity provider (0044): its first administrator is an
// account, not a group, and the operator who made it can neither read it
// back nor sign in as it.
func TestALocalTenantIsMadeWithItsFirstAdministratorAndNoRoleMap(t *testing.T) {
	seed(t)
	cleanNew(t)
	d := open(t)
	ctx := context.Background()

	in := NewTenant{
		Name: "Kalesi Foods", Slug: "kalesi-new", Plan: "growth", Host: "console.kalesi.example",
		Protocol: "local", OwnerEmail: " Kemi@Kalesi.example ", OwnerName: "Kemi Adeleke",
		OwnerInviteHash: []byte("0123456789abcdef0123456789abcdef"), OwnerCreatedBy: "tenantctl",
	}
	id, err := d.CreateTenant(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cfg, err := d.Identity(ctx, id)
	if err != nil || cfg.Protocol != "local" || cfg.Issuer != "" || cfg.LocalMFA != "admins" {
		t.Fatalf("identity: %+v %v", cfg, err)
	}
	var status, role, email, name, hash string
	queryOne(t, `SELECT status FROM local_accounts WHERE tenant_id = $1`, &status, id)
	queryOne(t, `SELECT role FROM local_accounts WHERE tenant_id = $1`, &role, id)
	queryOne(t, `SELECT email FROM local_accounts WHERE tenant_id = $1`, &email, id)
	queryOne(t, `SELECT name FROM local_accounts WHERE tenant_id = $1`, &name, id)
	queryOne(t, `SELECT password_hash FROM local_accounts WHERE tenant_id = $1`, &hash, id)
	if status != "invited" || role != "super_admin" || email != "kemi@kalesi.example" || name != "Kemi Adeleke" || hash != "" {
		t.Fatalf("the first administrator: %s %s %s %s %q", status, role, email, name, hash)
	}
	var tokens, maps int
	queryOne(t, `SELECT count(*) FROM local_tokens WHERE tenant_id = $1 AND purpose = 'invite' AND used_at IS NULL AND expires_at > now() + interval '6 days'`, &tokens, id)
	queryOne(t, `SELECT count(*) FROM tenant_role_map WHERE tenant_id = $1`, &maps, id)
	if tokens != 1 || maps != 0 {
		t.Fatalf("%d invitations, %d role mappings", tokens, maps)
	}
	if got := in.InviteLink("TOKEN"); got != "https://console.kalesi.example/signin/local/accept/TOKEN" {
		t.Fatalf("invite link: %s", got)
	}

	// Without an owner, or without a way for the owner to get in, nobody
	// could sign in at all, so there is no tenant.
	cleanNew(t)
	for _, bad := range []NewTenant{
		{Name: "K", Slug: "kalesi-new", Host: "console.kalesi.example", Protocol: "local",
			OwnerInviteHash: []byte("0123456789abcdef0123456789abcdef")},
		{Name: "K", Slug: "kalesi-new", Host: "console.kalesi.example", Protocol: "local", OwnerEmail: "kemi@kalesi.example"},
		{Name: "K", Slug: "kalesi-new", Host: "console.kalesi.example", Protocol: "local", OwnerEmail: "not-an-address",
			OwnerInviteHash: []byte("0123456789abcdef0123456789abcdef")},
	} {
		if _, err := d.CreateTenant(ctx, bad); err == nil {
			t.Fatalf("a local tenant was made with %+v", bad)
		}
	}
	var n int
	queryOne(t, `SELECT count(*) FROM tenants WHERE slug = 'kalesi-new'`, &n)
	if n != 0 {
		t.Fatal("a refused creation left a tenant behind")
	}
}
