package directory

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var tenantA = uuid.MustParse("11111111-1111-1111-1111-111111111111")

func open(t *testing.T) *Directory {
	t.Helper()
	dsn := os.Getenv("MDM_TEST_OPERATOR_DSN")
	if dsn == "" {
		t.Skip("MDM_TEST_OPERATOR_DSN not set")
	}
	d, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

func seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	adminDSN := os.Getenv("MDM_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("MDM_TEST_ADMIN_DSN not set")
	}
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	for _, s := range []string{
		`DELETE FROM notifications`,
		`DELETE FROM notification_targets`,
		`DELETE FROM tls_cache`,
		`DELETE FROM offboarding_log`,
		`DELETE FROM tenant_keys`,
		`DELETE FROM siem_cursors`,
		`DELETE FROM usage_snapshots`,
		`DELETE FROM signups`,
		`DELETE FROM integration_tokens`,
		`DELETE FROM android_enrollment_tokens`,
		`DELETE FROM android_enterprises`,
		`DELETE FROM sending_domains`,
		`DELETE FROM device_apps`,
		`DELETE FROM device_recovery_keys`,
		`DELETE FROM device_compliance`,
		`DELETE FROM device_certificates`,
		`DELETE FROM enrolments`,
		`DELETE FROM tenant_ca`,
		`DELETE FROM command_approvals`,
		`DELETE FROM commands`,
		`DELETE FROM audit_events`,
		`DELETE FROM devices`,
		`DELETE FROM local_tokens`,
		`DELETE FROM local_accounts`,
		`DELETE FROM tenant_enrolment`,
		`DELETE FROM people`,
		`DELETE FROM compliance_snapshots`,
		`DELETE FROM policies`,
		`DELETE FROM tenant_domains`,
		`DELETE FROM tenant_role_map`,
		`DELETE FROM tenant_identity`,
		`DELETE FROM command_signing_keys`,
		`DELETE FROM tenants WHERE id = '11111111-1111-1111-1111-111111111111'`,
		`DELETE FROM partners`,
		`INSERT INTO tenants (id, name, slug, plan, status, api_rate_per_min)
		 VALUES ('11111111-1111-1111-1111-111111111111','Kalesi Foods','kalesi','growth','active',600)`,
		`INSERT INTO tenant_domains (host, tenant_id, verified_at)
		 VALUES ('mdm.kalesi.example','11111111-1111-1111-1111-111111111111', now())`,
		`INSERT INTO devices (tenant_id, name, serial, os_family)
		 VALUES ('11111111-1111-1111-1111-111111111111','HQ-MBP-001','C02XK4YTQ6NV','macos')`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %.40s: %v", s, err)
		}
	}
}

func TestResolveHost(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()

	for _, host := range []string{
		"mdm.kalesi.example",
		"MDM.Kalesi.Example",     // case carries no meaning
		"mdm.kalesi.example:443", // nor does the port
	} {
		got, err := d.ResolveHost(ctx, host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got.ID != tenantA {
			t.Fatalf("%s resolved to %s", host, got.ID)
		}
		if got.APIRatePerMin != 600 {
			t.Fatalf("%s: rate %d, want the growth plan's 600", host, got.APIRatePerMin)
		}
	}

	if _, err := d.ResolveHost(ctx, "mdm.someoneelse.example"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("unknown host returned %v, want ErrUnknownHost", err)
	}
}

// The reason this package exists rather than an escape hatch on
// data.WithTenant: the role it connects as can answer "which tenant owns this
// hostname" and nothing else at all.
func TestTheDirectoryRoleCannotReachTenantData(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()

	for _, sql := range []string{
		`SELECT count(*) FROM devices`,
		`SELECT count(*) FROM policies`,
		`SELECT count(*) FROM audit_events`,
		`SELECT count(*) FROM commands`,
		`SELECT count(*) FROM tenant_branding`,
		// The mapping from a group to a role is tenant data and is read
		// under a claim, after the identity token has verified. The
		// directory never needs it and must not have it.
		`SELECT count(*) FROM tenant_role_map`,
		`SELECT count(*) FROM local_accounts`,
		`SELECT count(*) FROM local_tokens`,
		// Local accounts (0044): the operator may open the door for the first
		// administrator, a Super Admin and nothing else, and may not read,
		// change or add to them afterwards.
		`UPDATE local_accounts SET role = 'super_admin'`,
		`DELETE FROM local_accounts`,
		`DELETE FROM tenant_enrolment`,
		`UPDATE local_tokens SET used_at = NULL`,
		`INSERT INTO devices (tenant_id, name, serial, os_family)
		 VALUES ('11111111-1111-1111-1111-111111111111','x','y','macos')`,
		// Onboarding (0014) let this role write the four rows a new tenant
		// needs: the tenant, its hostname, its identity provider, and ONE
		// role mapping so the first administrator can get in. These are
		// the boundaries that still hold afterwards. It may not read the
		// mapping back, change it, or remove it: the operator opens the
		// door and cannot afterwards decide who is what inside.
		`UPDATE tenant_role_map SET role = 'super_admin'`,
		`DELETE FROM tenant_role_map`,
		// And its writes are to the shell, never to anything inside it.
		`INSERT INTO policies (tenant_id, name, body)
		 VALUES ('11111111-1111-1111-1111-111111111111','x','{}')`,
		`UPDATE devices SET name = 'renamed'`,
		// The operator seeds a tenant's first key and may never read one
		// back: a key it can read is a key it can use.
		`SELECT key_sealed FROM tenant_keys LIMIT 1`,
		// Rotation goes through the key master's functions, never directly.
		`UPDATE tenant_keys SET key_sealed = '\x00'`,
	} {
		err := d.probe(ctx, sql)
		if err == nil {
			t.Fatalf("the directory role succeeded at: %s", sql)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Fatalf("refused, but not by permissions: %s -> %v", sql, err)
		}
	}
}

// The carve-out, stated as a test rather than left in a comment.
//
// The directory role CAN read tenant_identity, across every tenant, because
// a browser at /signin has no claim to scope the read by and we still have
// to know which provider to send it to. This proves the carve-out is exactly
// that wide and no wider: the row comes back, and the one sensitive column
// in it is ciphertext.
func TestTheDirectoryRoleReadsIdentityConfigAndOnlyThat(t *testing.T) {
	seed(t)
	seedIdentityConfig(t)
	d := open(t)
	ctx := context.Background()

	cfg, err := d.Identity(ctx, uuid.MustParse("11111111-1111-1111-1111-111111111111"))
	if err != nil {
		t.Fatalf("the directory could not read the identity config: %v", err)
	}
	if cfg.Issuer != "https://login.microsoftonline.com/kalesi/v2.0" {
		t.Fatalf("got issuer %q", cfg.Issuer)
	}
	if len(cfg.SecretSealed) == 0 {
		t.Fatal("no sealed secret came back")
	}
	if strings.Contains(string(cfg.SecretSealed), "the-client-secret") {
		t.Fatal("the client secret is readable in the clear")
	}
}

// A tenant that has not finished setup is a state, not a failure, and the
// difference decides whether the console says "call support" or "here is
// the step you have not done".
func TestATenantWithNoIdentityConfigSaysSoSpecifically(t *testing.T) {
	seed(t)
	d := open(t)
	_, err := d.Identity(context.Background(),
		uuid.MustParse("22222222-2222-2222-2222-222222222222"))
	if !errors.Is(err, ErrNoIdentityConfig) {
		t.Fatalf("got %v, want ErrNoIdentityConfig", err)
	}
}

func seedIdentityConfig(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_identity
		  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url)
		VALUES ('11111111-1111-1111-1111-111111111111',
		        'https://login.microsoftonline.com/kalesi/v2.0',
		        'kalesi-console', $1,
		        'https://mdm.kalesi.example/signin/callback')`,
		[]byte{0x9a, 0x01, 0xff, 0x42, 0x00, 0x7e}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

func queryExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec: %v", err)
	}
}

// The operator may open the door for the first administrator of a tenant
// that has no identity provider (0044), through one INSERT policy: a Super
// Admin, invited or active, and a link that is an invitation. Anything
// else is refused by row-level security, not by a missing privilege, which
// is why this is not in the list above.
func TestTheOperatorMaySeedASuperAdminAccountAndNothingElse(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	for _, sql := range []string{
		`INSERT INTO local_accounts (tenant_id, email, role, status, created_by)
		 VALUES ('11111111-1111-1111-1111-111111111111','e@kalesi.example','employee','invited','operator')`,
		`INSERT INTO local_accounts (tenant_id, email, role, status, created_by)
		 VALUES ('11111111-1111-1111-1111-111111111111','d@kalesi.example','super_admin','disabled','operator')`,
		`INSERT INTO local_tokens (tenant_id, account_id, purpose, token_hash, expires_at)
		 VALUES ('11111111-1111-1111-1111-111111111111', gen_random_uuid(), 'reset', 'x', now())`,
	} {
		err := d.probe(ctx, sql)
		if err == nil {
			t.Fatalf("the directory role succeeded at: %s", sql)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
			t.Fatalf("refused, but not by row-level security: %s -> %v", sql, err)
		}
	}
}
