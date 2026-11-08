package data

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/tenantclaim"
)

// Requirement T13, extended from the database up through the data layer.
// The SQL suite proves PostgreSQL enforces isolation. These prove the Go
// code cannot be talked out of it.

var (
	tenantA = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	testKey = []byte("isolation-suite-signing-key-32-bytes!!")
)

func newSigner(t *testing.T) *tenantclaim.Signer {
	t.Helper()
	s, err := tenantclaim.NewSigner(testKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func tokenFor(t *testing.T, s *tenantclaim.Signer, tenant uuid.UUID, subject string) string {
	t.Helper()
	tok, err := s.Mint(tenantclaim.Claim{
		TenantID: tenant, Subject: subject, Role: "it_admin", RequestID: "test",
	}, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

// seed uses a superuser connection. Migrations and fixtures run privileged;
// application traffic never does. The fixture gives both tenants the same
// device names and serials on purpose.
func seed(t *testing.T, ctx context.Context) {
	t.Helper()
	adminDSN := os.Getenv("MDM_TEST_ADMIN_DSN")
	if adminDSN == "" {
		t.Skip("MDM_TEST_ADMIN_DSN not set")
	}
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	stmts := []string{
		`DELETE FROM notifications`,
		`DELETE FROM notification_targets`,
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
		`DELETE FROM tenants WHERE id IN ('11111111-1111-1111-1111-111111111111',
		                                   '22222222-2222-2222-2222-222222222222')`,
		`DELETE FROM partners`,
		`INSERT INTO tenants (id, name, slug, status) VALUES
		   ('11111111-1111-1111-1111-111111111111','Kalesi Foods','kalesi','active'),
		   ('22222222-2222-2222-2222-222222222222','Arbor Health','arbor','active')`,
		`INSERT INTO devices (tenant_id, name, serial, os_family) VALUES
		   ('11111111-1111-1111-1111-111111111111','HQ-MBP-001','C02XK4YTQ6NV','macos'),
		   ('11111111-1111-1111-1111-111111111111','HQ-WIN-004','SN-00000004','windows'),
		   ('22222222-2222-2222-2222-222222222222','HQ-MBP-001','C02XK4YTQ6NV','macos'),
		   ('22222222-2222-2222-2222-222222222222','HQ-WIN-004','SN-00000004','windows'),
		   ('22222222-2222-2222-2222-222222222222','HQ-IPH-009','SN-00000009','ios')`,
	}
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %.40s: %v", s, err)
		}
	}
}

func openStore(t *testing.T, ctx context.Context, maxConns int32) *Store {
	t.Helper()
	dsn := os.Getenv("MDM_TEST_DSN")
	if dsn == "" {
		t.Skip("MDM_TEST_DSN not set")
	}
	st, err := Open(ctx, dsn, newSigner(t), maxConns)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestTenantSeesOnlyItsOwnDevices(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 4)
	sg := newSigner(t)

	for _, tc := range []struct {
		name   string
		tenant uuid.UUID
		want   int
	}{
		{"tenant A", tenantA, 2},
		{"tenant B", tenantB, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := st.WithTenant(ctx, tokenFor(t, sg, tc.tenant, "o.martins"),
				func(ctx context.Context, tx *Tx) error {
					got, err := ListDevices(ctx, tx)
					if err != nil {
						return err
					}
					if len(got) != tc.want {
						t.Fatalf("saw %d devices, want %d", len(got), tc.want)
					}
					return nil
				})
			if err != nil {
				t.Fatalf("WithTenant: %v", err)
			}
		})
	}
}

// The forgotten WHERE clause. Both tenants hold this serial.
func TestSharedSerialReturnsOneRow(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 4)
	sg := newSigner(t)

	err := st.WithTenant(ctx, tokenFor(t, sg, tenantA, "o.martins"),
		func(ctx context.Context, tx *Tx) error {
			got, err := FindDeviceBySerial(ctx, tx, "C02XK4YTQ6NV")
			if err != nil {
				return err
			}
			if len(got) != 1 {
				t.Fatalf("a serial held by both tenants returned %d rows, want 1", len(got))
			}
			return nil
		})
	if err != nil {
		t.Fatalf("WithTenant: %v", err)
	}
}

func TestInsertLandsInTheCallersTenantOnly(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 4)
	sg := newSigner(t)

	if err := st.WithTenant(ctx, tokenFor(t, sg, tenantA, "o.martins"),
		func(ctx context.Context, tx *Tx) error {
			_, err := InsertDevice(ctx, tx, "NEW-A-001", "SN-NEW-A", "macos")
			return err
		}); err != nil {
		t.Fatalf("insert as A: %v", err)
	}

	if err := st.WithTenant(ctx, tokenFor(t, sg, tenantB, "j.okafor"),
		func(ctx context.Context, tx *Tx) error {
			got, err := FindDeviceBySerial(ctx, tx, "SN-NEW-A")
			if err != nil {
				return err
			}
			if len(got) != 0 {
				t.Fatalf("tenant B can see a device tenant A just created")
			}
			return nil
		}); err != nil {
		t.Fatalf("read as B: %v", err)
	}
}

// Even holding a transaction, naming another tenant explicitly is refused by
// the WITH CHECK clause. The Go API makes this unreachable; this proves the
// database would stop it anyway.
func TestExplicitForeignTenantInsertIsRejected(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 4)
	sg := newSigner(t)

	err := st.WithTenant(ctx, tokenFor(t, sg, tenantA, "o.martins"),
		func(ctx context.Context, tx *Tx) error {
			_, err := tx.Exec(ctx, `
				INSERT INTO devices (tenant_id, name, serial, os_family)
				VALUES ($1, 'planted', 'SN-PLANT', 'macos')`, tenantB)
			return err
		})
	if err == nil {
		t.Fatal("tenant A planted a row in tenant B")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
		t.Fatalf("refused, but not by row-level security: %v", err)
	}
}

func TestQueryWithoutAClaimIsRefused(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 4)

	ran := false
	err := st.WithTenant(ctx, "", func(ctx context.Context, tx *Tx) error {
		ran = true
		return nil
	})
	if err == nil {
		t.Fatal("an empty token was accepted")
	}
	if ran {
		t.Fatal("the callback ran without a tenant")
	}
}

func TestForgedAndExpiredTokensAreRefused(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 4)
	sg := newSigner(t)

	good := tokenFor(t, sg, tenantA, "o.martins")

	// Same body, signature from a different key.
	other, _ := tenantclaim.NewSigner([]byte("a-completely-different-key-32-bytes!!"))
	forged, err := other.Mint(tenantclaim.Claim{
		TenantID: tenantB, Subject: "attacker", Role: "super_admin",
	}, time.Minute)
	if err != nil {
		t.Fatalf("mint forged: %v", err)
	}

	tampered := good[:len(good)-4] + "AAAA"

	expired, err := sg.Mint(tenantclaim.Claim{
		TenantID: tenantA, Subject: "o.martins", Role: "it_admin",
	}, -time.Minute)
	if err != nil {
		t.Fatalf("mint expired: %v", err)
	}

	for name, tok := range map[string]string{
		"forged":    forged,
		"tampered":  tampered,
		"expired":   expired,
		"nonsense":  "not-a-token",
		"empty-sig": "eyJ0aWQiOiJ4In0.",
	} {
		t.Run(name, func(t *testing.T) {
			ran := false
			err := st.WithTenant(ctx, tok, func(ctx context.Context, tx *Tx) error {
				ran = true
				return nil
			})
			if err == nil {
				t.Fatalf("%s token was accepted", name)
			}
			if ran {
				t.Fatalf("%s token reached the callback", name)
			}
		})
	}
}

// Connections are pooled and reused. With a pool of exactly one, every
// transaction below runs on the same physical connection, so a tenant setting
// that outlived its transaction would show up here as the wrong tenant.
func TestPooledConnectionCarriesNoTenantBetweenTransactions(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 1)
	sg := newSigner(t)

	order := []struct {
		tenant uuid.UUID
		want   int
	}{
		{tenantA, 2}, {tenantB, 3}, {tenantA, 2}, {tenantB, 3}, {tenantA, 2},
	}

	for i, step := range order {
		err := st.WithTenant(ctx, tokenFor(t, sg, step.tenant, "o.martins"),
			func(ctx context.Context, tx *Tx) error {
				var observed string
				if err := tx.QueryRow(ctx,
					`SELECT coalesce(app.current_tenant()::text, '')`).Scan(&observed); err != nil {
					return err
				}
				if observed != step.tenant.String() {
					t.Fatalf("step %d: transaction saw tenant %q, want %q",
						i, observed, step.tenant)
				}
				got, err := ListDevices(ctx, tx)
				if err != nil {
					return err
				}
				if len(got) != step.want {
					t.Fatalf("step %d: saw %d devices, want %d", i, len(got), step.want)
				}
				return nil
			})
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
}

// The audit chain is written by the database trigger, so application code
// that forgets to chain cannot produce an unchained row.
func TestAuditIsChainedPerTenant(t *testing.T) {
	ctx := context.Background()
	seed(t, ctx)
	st := openStore(t, ctx, 4)
	sg := newSigner(t)

	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		if err := st.WithTenant(ctx, tokenFor(t, sg, tenant, "o.martins"),
			func(ctx context.Context, tx *Tx) error {
				for _, a := range []string{"device.locked", "policy.created", "device.wiped"} {
					if err := AppendAudit(ctx, tx, a, "HQ-MBP-001"); err != nil {
						return err
					}
				}
				var broken *int64
				if err := tx.QueryRow(ctx,
					`SELECT app.verify_audit_chain($1)`, tenant).Scan(&broken); err != nil {
					return err
				}
				if broken != nil {
					t.Fatalf("tenant %s chain breaks at row %d", tenant, *broken)
				}
				return nil
			}); err != nil {
			t.Fatalf("tenant %s: %v", tenant, err)
		}
	}
}
