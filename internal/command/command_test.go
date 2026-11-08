package command

import (
	"context"
	"crypto/rsa"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/tenantclaim"
)

var (
	tenantA = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	testKey = []byte("isolation-suite-signing-key-32-bytes!!")
)

type harness struct {
	store   *data.Store
	signer  *tenantclaim.Signer
	pipe    *Pipeline
	devices map[uuid.UUID][]uuid.UUID
}

func (h harness) token(t *testing.T, tenant uuid.UUID, subject string, role authz.Role) string {
	t.Helper()
	tok, err := h.signer.Mint(tenantclaim.Claim{
		TenantID: tenant, Subject: subject, Role: string(role), RequestID: "test",
	}, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

// as runs fn inside one tenant-scoped transaction for the given person.
func (h harness) as(t *testing.T, tenant uuid.UUID, subject string, role authz.Role,
	fn func(ctx context.Context, tx *data.Tx) error) error {
	t.Helper()
	return h.store.WithTenant(context.Background(), h.token(t, tenant, subject, role), fn)
}

func newHarness(t *testing.T) harness {
	t.Helper()
	ctx := context.Background()
	adminDSN := os.Getenv("MDM_TEST_ADMIN_DSN")
	appDSN := os.Getenv("MDM_TEST_DSN")
	if adminDSN == "" || appDSN == "" {
		t.Skip("MDM_TEST_ADMIN_DSN or MDM_TEST_DSN not set")
	}

	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)

	for _, s := range []string{
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
		`DELETE FROM tenant_branding`,
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
		   ('22222222-2222-2222-2222-222222222222','HQ-MBP-001','C02XK4YTQ6NV','macos')`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %.40s: %v", s, err)
		}
	}

	devices := map[uuid.UUID][]uuid.UUID{}
	rows, err := conn.Query(ctx, `SELECT tenant_id, id FROM devices ORDER BY tenant_id`)
	if err != nil {
		t.Fatalf("ids: %v", err)
	}
	for rows.Next() {
		var tid, did uuid.UUID
		if err := rows.Scan(&tid, &did); err != nil {
			t.Fatalf("scan: %v", err)
		}
		devices[tid] = append(devices[tid], did)
	}
	rows.Close()

	signer, err := tenantclaim.NewSigner(testKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store, err := data.Open(ctx, appDSN, signer, 4)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(store.Close)

	// 1024-bit keys only because these tests generate many of them. Production
	// uses the vault's key, and DevKeyProvider is not deployable anyway.
	pipe := New(NewDevKeyProvider(1024), AppleNotConfigured(), DefaultLimiter())
	return harness{store: store, signer: signer, pipe: pipe, devices: devices}
}

// ---------------------------------------------------------------- the shape

// Exactly one command type is irreversible, and it is the only one needing
// two approvals. If a second irreversible type is ever added, this fails
// until someone decides what approving it should cost.
func TestOnlyOneTypeIsIrreversibleAndItIsTheOneNeedingTwoApprovals(t *testing.T) {
	var irreversible []Type
	for _, ty := range Types() {
		s, ok := SpecFor(ty)
		if !ok {
			t.Fatalf("%s has no spec", ty)
		}
		if !s.Reversible {
			irreversible = append(irreversible, ty)
		}
		if s.Reversible && s.Approvals != 1 {
			t.Errorf("%s is reversible but needs %d approvals", ty, s.Approvals)
		}
		if !s.Reversible && s.Approvals != 2 {
			t.Errorf("%s is irreversible but needs %d approvals", ty, s.Approvals)
		}
	}
	if len(irreversible) != 1 || irreversible[0] != WipeFull {
		t.Fatalf("irreversible types are %v, want exactly [wipe_full]", irreversible)
	}
}

// ---------------------------------------------------------------- approvals

func TestReversibleCommandIsApprovedByTheAsking(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	var c Command
	err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: Lock, Reason: "stolen"})
		return err
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if c.State != Approved {
		t.Fatalf("lock is %s, want approved", c.State)
	}
	if c.Signature == "" || c.Nonce == "" {
		t.Fatal("an approved command reached the end without a signature or a one-time code")
	}
}

func TestFullWipeIsHeldUntilASecondPersonWithADifferentRoleAgrees(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: WipeFull, Reason: "reported stolen"})
		return err
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if c.State != Held {
		t.Fatalf("full wipe is %s, want held", c.State)
	}
	if c.Signature != "" {
		t.Fatal("a held command was signed, so a second approval would mean nothing")
	}

	var after Command
	if err := h.as(t, tenantA, "d.adeyinka", authz.SecurityManager, func(ctx context.Context, tx *data.Tx) error {
		var err error
		after, err = h.pipe.Decide(ctx, tx, c.ID, DecisionInput{Approve: true, Note: "police report seen"})
		return err
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if after.State != Approved {
		t.Fatalf("after a second approval the wipe is %s, want approved", after.State)
	}
	if after.Signature == "" {
		t.Fatal("approved but unsigned")
	}
}

func TestTheRequesterCannotApproveTheirOwnRequest(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	var c Command
	if err := h.as(t, tenantA, "f.okonkwo", authz.SuperAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: WipeFull, Reason: "stolen"})
		return err
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	// Same person, and a Super Admin may approve in general.
	err := h.as(t, tenantA, "f.okonkwo", authz.SuperAdmin, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Decide(ctx, tx, c.ID, DecisionInput{Approve: true})
		return err
	})
	if err == nil {
		t.Fatal("one person asked for a wipe and approved it")
	}
	if !strings.Contains(err.Error(), "may not approve it") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestTwoApprovalsMustComeFromTwoDistinctRoles(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: WipeFull, Reason: "stolen"})
		return err
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	if err := h.as(t, tenantA, "d.adeyinka", authz.SecurityManager, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Decide(ctx, tx, c.ID, DecisionInput{Approve: true})
		return err
	}); err != nil {
		t.Fatalf("first approval: %v", err)
	}

	// A second Security Manager is one kind of judgement applied twice.
	err := h.as(t, tenantA, "another.sm", authz.SecurityManager, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Decide(ctx, tx, c.ID, DecisionInput{Approve: true})
		return err
	})
	if err == nil {
		t.Fatal("two approvals from the same role were accepted")
	}
}

func TestRolesAreEnforcedAtThePipeline(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	// A Security Manager may approve a wipe but not ask for one.
	err := h.as(t, tenantA, "d.adeyinka", authz.SecurityManager, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: WipeFull, Reason: "x"})
		return err
	})
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("a Security Manager requested a wipe: %v", err)
	}

	// Helpdesk may do neither.
	err = h.as(t, tenantA, "p.eneh", authz.Helpdesk, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: Lock, Reason: "x"})
		return err
	})
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("helpdesk locked a device: %v", err)
	}
}

// ---------------------------------------------------------------- signing

func TestSignatureVerifiesAndIsBoundToItsTenant(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: Lock, Reason: "stolen"})
		return err
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	var key *rsa.PrivateKey
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		key, err = h.pipe.keys.SigningKey(ctx, tx)
		return err
	}); err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := Verify(&key.PublicKey, tenantA, c); err != nil {
		t.Fatalf("a freshly signed command does not verify: %v", err)
	}

	// The tenant is inside the signed payload, so the same signature presented
	// against another tenant does not verify.
	if err := Verify(&key.PublicKey, tenantB, c); err == nil {
		t.Fatal("a signature verified against the wrong tenant")
	}

	// And changing what the command says breaks it.
	tampered := c
	tampered.Type = WipeFull
	if err := Verify(&key.PublicKey, tenantA, tampered); err == nil {
		t.Fatal("a lock signature verified as a full wipe")
	}
}

// ---------------------------------------------------------------- delivery

func TestPushNotConfiguredLeavesTheCommandQueuedRatherThanRefused(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: Lock, Reason: "stolen"})
		if err != nil {
			return err
		}
		c, err = h.pipe.Dispatch(ctx, tx, c.ID)
		return err
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	if c.State != Queued {
		t.Fatalf("with no push provider the command is %s, want queued", c.State)
	}
	// And the reason is legible rather than a bare failure.
	perr := AppleNotConfigured().Push(context.Background(), PushTarget{})
	if !errors.Is(perr, ErrPushNotConfigured) {
		t.Fatalf("wrong error type: %v", perr)
	}
	if !strings.Contains(perr.Error(), "vendor CSR signing certificate") {
		t.Fatalf("the stand-in does not say what is missing: %v", perr)
	}
}

// Pushed means a wake-up was sent. It does not mean anything ran.
func TestPushedIsNotDone(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]
	h.pipe.push = okPush{}

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: Lock, Reason: "stolen"})
		if err != nil {
			return err
		}
		c, err = h.pipe.Dispatch(ctx, tx, c.ID)
		return err
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if c.State != Pushed {
		t.Fatalf("state is %s, want pushed", c.State)
	}
	if c.AcknowledgedAt != nil {
		t.Fatal("a pushed command is being reported as acknowledged")
	}
}

type okPush struct{}

func (okPush) Name() string                           { return "test" }
func (okPush) Push(context.Context, PushTarget) error { return nil }

func TestAcknowledgementNeedsTheOneTimeCodeAndWorksOnce(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]
	h.pipe.push = okPush{}

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: Lock, Reason: "stolen"})
		if err != nil {
			return err
		}
		c, err = h.pipe.Dispatch(ctx, tx, c.ID)
		return err
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// A wrong code is refused.
	err := h.as(t, tenantA, "device", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Acknowledge(ctx, tx, c.ID, "0000")
		return err
	})
	if !errors.Is(err, ErrBadNonce) {
		t.Fatalf("a wrong code was accepted: %v", err)
	}

	// The right code works.
	var done Command
	if err := h.as(t, tenantA, "device", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		done, err = h.pipe.Acknowledge(ctx, tx, c.ID, c.Nonce)
		return err
	}); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if done.State != Acknowledged {
		t.Fatalf("state is %s, want acknowledged", done.State)
	}

	// R4: a replay of the same code is refused.
	err = h.as(t, tenantA, "device", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Acknowledge(ctx, tx, c.ID, c.Nonce)
		return err
	})
	if err == nil {
		t.Fatal("the same one-time code was accepted twice")
	}
}

func TestAnExpiredCodeIsRefusedAndTheCommandIsNeverRetried(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]
	h.pipe.push = okPush{}

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var err error
		c, err = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: Lock, Reason: "stolen"})
		if err != nil {
			return err
		}
		c, err = h.pipe.Dispatch(ctx, tx, c.ID)
		return err
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Stand half an hour and one minute later.
	h.pipe.SetClock(func() time.Time { return time.Now().Add(NonceTTL + time.Minute) })

	var out Command
	err := h.as(t, tenantA, "device", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var e error
		out, e = h.pipe.Acknowledge(ctx, tx, c.ID, c.Nonce)
		return e
	})
	if !errors.Is(err, ErrNonceExpired) {
		t.Fatalf("an expired code was accepted: %v", err)
	}
	if out.State != Expired {
		t.Fatalf("state is %s, want expired", out.State)
	}

	// And dispatching it again does not quietly resurrect it.
	err = h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		_, e := h.pipe.Dispatch(ctx, tx, c.ID)
		return e
	})
	if !errors.Is(err, ErrWrongState) {
		t.Fatalf("an expired command was dispatched again: %v", err)
	}
}

// ---------------------------------------------------------------- R1

func TestTheLimiterTripsAtTheEleventhFullWipeAndRecordsTheAttempt(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	for i := 1; i <= 10; i++ {
		if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
			_, err := h.pipe.Request(ctx, tx,
				RequestInput{DeviceID: dev, Type: WipeFull, Reason: "incident"})
			return err
		}); err != nil {
			t.Fatalf("wipe %d: %v", i, err)
		}
	}

	var refused Command
	err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var e error
		refused, e = h.pipe.Request(ctx, tx,
			RequestInput{DeviceID: dev, Type: WipeFull, Reason: "incident"})
		return e
	})
	if !errors.Is(err, ErrLimiterTripped) {
		t.Fatalf("the eleventh wipe was allowed: %v", err)
	}
	if refused.State != Refused {
		t.Fatalf("the refused attempt is %s, want refused", refused.State)
	}
	if !strings.Contains(refused.RefusedReason, "limiter") {
		t.Fatalf("the refusal does not say why: %q", refused.RefusedReason)
	}
}

// The limit is per admin. One person working an incident does not lock out
// their colleagues.
func TestTheLimiterIsPerAdmin(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	for i := 1; i <= 10; i++ {
		_ = h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
			_, err := h.pipe.Request(ctx, tx,
				RequestInput{DeviceID: dev, Type: WipeFull, Reason: "incident"})
			return err
		})
	}

	if err := h.as(t, tenantA, "i.danjuma", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		_, err := h.pipe.Request(ctx, tx,
			RequestInput{DeviceID: dev, Type: WipeFull, Reason: "different incident"})
		return err
	}); err != nil {
		t.Fatalf("a second admin was blocked by the first admin's limit: %v", err)
	}
}

// ---------------------------------------------------------------- isolation

func TestACommandCannotNameAnotherTenantsDevice(t *testing.T) {
	h := newHarness(t)
	bDevice := h.devices[tenantB][0]

	err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		_, e := h.pipe.Request(ctx, tx,
			RequestInput{DeviceID: bDevice, Type: Lock, Reason: "stolen"})
		return e
	})
	if !errors.Is(err, ErrNoDevice) {
		t.Fatalf("tenant A issued a command against tenant B's device: %v", err)
	}
}

func TestOneTenantCannotApproveAnothersCommand(t *testing.T) {
	h := newHarness(t)
	dev := h.devices[tenantA][0]

	var c Command
	if err := h.as(t, tenantA, "o.martins", authz.ITAdmin, func(ctx context.Context, tx *data.Tx) error {
		var e error
		c, e = h.pipe.Request(ctx, tx, RequestInput{DeviceID: dev, Type: WipeFull, Reason: "stolen"})
		return e
	}); err != nil {
		t.Fatalf("request: %v", err)
	}

	err := h.as(t, tenantB, "j.okafor", authz.SuperAdmin, func(ctx context.Context, tx *data.Tx) error {
		_, e := h.pipe.Decide(ctx, tx, c.ID, DecisionInput{Approve: true})
		return e
	})
	if err == nil {
		t.Fatal("tenant B approved tenant A's wipe")
	}
}
