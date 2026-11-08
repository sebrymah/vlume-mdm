package directory

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The owner's own accounts (0048): who can sign in to the console that can
// suspend every customer.

func cleanOperators(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("MDM_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("MDM_TEST_ADMIN_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, s := range []string{`DELETE FROM operator_events`, `DELETE FROM operator_tokens`, `DELETE FROM operator_accounts`} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func adminTry(t *testing.T, sql string, args ...any) error {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql, args...)
	return err
}

func TestOperatorAccountsAreCreatedOnceAndAsInvitedWithNothing(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	ctx := context.Background()
	o, err := d.CreateOperator(ctx, "  Tobi.Adeyemo@Example.COM ", "Tobi", "tenantctl")
	if err != nil {
		t.Fatal(err)
	}
	if o.Email != "tobi.adeyemo@example.com" || o.Status != "invited" || o.PasswordHash != "" || o.TOTPEnabled {
		t.Fatalf("%+v", o)
	}
	if _, err := d.CreateOperator(ctx, "TOBI.adeyemo@example.com", "x", "y"); !errors.Is(err, ErrOperatorExists) {
		t.Fatalf("a second account for the same person by capital letters: %v", err)
	}
	for _, bad := range []string{"", "nobody", "a@b", "a b@c.example", "a@@c.example"} {
		if _, err := d.CreateOperator(ctx, bad, "x", "y"); !errors.Is(err, ErrBadOperatorAddress) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// The database itself refuses an active owner without both factors, so no
// bug can leave an owner signed in on a password alone.
func TestAnActiveOperatorAlwaysHasBothFactors(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	o, _ := d.CreateOperator(context.Background(), "a@example.com", "", "t")
	if err := adminTry(t, `UPDATE operator_accounts SET status = 'active' WHERE id = $1`, o.ID); err == nil {
		t.Fatal("an account with no password and no second factor was made active")
	}
	if err := adminTry(t, `UPDATE operator_accounts SET status = 'active', password_hash = 'x' WHERE id = $1`, o.ID); err == nil {
		t.Fatal("an account with a password and no second factor was made active")
	}
	if err := adminTry(t, `UPDATE operator_accounts SET totp_enabled = true WHERE id = $1`, o.ID); err == nil {
		t.Fatal("a second factor was switched on with no secret")
	}
}

// The role that serves every organisation's console can read none of this.
func TestNoCustomerFacingRoleCanReadAnOwnerAccount(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	if _, err := d.CreateOperator(context.Background(), "a@example.com", "", "t"); err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("MDM_TEST_DSN") // the application role
	if dsn == "" {
		t.Skip("MDM_TEST_DSN not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, q := range []string{
		`SELECT * FROM operator_accounts`, `SELECT password_hash FROM operator_accounts`,
		`SELECT * FROM operator_tokens`, `SELECT * FROM operator_events`,
		`UPDATE operator_accounts SET status = 'active'`, `INSERT INTO operator_events (actor, action) VALUES ('x', 'y')`,
	} {
		_, err := conn.Exec(ctx, q)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Errorf("the application role was not refused by permissions: %s -> %v", q, err)
		}
	}
}

// The record of what owners do can be added to and read, and nothing more.
func TestTheRecordOfWhatOwnersDoCannotBeChanged(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	ctx := context.Background()
	if err := d.OperatorEvent(ctx, "a@example.com", "org.suspended", "kalesi", "non-payment"); err != nil {
		t.Fatal(err)
	}
	rows, err := d.OperatorEvents(ctx, 10)
	if err != nil || len(rows) != 1 || rows[0].Action != "org.suspended" || rows[0].Detail != "non-payment" {
		t.Fatalf("%v %v", rows, err)
	}
	for _, q := range []string{`UPDATE operator_events SET actor = 'someone else'`, `DELETE FROM operator_events`, `TRUNCATE operator_events`} {
		err := d.probe(ctx, q)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Errorf("the operator role was not refused: %s -> %v", q, err)
		}
	}
}

func TestALinkWorksOnceAndOnlyTheNewestWorks(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	o, _ := d.CreateOperator(ctx, "a@example.com", "", "t")
	h1, h2 := []byte("hash-one-hash-one-hash-one-hash!"), []byte("hash-two-hash-two-hash-two-hash!")
	if err := d.IssueOperatorToken(ctx, o.ID, "invite", h1, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	// A newer link replaces it.
	if err := d.IssueOperatorToken(ctx, o.ID, "invite", h2, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.PeekOperatorToken(ctx, h1, "invite", now); ok {
		t.Fatal("an older link still works after a newer one was made")
	}
	if _, ok, _ := d.PeekOperatorToken(ctx, h2, "reset", now); ok {
		t.Fatal("an invitation worked as a reset")
	}
	if _, ok, _ := d.PeekOperatorToken(ctx, h2, "invite", now); !ok {
		t.Fatal("the newest link did not work")
	}
	if _, err := d.SpendOperatorToken(ctx, h2, "invite", now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SpendOperatorToken(ctx, h2, "invite", now); !errors.Is(err, ErrOperatorLink) {
		t.Fatalf("a spent link was used again: %v", err)
	}
	// And it expires.
	h3 := []byte("hash-3-hash-3-hash-3-hash-3-hash")
	_ = d.IssueOperatorToken(ctx, o.ID, "reset", h3, now.Add(time.Minute), now)
	if _, err := d.SpendOperatorToken(ctx, h3, "reset", now.Add(2*time.Minute)); !errors.Is(err, ErrOperatorLink) {
		t.Fatalf("an expired link worked: %v", err)
	}
}

func TestFiveWrongAnswersLockAnOperatorAndSuccessAfterwardsClearsIt(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	o, _ := d.CreateOperator(ctx, "a@example.com", "", "t")
	for i := 1; i <= OperatorLockAfter; i++ {
		locked, err := d.RecordOperatorFailure(ctx, o.ID, now)
		if err != nil || locked != (i == OperatorLockAfter) {
			t.Fatalf("failure %d: locked %v err %v", i, locked, err)
		}
	}
	got, _ := d.OperatorByID(ctx, o.ID)
	if !got.Locked(now) {
		t.Fatal("not locked after five")
	}
	if got.Locked(now.Add(OperatorLockFor + time.Second)) {
		t.Fatal("still locked after the lock has lapsed")
	}
	// After the lock has lapsed the count starts again, so one more wrong
	// answer is the first, not the sixth.
	later := now.Add(OperatorLockFor + time.Minute)
	if locked, _ := d.RecordOperatorFailure(ctx, o.ID, later); locked {
		t.Fatal("the count did not start again after the lock lapsed")
	}
	if err := d.RecordOperatorSuccess(ctx, o.ID, later); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.OperatorByID(ctx, o.ID); got.FailedCount != 0 || got.LastSignInAt == nil {
		t.Fatalf("%+v", got)
	}
}

// The second factor: a time step is spent once, a recovery code once, and
// resetting it sends the account back to invited because an active account
// must have one.
func TestTheSecondFactorIsSpentOnceAndResetGoesBackToInvited(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	o, _ := d.CreateOperator(ctx, "a@example.com", "", "t")
	if err := d.SetOperatorPassword(ctx, o.ID, "$argon2id$stub", now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.SetPendingOperatorTOTP(ctx, o.ID, []byte("sealed-1")); !ok {
		t.Fatal("the first secret was not stored")
	}
	if ok, _ := d.SetPendingOperatorTOTP(ctx, o.ID, []byte("sealed-2")); ok {
		t.Fatal("a second secret replaced one a phone may have scanned")
	}
	if err := d.EnableOperatorTOTP(ctx, o.ID, 100, []string{"r1", "r2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.OperatorByID(ctx, o.ID); got.Status != "active" || !got.TOTPEnabled {
		t.Fatalf("not active after enrolling: %+v", got)
	}
	if ok, _ := d.AcceptOperatorTOTPStep(ctx, o.ID, 101); !ok {
		t.Fatal("a fresh step was refused")
	}
	if ok, _ := d.AcceptOperatorTOTPStep(ctx, o.ID, 101); ok {
		t.Fatal("a step was accepted twice")
	}
	if ok, _ := d.AcceptOperatorTOTPStep(ctx, o.ID, 100); ok {
		t.Fatal("an older step was accepted")
	}
	if ok, _ := d.UseOperatorRecovery(ctx, o.ID, "r1"); !ok {
		t.Fatal("a recovery code was refused")
	}
	if ok, _ := d.UseOperatorRecovery(ctx, o.ID, "r1"); ok {
		t.Fatal("a recovery code worked twice")
	}
	if err := d.ResetOperatorMFA(ctx, o.ID, "b@example.com"); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.OperatorByID(ctx, o.ID); got.Status != "invited" || got.TOTPEnabled || len(got.TOTPSealed) != 0 {
		t.Fatalf("not back to invited after a reset: %+v", got)
	}
}

func TestTheLastActiveOperatorCannotBeDisabled(t *testing.T) {
	cleanOperators(t)
	d := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(email string) Operator {
		o, _ := d.CreateOperator(ctx, email, "", "t")
		_ = d.SetOperatorPassword(ctx, o.ID, "$argon2id$stub", now)
		_, _ = d.SetPendingOperatorTOTP(ctx, o.ID, []byte("sealed"))
		if err := d.EnableOperatorTOTP(ctx, o.ID, 1, nil); err != nil {
			t.Fatal(err)
		}
		return o
	}
	a, b := mk("a@example.com"), mk("b@example.com")
	if err := d.SetOperatorStatus(ctx, a.ID, true, "b@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetOperatorStatus(ctx, b.ID, true, "b@example.com"); !errors.Is(err, ErrLastOperator) {
		t.Fatalf("the last active operator was disabled: %v", err)
	}
	if got, _ := d.OperatorByID(ctx, b.ID); got.Status != "active" {
		t.Fatalf("%s", got.Status)
	}
	// A disabled account is back to what it was when re-enabled.
	if err := d.SetOperatorStatus(ctx, a.ID, false, "b@example.com"); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.OperatorByID(ctx, a.ID); got.Status != "active" {
		t.Fatalf("re-enabled as %s", got.Status)
	}
}
