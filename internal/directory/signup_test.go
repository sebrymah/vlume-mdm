package directory

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The operator's view of sign-ups. The tests here are about what the view
// says and what it withholds: the state of each request in one word, and
// never anything that could be turned back into a link.

func cleanSignups(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	for _, s := range []string{
		`DELETE FROM signups`,
		`DELETE FROM tenant_role_map WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'sv-%')`,
		`DELETE FROM tenant_identity WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'sv-%')`,
		`DELETE FROM tenant_domains WHERE tenant_id IN (SELECT id FROM tenants WHERE slug LIKE 'sv-%')`,
		`DELETE FROM command_signing_keys`,
		`DELETE FROM tenants WHERE slug LIKE 'sv-%'`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("clean: %v", err)
		}
	}
}

func hashOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestTheOperatorSeesEachSignupsStateInOneWord(t *testing.T) {
	seed(t)
	cleanSignups(t)
	d := open(t)
	ctx := context.Background()

	start := func(email, token string) {
		t.Helper()
		if _, err := d.StartSignup(ctx, email, "Arbor", "203.0.113.5", hashOf(token)); err != nil {
			t.Fatalf("start %s: %v", email, err)
		}
	}
	// waiting: sent, never opened.
	start("waiting@arbor.example", "t-waiting")
	// opened: the link was followed.
	start("opened@arbor.example", "t-opened")
	if _, err := d.OpenSignup(ctx, hashOf("t-opened")); err != nil {
		t.Fatalf("open: %v", err)
	}
	// replaced: asked again; the first link is dead, the second waits.
	start("again@arbor.example", "t-again-1")
	start("again@arbor.example", "t-again-2")
	// expired: moved back with the admin connection rather than waited for.
	start("late@cedar.example", "t-late")
	adminExec(t, `UPDATE signups SET expires_at = now() - interval '1 minute' WHERE email = 'late@cedar.example'`)
	// finished: a tenant came out of it.
	start("done@cedar.example", "t-done")
	if _, err := d.SetSignupSlug(ctx, hashOf("t-done"), "sv-done"); err != nil {
		t.Fatalf("slug: %v", err)
	}
	in := kalesi()
	in.Slug, in.Host = "sv-done", "sv-done.mdm.example"
	if _, err := d.FinishSignup(ctx, hashOf("t-done"), in); err != nil {
		t.Fatalf("finish: %v", err)
	}

	states := func(all bool) map[string]string {
		t.Helper()
		rs, err := d.ListSignups(ctx, all)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		out := map[string]string{}
		for _, r := range rs {
			// Two rows for again@: the view must tell them apart.
			key := r.Email
			if _, dup := out[key]; dup {
				key += "#2"
			}
			out[key] = r.State
		}
		return out
	}

	open := states(false)
	want := map[string]string{
		"waiting@arbor.example": "waiting",
		"opened@arbor.example":  "opened",
		"again@arbor.example":   "waiting",
	}
	if len(open) != len(want) {
		t.Fatalf("open sign-ups: %v", open)
	}
	for k, v := range want {
		if open[k] != v {
			t.Fatalf("%s is %q, want %q", k, open[k], v)
		}
	}

	all := states(true)
	for k, v := range map[string]string{
		"again@arbor.example#2": "replaced",
		"late@cedar.example":    "expired",
		"done@cedar.example":    "finished",
	} {
		if all[k] != v {
			t.Fatalf("%s is %q, want %q (all: %v)", k, all[k], v, all)
		}
	}
	// The finished one names the tenant it became.
	rs, _ := d.ListSignups(ctx, true)
	for _, r := range rs {
		if r.Email == "done@cedar.example" && r.TenantSlug != "sv-done" {
			t.Fatalf("the finished sign-up does not name its tenant: %+v", r)
		}
	}
}

func TestCancellingASignupKillsTheLinkAndKeepsTheRecord(t *testing.T) {
	seed(t)
	cleanSignups(t)
	d := open(t)
	ctx := context.Background()

	if _, err := d.StartSignup(ctx, "ada@arbor.example", "Arbor", "203.0.113.6", hashOf("t-cancel")); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := d.CancelSignup(ctx, "ada@arbor.example"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := d.OpenSignup(ctx, hashOf("t-cancel")); !errors.Is(err, ErrSignupExpired) {
		t.Fatalf("a cancelled link still opens: %v", err)
	}
	if err := d.CancelSignup(ctx, "ada@arbor.example"); !errors.Is(err, ErrNoSuchSignup) {
		t.Fatalf("cancelling twice: %v", err)
	}
	// Still on the record, so it still counts against the caps.
	rs, err := d.ListSignups(ctx, true)
	if err != nil || len(rs) != 1 || rs[0].State != "expired" {
		t.Fatalf("after cancel: %v %v", rs, err)
	}
	if open, _ := d.ListSignups(ctx, false); len(open) != 0 {
		t.Fatal("a cancelled sign-up is listed as open")
	}
}

func adminExec(t *testing.T, sql string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("exec: %v", err)
	}
}
