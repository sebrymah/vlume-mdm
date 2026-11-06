package session

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var tenant = uuid.MustParse("11111111-1111-1111-1111-111111111111")

func signer(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("session-suite-signing-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func at(s *Signer, when time.Time) { s.Now = func() time.Time { return when } }

func start(t *testing.T, s *Signer) (string, Session) {
	t.Helper()
	tok, sess, err := s.Start(Session{TenantID: tenant, Subject: "o.martins", Role: "it_admin"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return tok, sess
}

func TestAShortKeyIsRefused(t *testing.T) {
	if _, err := NewSigner([]byte("too short")); err == nil {
		t.Fatal("a short signing key was accepted")
	}
}

func TestASessionRoundTrips(t *testing.T) {
	s := signer(t)
	tok, _ := start(t, s)
	got, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.TenantID != tenant || got.Subject != "o.martins" || got.Role != "it_admin" {
		t.Fatalf("contents changed in transit: %+v", got)
	}
}

// The whole point of signing. A changed tenant is the one that matters: it is
// the difference between reading your own devices and reading someone else's.
func TestATamperedSessionIsRefused(t *testing.T) {
	s := signer(t)
	tok, _ := start(t, s)

	body, _, _ := strings.Cut(tok, ".")
	flipped := "A" + body[1:]
	if body[0] == 'A' {
		flipped = "B" + body[1:]
	}

	cases := map[string]string{
		"body changed":      flipped + tok[len(body):],
		"signature changed": tok[:len(tok)-4] + "AAAA",
		"signature removed": strings.Split(tok, ".")[0],
		"empty":             "",
		"nonsense":          "not-a-token",
	}
	for name, bad := range cases {
		if _, err := s.Verify(bad); err == nil {
			t.Fatalf("%s: a bad token verified", name)
		}
	}
}

func TestASessionSignedWithAnotherKeyIsRefused(t *testing.T) {
	s := signer(t)
	tok, _ := start(t, s)

	other, err := NewSigner([]byte("a-completely-different-key-32-bytes!"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if _, err := other.Verify(tok); err == nil {
		t.Fatal("a session verified under a key that did not sign it")
	}
}

func TestASessionExpiresAbsolutely(t *testing.T) {
	s := signer(t)
	base := time.Now().UTC()
	at(s, base)
	tok, sess := start(t, s)

	// Nobody reaches the absolute end by sitting still: the idle timeout
	// gets them first. So use the console every ten minutes, which is what a
	// person at their desk does, and check the absolute end still arrives.
	for n := time.Duration(1); n*10*time.Minute < Lifetime; n++ {
		at(s, base.Add(n*10*time.Minute))
		var err error
		if _, err = s.Verify(tok); err != nil {
			t.Fatalf("a session in constant use died after %v: %v", n*10*time.Minute, err)
		}
		tok, sess, err = s.Renew(sess)
		if err != nil {
			t.Fatalf("renew: %v", err)
		}
	}

	at(s, base.Add(Lifetime+time.Minute))
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("a session in constant use outlived its absolute lifetime")
	}
}

func TestASessionExpiresWhenIdle(t *testing.T) {
	s := signer(t)
	base := time.Now().UTC()
	at(s, base)
	tok, _ := start(t, s)

	at(s, base.Add(IdleTimeout+time.Minute))
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("an idle session still worked")
	}
}

// Renewal is the sliding part. Using the console keeps you signed in, and
// that is the behaviour people expect; what it must NOT do is let a session
// slide past its absolute end.
func TestRenewalSlidesTheIdleDeadlineButNotTheEnd(t *testing.T) {
	s := signer(t)
	base := time.Now().UTC()
	at(s, base)
	_, sess := start(t, s)

	at(s, base.Add(20*time.Minute))
	tok2, sess2, err := s.Renew(sess)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !sess2.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("renewal moved the absolute expiry: %v -> %v", sess.ExpiresAt, sess2.ExpiresAt)
	}
	if !sess2.IdleUntil.After(sess.IdleUntil) {
		t.Fatal("renewal did not move the idle deadline")
	}

	// Past the original idle deadline, the renewed token still works.
	at(s, base.Add(IdleTimeout+time.Minute))
	if _, err := s.Verify(tok2); err != nil {
		t.Fatalf("a renewed session was treated as idle: %v", err)
	}

	// Right at the end of the absolute lifetime, renewal cannot save it.
	at(s, base.Add(Lifetime-time.Minute))
	tok3, _, err := s.Renew(sess2)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	at(s, base.Add(Lifetime+time.Second))
	if _, err := s.Verify(tok3); err == nil {
		t.Fatal("renewal pushed a session past its absolute lifetime")
	}
}

// StartedAt is what tenant-wide revocation compares against. If renewal moved
// it, an active browser would refresh its way straight through a revocation,
// which is precisely the case revocation exists for.
func TestRenewalNeverMovesStartedAt(t *testing.T) {
	s := signer(t)
	base := time.Now().UTC()
	at(s, base)
	_, sess := start(t, s)

	for i := 1; i <= 5; i++ {
		at(s, base.Add(time.Duration(i)*10*time.Minute))
		var err error
		_, sess, err = s.Renew(sess)
		if err != nil {
			t.Fatalf("renew: %v", err)
		}
		if !sess.StartedAt.Equal(base) {
			t.Fatalf("renewal %d moved StartedAt to %v", i, sess.StartedAt)
		}
	}
}

func TestShouldRenewOnlyAfterTheTokenIsStale(t *testing.T) {
	s := signer(t)
	base := time.Now().UTC()
	at(s, base)
	_, sess := start(t, s)

	if sess.ShouldRenew() {
		t.Fatal("a session asked to be renewed the moment it was issued")
	}
	sess.IssuedAt = time.Now().UTC().Add(-RenewAfter - time.Minute)
	if !sess.ShouldRenew() {
		t.Fatal("a stale session did not ask to be renewed")
	}
}

// ---------------------------------------------------------------- the flow

func TestAFlowRoundTrips(t *testing.T) {
	s := signer(t)
	tok, err := s.MintFlow(Flow{
		TenantID: tenant, State: "st", Nonce: "nc", Verifier: "vf", Return: "/devices",
	})
	if err != nil {
		t.Fatalf("mint flow: %v", err)
	}
	got, err := s.VerifyFlow(tok)
	if err != nil {
		t.Fatalf("verify flow: %v", err)
	}
	if got.State != "st" || got.Nonce != "nc" || got.Verifier != "vf" || got.Return != "/devices" {
		t.Fatalf("flow changed in transit: %+v", got)
	}
}

// Both tokens are signed with the same key, so without the version prefix a
// flow token would be a token this signer vouches for, sitting in a cookie
// the browser already holds. It must not pass as a session, and a session
// must not pass as a flow.
func TestAFlowTokenIsNotASessionToken(t *testing.T) {
	s := signer(t)
	flow, err := s.MintFlow(Flow{TenantID: tenant, State: "st", Nonce: "nc"})
	if err != nil {
		t.Fatalf("mint flow: %v", err)
	}
	if _, err := s.Verify(flow); err == nil {
		t.Fatal("a sign-in flow token verified as a session")
	}

	sessionTok, _ := start(t, s)
	if _, err := s.VerifyFlow(sessionTok); err == nil {
		t.Fatal("a session verified as a sign-in flow")
	}
}

func TestAFlowExpires(t *testing.T) {
	s := signer(t)
	base := time.Now().UTC()
	at(s, base)
	tok, err := s.MintFlow(Flow{TenantID: tenant, State: "st", Nonce: "nc"})
	if err != nil {
		t.Fatalf("mint flow: %v", err)
	}
	at(s, base.Add(FlowLifetime+time.Minute))
	if _, err := s.VerifyFlow(tok); err == nil {
		t.Fatal("a stale sign-in flow was still accepted")
	}
}

func TestAnIncompleteSessionIsRefusedAtMinting(t *testing.T) {
	s := signer(t)
	for name, sess := range map[string]Session{
		"no tenant":  {Subject: "a", Role: "it_admin"},
		"no subject": {TenantID: tenant, Role: "it_admin"},
		"no role":    {TenantID: tenant, Subject: "a"},
	} {
		if _, _, err := s.Start(sess); err == nil {
			t.Fatalf("%s: minted anyway", name)
		}
	}
}
