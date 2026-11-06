package session

import (
	"testing"

	"github.com/google/uuid"
)

// Rotation with a grace key (0044). The control --break-rotategrace
// forgets the previous key and the first assertion fails.
func TestASessionMintedBeforeRotationStillVerifiesUntilTheNextOne(t *testing.T) {
	s, err := NewSigner([]byte("first-session-signing-key-32-bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.Start(Session{TenantID: uuid.New(), Subject: "t.eze", Role: "employee"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate([]byte("second-session-signing-key-32-bytes!")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok); err != nil {
		t.Fatalf("a session minted before the rotation no longer verifies: %v", err)
	}
	// New tokens are under the new key: a signer that never rotated
	// refuses them, one holding only the new key accepts them.
	tok2, _, err := s.Start(Session{TenantID: uuid.New(), Subject: "t.eze", Role: "employee"})
	if err != nil {
		t.Fatal(err)
	}
	old, _ := NewSigner([]byte("first-session-signing-key-32-bytes!!"))
	if _, err := old.Verify(tok2); err == nil {
		t.Fatal("a token under the new key verified under the old key alone")
	}
	fresh, _ := NewSigner([]byte("second-session-signing-key-32-bytes!"))
	if _, err := fresh.Verify(tok2); err != nil {
		t.Fatalf("a token under the new key does not verify under it alone: %v", err)
	}
	// The grace lasts one rotation.
	if err := s.Rotate([]byte("third-session-signing-key-32-bytes!!")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("a token two rotations old still verifies")
	}
	if _, err := s.Verify(tok2); err != nil {
		t.Fatalf("a token one rotation old does not verify: %v", err)
	}
	// Rotating to the same key changes nothing.
	if err := s.Rotate([]byte("third-session-signing-key-32-bytes!!")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok2); err != nil {
		t.Fatalf("a same-key rotation dropped the grace: %v", err)
	}
	if err := s.Rotate([]byte("short")); err == nil {
		t.Fatal("a short key was accepted")
	}
}
