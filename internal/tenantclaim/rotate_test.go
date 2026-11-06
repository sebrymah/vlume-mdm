package tenantclaim

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAClaimMintedBeforeRotationStillVerifiesUntilTheNextOne(t *testing.T) {
	s, err := NewSigner([]byte("first-claim-signing-key-32-bytes!!!!"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Mint(Claim{TenantID: uuid.New(), Subject: "x", Role: "it_admin", RequestID: "r"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate([]byte("second-claim-signing-key-32-bytes!!!")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok); err != nil {
		t.Fatalf("a claim minted before the rotation no longer verifies: %v", err)
	}
	tok2, _ := s.Mint(Claim{TenantID: uuid.New(), Subject: "x", Role: "it_admin", RequestID: "r"}, time.Minute)
	old, _ := NewSigner([]byte("first-claim-signing-key-32-bytes!!!!"))
	if _, err := old.Verify(tok2); err == nil {
		t.Fatal("a claim under the new key verified under the old key alone")
	}
	if err := s.Rotate([]byte("third-claim-signing-key-32-bytes!!!!")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("a claim two rotations old still verifies")
	}
}
