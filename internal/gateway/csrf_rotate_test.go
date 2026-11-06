package gateway

import (
	"testing"

	"github.com/google/uuid"
)

func TestAFormOpenedBeforeAKeyRotationStillSubmitsOnce(t *testing.T) {
	g := &Gateway{csrfKey: []byte("first-claim-signing-key-32-bytes!!!!")}
	tenant := uuid.New()
	tok := g.csrfFor(tenant, "o.martins", "it_admin")
	g.RotateCSRFKey([]byte("second-claim-signing-key-32-bytes!!!"))
	if !g.csrfMatches(tok, tenant, "o.martins", "it_admin") {
		t.Fatal("a form token from before the rotation was refused")
	}
	if g.csrfMatches(tok, tenant, "p.eneh", "it_admin") {
		t.Fatal("a form token matched another person")
	}
	g.RotateCSRFKey([]byte("third-claim-signing-key-32-bytes!!!!"))
	if g.csrfMatches(tok, tenant, "o.martins", "it_admin") {
		t.Fatal("a form token two rotations old was accepted")
	}
}
