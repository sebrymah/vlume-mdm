package secrets

import "testing"

func TestRotatingTheMasterKeepsEveryTenantKeyOpening(t *testing.T) {
	first, _ := NewAESSealer([]byte("first-master-key-exactly-32-byte"))
	second, _ := NewAESSealer([]byte("second-master-key-exactly-32-byt"))
	k := NewKeyring(first)
	underFirst, err := first.Seal([]byte("tenant key"))
	if err != nil {
		t.Fatal(err)
	}
	k.RotateMaster(second)
	if got, err := k.OpenMaster(underFirst); err != nil || string(got) != "tenant key" {
		t.Fatalf("a tenant key under the old master no longer opens: %v", err)
	}
	underSecond, _ := second.Seal([]byte("newer tenant key"))
	if got, err := k.OpenMaster(underSecond); err != nil || string(got) != "newer tenant key" {
		t.Fatalf("under the new master: %v", err)
	}
	// Rotating to the same master changes nothing; a nil one is ignored.
	k.RotateMaster(second)
	k.RotateMaster(nil)
	m, prev := k.masters()
	if m != second || len(prev) != 1 || prev[0] != first {
		t.Fatalf("masters after rotation: %v %v", m, prev)
	}
}
