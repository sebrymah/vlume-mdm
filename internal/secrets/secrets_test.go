package secrets

import (
	"bytes"
	"errors"
	"testing"
)

var key = []byte("sealing-key-exactly-32-bytes-ok!")

func sealer(t *testing.T) *AESSealer {
	t.Helper()
	s, err := NewAESSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func TestOnlyA32ByteKeyIsAccepted(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("x"), 31),
		bytes.Repeat([]byte("x"), 33)} {
		if _, err := NewAESSealer(bad); err == nil {
			t.Fatalf("a %d-byte key was accepted", len(bad))
		}
	}
}

func TestASecretRoundTrips(t *testing.T) {
	s := sealer(t)
	plain := []byte("the-client-secret-from-entra")
	sealed, err := s.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("the sealed form still contains the secret in the clear")
	}
	open, err := s.Open(sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(open, plain) {
		t.Fatalf("got %q, want %q", open, plain)
	}
}

// Sealing the same value twice has to produce different bytes. Otherwise the
// stored column tells anyone who can read it which tenants share a secret,
// which is a fact worth having if you are working out where to push.
func TestTheSameSecretSealsDifferentlyEachTime(t *testing.T) {
	s := sealer(t)
	a, err := s.Seal([]byte("same"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	b, err := s.Seal([]byte("same"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same value were identical")
	}
}

func TestAnotherKeyCannotOpenIt(t *testing.T) {
	s := sealer(t)
	sealed, err := s.Seal([]byte("the-client-secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	other, err := NewAESSealer([]byte("another-key-exactly-32-bytes-!!!"))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("the wrong key opened a sealed secret")
	}
}

// This is what sealing buys over encoding: a database row that has been
// edited does not open. Without the authentication tag, a changed byte would
// decrypt to a different secret and we would send it to the provider.
func TestATamperedValueDoesNotOpen(t *testing.T) {
	s := sealer(t)
	sealed, err := s.Seal([]byte("the-client-secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := range sealed {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := s.Open(bad); err == nil {
			t.Fatalf("a value with byte %d flipped still opened", i)
		}
	}
}

func TestSomethingTooShortToBeSealedIsRefused(t *testing.T) {
	s := sealer(t)
	if _, err := s.Open([]byte("abc")); err == nil {
		t.Fatal("a value shorter than a nonce was accepted")
	}
	if _, err := s.Open(nil); err == nil {
		t.Fatal("nothing at all was accepted")
	}
}

// Rotating the master: a tenant key sealed under the old master still
// opens while the new one is current, and the re-seal moves it across.
func TestAMasterBeingRotatedOutStillOpensWhatItSealed(t *testing.T) {
	old := sealer(t)
	cur, err := NewAESSealer([]byte("the-new-master-key-32-bytes-long"))
	if err != nil {
		t.Fatal(err)
	}
	tenantKey, _ := NewTenantKey()
	underOld, _ := old.Seal(tenantKey)

	k := NewKeyring(cur, old)
	if got, err := k.openMaster(underOld); err != nil || !bytes.Equal(got, tenantKey) {
		t.Fatalf("a key under the previous master did not open: %v", err)
	}
	if _, err := NewKeyring(cur).openMaster(underOld); err == nil {
		t.Fatal("a keyring with no previous master opened a key sealed under it")
	}

	// The step of a rotation: across, already, or halt.
	moved, already, err := ResealMaster(old, cur, underOld)
	if err != nil || already {
		t.Fatalf("reseal: %v already=%v", err, already)
	}
	if got, err := cur.Open(moved); err != nil || !bytes.Equal(got, tenantKey) {
		t.Fatalf("the moved key does not open under the current master: %v", err)
	}
	if _, err := old.Open(moved); err == nil {
		t.Fatal("the moved key still opens under the old master")
	}
	if _, already, err := ResealMaster(old, cur, moved); err != nil || !already {
		t.Fatalf("a key already under the current master was not reported as such: %v", err)
	}
	stranger, _ := NewAESSealer([]byte("a-master-nobody-here-knows-32byt"))
	underStranger, _ := stranger.Seal(tenantKey)
	if _, _, err := ResealMaster(old, cur, underStranger); !errors.Is(err, ErrUnopenable) {
		t.Fatalf("a key under neither master was not a halt: %v", err)
	}
}
