package directory

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"platform/internal/secrets"
)

// T3: rotating the master key. Every tenant key moves, or none does.

func masters(t *testing.T) (old, cur *secrets.AESSealer) {
	t.Helper()
	old, err := secrets.NewAESSealer([]byte("the-old-master-key-32-bytes-long"))
	if err != nil {
		t.Fatal(err)
	}
	cur, err = secrets.NewAESSealer([]byte("the-new-master-key-32-bytes-long"))
	if err != nil {
		t.Fatal(err)
	}
	return old, cur
}

func insertKey(t *testing.T, version int, sealed []byte, retired bool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_keys (tenant_id, version, key_sealed, retired_at)
		VALUES ('11111111-1111-1111-1111-111111111111', $1, $2, CASE WHEN $3 THEN now() ELSE NULL END)`,
		version, sealed, retired); err != nil {
		t.Fatal(err)
	}
}

func TestEveryTenantKeyMovesToTheNewMasterInOneGo(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	old, cur := masters(t)

	k1, _ := secrets.NewTenantKey()
	k2, _ := secrets.NewTenantKey()
	s1, _ := old.Seal(k1)
	s2, _ := old.Seal(k2)
	insertKey(t, 1, s1, true)
	insertKey(t, 2, s2, false)

	// Before: nothing opens under the new master.
	if _, failing, _ := d.VerifyMasterKeys(ctx, func(b []byte) error { _, err := cur.Open(b); return err }); len(failing) != 2 {
		t.Fatalf("before the rotation %d keys fail under the new master, want 2", len(failing))
	}

	rep, err := d.ResealMasterKeys(ctx, func(b []byte) ([]byte, bool, error) { return secrets.ResealMaster(old, cur, b) })
	if err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if rep.Total != 2 || rep.Resealed != 2 || rep.AlreadyCurrent != 0 {
		t.Fatalf("report %+v", rep)
	}

	// After: every key, the retired version included, opens under the new
	// master and under nothing else, and it is the same key.
	blobs, err := d.KeyBlobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range blobs {
		plain, err := cur.Open(b.Sealed)
		if err != nil {
			t.Fatalf("version %d does not open under the new master: %v", b.Version, err)
		}
		want := k1
		if b.Version == 2 {
			want = k2
		}
		if !bytes.Equal(plain, want) {
			t.Fatalf("version %d is not the same key after the move", b.Version)
		}
		if _, err := old.Open(b.Sealed); err == nil {
			t.Fatalf("version %d still opens under the old master", b.Version)
		}
	}
	// A second run finds nothing to do and says so.
	rep, err = d.ResealMasterKeys(ctx, func(b []byte) ([]byte, bool, error) { return secrets.ResealMaster(old, cur, b) })
	if err != nil || rep.AlreadyCurrent != 2 || rep.Resealed != 0 {
		t.Fatalf("second run: %+v %v", rep, err)
	}
}

// Reliability over coverage: one key the rotation cannot open stops the
// whole run, and the keys it could have moved are left exactly as they
// were. A half-rotated database is the one state nobody can recover from
// without the tool, and the tool would not know where it stopped.
func TestOneKeyNobodyCanOpenHaltsTheRotationAndChangesNothing(t *testing.T) {
	seed(t)
	d := open(t)
	ctx := context.Background()
	old, cur := masters(t)
	stranger, _ := secrets.NewAESSealer([]byte("a-master-nobody-here-knows-32byt"))

	k1, _ := secrets.NewTenantKey()
	k2, _ := secrets.NewTenantKey()
	s1, _ := old.Seal(k1)
	s2, _ := stranger.Seal(k2)
	insertKey(t, 1, s1, false)
	insertKey(t, 2, s2, true)

	_, err := d.ResealMasterKeys(ctx, func(b []byte) ([]byte, bool, error) { return secrets.ResealMaster(old, cur, b) })
	if !errors.Is(err, secrets.ErrUnopenable) {
		t.Fatalf("the run did not halt on the key it could not open: %v", err)
	}
	if !strings.Contains(err.Error(), "version 2") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("the halt does not say which key and that nothing changed: %v", err)
	}
	blobs, _ := d.KeyBlobs(ctx)
	for _, b := range blobs {
		if b.Version == 1 && !bytes.Equal(b.Sealed, s1) {
			t.Fatal("the key the run could open was moved although the run halted")
		}
	}
}
