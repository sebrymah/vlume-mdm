package secrets

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/uuid"

	"platform/internal/data"
)

// T3: one key per tenant.
//
// The master key seals tenant keys and nothing else. A tenant key seals
// that tenant's values and nothing else. A sealed value carries the
// version of the tenant key that sealed it, so rotation can make a new
// version and re-seal this tenant's values without touching any other
// tenant's, and so a value sealed under a retired version still opens.
//
// Values sealed before tenant keys existed are under the master key in
// the old format. Open tells them apart by the magic the new format
// starts with and falls back; Rotate re-seals them under the tenant's key.

// Sealer is the port the rest of the platform uses. The transaction says
// which tenant, through its claim, so no caller can seal under another
// tenant's key by passing the wrong id.
type Sealer interface {
	Seal(ctx context.Context, tx *data.Tx, plain []byte) ([]byte, error)
	Open(ctx context.Context, tx *data.Tx, sealed []byte) ([]byte, error)
}

var magic = []byte("TK2\x00")

const keySize = 32

// NewTenantKey makes a fresh tenant key.
func NewTenantKey() ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// SealWith seals under a tenant key, tagged with the key's version.
func SealWith(key []byte, version int, plain []byte) ([]byte, error) {
	if version <= 0 || version > 65535 {
		return nil, errors.New("secrets: key version out of range")
	}
	s, err := NewAESSealer(key)
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(magic)+2+len(ct))
	out = append(out, magic...)
	out = binary.BigEndian.AppendUint16(out, uint16(version))
	return append(out, ct...), nil
}

// Version reads which tenant-key version sealed a value, or 0 for a value
// in the old master-key format.
func Version(sealed []byte) int {
	if len(sealed) < len(magic)+2 || string(sealed[:len(magic)]) != string(magic) {
		return 0
	}
	return int(binary.BigEndian.Uint16(sealed[len(magic):]))
}

// OpenWith opens a value sealed by SealWith under the given key.
func OpenWith(key []byte, sealed []byte) ([]byte, error) {
	if Version(sealed) == 0 {
		return nil, ErrNotSealed
	}
	s, err := NewAESSealer(key)
	if err != nil {
		return nil, err
	}
	return s.Open(sealed[len(magic)+2:])
}

// Keyring is the Sealer the platform runs with: the master key, and the
// tenant keys it opens on demand.
type Keyring struct {
	master *AESSealer
	// previous are masters being rotated out. A tenant key sealed under
	// one still opens; nothing is ever sealed under one. The window
	// between deploying a new master and re-sealing every tenant key is
	// what they are for, and it closes when the tool has run.
	previous []*AESSealer
	mu       sync.Mutex
	cache    map[string][]byte // tenant|version -> key
}

func NewKeyring(master *AESSealer, previous ...*AESSealer) *Keyring {
	return &Keyring{master: master, previous: previous, cache: map[string][]byte{}}
}

// RotateMaster makes master the one tenant keys are sealed under from now on
// and keeps the one it replaces among the previous, so every tenant key
// still opens until tenantctl reseal-master has moved them (0044). The
// tenant keys already opened stay opened: they are the tenants' own and
// did not change.
func (k *Keyring) RotateMaster(master *AESSealer) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if master == nil || master == k.master {
		return
	}
	k.previous = append([]*AESSealer{k.master}, k.previous...)
	k.master = master
}

// masters is the current master and the ones being rotated out, read
// under the lock so a rotation never splits a read.
func (k *Keyring) masters() (*AESSealer, []*AESSealer) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.master, k.previous
}

// openMaster opens a tenant key under the current master, or under one
// being rotated out. The error reported is the current master's: that is
// the one a value is supposed to be under.
func (k *Keyring) openMaster(sealed []byte) ([]byte, error) {
	master, previous := k.masters()
	plain, err := master.Open(sealed)
	if err == nil {
		return plain, nil
	}
	for _, m := range previous {
		if p, perr := m.Open(sealed); perr == nil {
			return p, nil
		}
	}
	return nil, err
}

// OpenMaster opens a tenant key as stored, under the current master or one
// being rotated out. The move bundle uses it to re-seal a tenant's keys
// under a transport key; nothing else outside this package needs it.
func (k *Keyring) OpenMaster(sealed []byte) ([]byte, error) { return k.openMaster(sealed) }

// SealMaster seals a value under the current master key directly, with no
// tenant involved. It is for the platform owner's own secrets (an owner's
// authenticator secret), which belong to no organisation and so have no
// tenant key to be sealed under. OpenMaster opens what it makes, and a master
// being rotated out still opens what it sealed.
func (k *Keyring) SealMaster(plain []byte) ([]byte, error) {
	cur, _ := k.masters()
	return cur.Seal(plain)
}

// ErrUnopenable is a tenant key that neither the current master nor the
// previous one can open. A rotation stops on it rather than guessing.
var ErrUnopenable = errors.New("secrets: this tenant key opens under neither the current nor the previous master key")

// ResealMaster is one step of a master-key rotation: a tenant key sealed
// under the previous master comes back sealed under the current one. A
// key already under the current master is reported as such and left
// alone; a key under neither is ErrUnopenable, and the caller halts.
func ResealMaster(previous, current *AESSealer, sealed []byte) (resealed []byte, already bool, err error) {
	if _, err := current.Open(sealed); err == nil {
		return sealed, true, nil
	}
	if previous == nil {
		return nil, false, ErrUnopenable
	}
	plain, err := previous.Open(sealed)
	if err != nil {
		return nil, false, ErrUnopenable
	}
	out, err := current.Seal(plain)
	if err != nil {
		return nil, false, err
	}
	return out, false, nil
}

// NewTenantKey is for creating a tenant: the key in the clear for sealing
// the tenant's first secret, and sealed under the master for the row.
func (k *Keyring) NewTenantKey() (plain, sealed []byte, err error) {
	plain, err = NewTenantKey()
	if err != nil {
		return nil, nil, err
	}
	master, _ := k.masters()
	sealed, err = master.Seal(plain)
	if err != nil {
		return nil, nil, err
	}
	return plain, sealed, nil
}

func cacheKey(tenant uuid.UUID, version int) string {
	return fmt.Sprintf("%s|%d", tenant, version)
}

// current is the tenant's live key, made on first use for a tenant that
// predates tenant keys.
func (k *Keyring) current(ctx context.Context, tx *data.Tx) (int, []byte, error) {
	var version int
	var sealed []byte
	err := tx.QueryRow(ctx, `SELECT version, key_sealed FROM tenant_keys WHERE retired_at IS NULL`).Scan(&version, &sealed)
	if err != nil {
		if err.Error() != "no rows in result set" {
			return 0, nil, err
		}
		plain, sealedKey, err := k.NewTenantKey()
		if err != nil {
			return 0, nil, err
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO tenant_keys (tenant_id, version, key_sealed)
			VALUES (app.current_tenant(), coalesce((SELECT max(version) FROM tenant_keys), 0) + 1, $1)
			RETURNING version`, sealedKey).Scan(&version); err != nil {
			return 0, nil, err
		}
		k.remember(tx, version, plain)
		return version, plain, nil
	}
	plain, err := k.openMaster(sealed)
	if err != nil {
		return 0, nil, fmt.Errorf("secrets: this tenant's key cannot be opened under the master key: %w", err)
	}
	k.remember(tx, version, plain)
	return version, plain, nil
}

func (k *Keyring) remember(tx *data.Tx, version int, key []byte) {
	k.mu.Lock()
	k.cache[cacheKey(tx.Claim().TenantID, version)] = key
	k.mu.Unlock()
}

func (k *Keyring) byVersion(ctx context.Context, tx *data.Tx, version int) ([]byte, error) {
	k.mu.Lock()
	key, ok := k.cache[cacheKey(tx.Claim().TenantID, version)]
	k.mu.Unlock()
	if ok {
		return key, nil
	}
	var sealed []byte
	if err := tx.QueryRow(ctx, `SELECT key_sealed FROM tenant_keys WHERE version = $1`, version).Scan(&sealed); err != nil {
		return nil, fmt.Errorf("secrets: no key version %d for this tenant: %w", version, ErrNotSealed)
	}
	plain, err := k.openMaster(sealed)
	if err != nil {
		return nil, fmt.Errorf("secrets: key version %d cannot be opened under the master key: %w", version, err)
	}
	k.remember(tx, version, plain)
	return plain, nil
}

func (k *Keyring) Seal(ctx context.Context, tx *data.Tx, plain []byte) ([]byte, error) {
	version, key, err := k.current(ctx, tx)
	if err != nil {
		return nil, err
	}
	return SealWith(key, version, plain)
}

func (k *Keyring) Open(ctx context.Context, tx *data.Tx, sealed []byte) ([]byte, error) {
	v := Version(sealed)
	if v == 0 {
		// Before tenant keys: under the master, old format.
		return k.openMaster(sealed)
	}
	key, err := k.byVersion(ctx, tx, v)
	if err != nil {
		return nil, err
	}
	return OpenWith(key, sealed)
}

// Rotate makes a new current version and retires the old one. The caller
// re-seals the tenant's values; until it does, they still open, because
// retired keys stay readable.
func (k *Keyring) Rotate(ctx context.Context, tx *data.Tx) (int, error) {
	plain, sealedKey, err := k.NewTenantKey()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_keys SET retired_at = now() WHERE retired_at IS NULL`); err != nil {
		return 0, err
	}
	var version int
	if err := tx.QueryRow(ctx, `
		INSERT INTO tenant_keys (tenant_id, version, key_sealed)
		VALUES (app.current_tenant(), coalesce((SELECT max(version) FROM tenant_keys), 0) + 1, $1)
		RETURNING version`, sealedKey).Scan(&version); err != nil {
		return 0, err
	}
	k.remember(tx, version, plain)
	return version, nil
}

// Reseal opens under whatever sealed it and seals under the current key.
func (k *Keyring) Reseal(ctx context.Context, tx *data.Tx, sealed []byte) ([]byte, error) {
	plain, err := k.Open(ctx, tx, sealed)
	if err != nil {
		return nil, err
	}
	return k.Seal(ctx, tx, plain)
}
