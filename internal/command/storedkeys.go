package command

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"platform/internal/data"
	"platform/internal/secrets"
)

// StoredKeys is the KeyProvider a deployment runs with: a key per tenant
// and version in command_signing_keys, the private half sealed under the
// tenant's own key, read under the tenant's claim, cached once opened.
// The first command a tenant ever signs makes its key; Rotate makes the
// next version and keeps the old one readable, because a command signed
// under it may still be on its way to a laptop that was off.
type StoredKeys struct {
	Sealer secrets.Sealer
	// Bits is the RSA size; zero means 2048. Tests use less to stay fast.
	Bits int

	mu    sync.Mutex
	cache map[string]*rsa.PrivateKey // tenant|version -> key
}

func (s *StoredKeys) bits() int {
	if s.Bits == 0 {
		return 2048
	}
	return s.Bits
}

func (s *StoredKeys) remember(tx *data.Tx, version int, k *rsa.PrivateKey) {
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]*rsa.PrivateKey{}
	}
	s.cache[fmt.Sprintf("%s|%d", tx.Claim().TenantID, version)] = k
	s.mu.Unlock()
}

func (s *StoredKeys) cached(tx *data.Tx, version int) (*rsa.PrivateKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.cache[fmt.Sprintf("%s|%d", tx.Claim().TenantID, version)]
	return k, ok
}

// SigningKey is the tenant's current key, made on first use.
func (s *StoredKeys) SigningKey(ctx context.Context, tx *data.Tx) (*rsa.PrivateKey, error) {
	if s.Sealer == nil {
		return nil, errors.New("command: stored signing keys need a sealer")
	}
	var version int
	var sealed []byte
	err := tx.QueryRow(ctx, `SELECT version, private_key_sealed FROM command_signing_keys WHERE retired_at IS NULL`).Scan(&version, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.make(ctx, tx)
	}
	if err != nil {
		return nil, err
	}
	if k, ok := s.cached(tx, version); ok {
		return k, nil
	}
	der, err := s.Sealer.Open(ctx, tx, sealed)
	if err != nil {
		return nil, fmt.Errorf("command: the signing key cannot be opened: %w", err)
	}
	k, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("command: the stored signing key is not a key: %w", err)
	}
	s.remember(tx, version, k)
	return k, nil
}

// make writes the next version: sealed private half, public half in the
// clear, under the transaction's tenant.
func (s *StoredKeys) make(ctx context.Context, tx *data.Tx) (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, s.bits())
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	sealed, err := s.Sealer.Seal(ctx, tx, der)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	var version int
	if err := tx.QueryRow(ctx, `
		INSERT INTO command_signing_keys (tenant_id, version, private_key_sealed, public_key)
		VALUES (app.current_tenant(), coalesce((SELECT max(version) FROM command_signing_keys), 0) + 1, $1, $2)
		RETURNING version`, sealed, pub).Scan(&version); err != nil {
		return nil, err
	}
	s.remember(tx, version, k)
	return k, nil
}

// Rotate retires the current key and makes the next. Commands already
// signed still verify: the retired key stays in the list the device reads.
func (s *StoredKeys) Rotate(ctx context.Context, tx *data.Tx) (int, error) {
	if _, err := tx.Exec(ctx, `UPDATE command_signing_keys SET retired_at = now() WHERE retired_at IS NULL`); err != nil {
		return 0, err
	}
	k, err := s.make(ctx, tx)
	if err != nil {
		return 0, err
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT version FROM command_signing_keys WHERE retired_at IS NULL`).Scan(&version); err != nil {
		return 0, err
	}
	_ = k
	return version, nil
}

// PublicKeys lists every version, current first, so a device can verify
// whatever it is handed.
func (s *StoredKeys) PublicKeys(ctx context.Context, tx *data.Tx) ([]PublicKey, error) {
	// Make sure a tenant that has never signed anything still has a key to
	// hand out, so a device never caches "no keys".
	if _, err := s.SigningKey(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT version, public_key FROM command_signing_keys ORDER BY (retired_at IS NULL) DESC, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublicKey
	for rows.Next() {
		var v int
		var der []byte
		if err := rows.Scan(&v, &der); err != nil {
			return nil, err
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("command: a stored signing key is not RSA")
		}
		out = append(out, PublicKey{Version: v, Key: rsaPub})
	}
	return out, rows.Err()
}
