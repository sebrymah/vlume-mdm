package command

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"platform/internal/data"
)

// KeyProvider hands out a tenant's command signing key. R8 requires
// RSA-SHA256, and the specification puts the key in the tenant's key vault
// entry with its own rotation.
//
// This is the adapter port for that. The shape of everything below does not
// change when the implementation moves from memory to a vault; the source of
// the bytes does.
type KeyProvider interface {
	// SigningKey is the current key of the transaction's tenant. The
	// transaction is passed so a stored key is read under the tenant's
	// own claim, like everything else of the tenant's.
	SigningKey(ctx context.Context, tx *data.Tx) (*rsa.PrivateKey, error)
	// PublicKeys are every key a device may still meet a signature from:
	// the current one first, retired ones after it.
	PublicKeys(ctx context.Context, tx *data.Tx) ([]PublicKey, error)
}

// PublicKey is one version of a tenant's verification key.
type PublicKey struct {
	Version int
	Key     *rsa.PublicKey
}

// DevKeyProvider generates a key per tenant and keeps it in memory. It is for
// development and tests only: keys do not survive a restart, are not rotated,
// and are not protected by anything. Nothing deployed may use it.
type DevKeyProvider struct {
	mu   sync.Mutex
	keys map[uuid.UUID]*rsa.PrivateKey
	bits int
}

func NewDevKeyProvider(bits int) *DevKeyProvider {
	if bits == 0 {
		bits = 2048
	}
	return &DevKeyProvider{keys: map[uuid.UUID]*rsa.PrivateKey{}, bits: bits}
}

func (d *DevKeyProvider) SigningKey(_ context.Context, tx *data.Tx) (*rsa.PrivateKey, error) {
	tenant := tx.Claim().TenantID
	d.mu.Lock()
	defer d.mu.Unlock()
	if k, ok := d.keys[tenant]; ok {
		return k, nil
	}
	k, err := rsa.GenerateKey(rand.Reader, d.bits)
	if err != nil {
		return nil, err
	}
	d.keys[tenant] = k
	return k, nil
}

func (d *DevKeyProvider) PublicKeys(ctx context.Context, tx *data.Tx) ([]PublicKey, error) {
	k, err := d.SigningKey(ctx, tx)
	if err != nil {
		return nil, err
	}
	return []PublicKey{{Version: 1, Key: &k.PublicKey}}, nil
}

// Payload is exactly what gets signed, and it is exported because the device
// has to rebuild it byte for byte to verify.
//
// The tenant is in it deliberately: without that, a signature lifted from one
// tenant could be replayed against another tenant's device with the same
// command identifier.
func Payload(tenant uuid.UUID, c Command) string {
	exp := ""
	if c.NonceExpiresAt != nil {
		exp = c.NonceExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return strings.Join([]string{
		"mdm.command.v1",
		tenant.String(),
		c.ID.String(),
		c.DeviceID.String(),
		string(c.Type),
		c.Nonce,
		exp,
	}, "|")
}

// Verify is what the device does. It is here so the test suite checks the
// same code the sensor will, rather than a second implementation that agrees
// with this one until it does not.
func Verify(pub *rsa.PublicKey, tenant uuid.UUID, c Command) error {
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("command: signature is not valid base64: %w", err)
	}
	sum := sha256.Sum256([]byte(Payload(tenant, c)))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)
}

// sign mints the one-time code, sets its expiry and signs the whole thing.
// Nothing reaches a device unsigned: the schema has a check constraint that
// refuses an approved command without a signature, a nonce and an expiry.
func (p *Pipeline) sign(ctx context.Context, tx *data.Tx, c Command) (Command, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return Command{}, err
	}
	c.Nonce = hex.EncodeToString(raw)
	// Truncated to microseconds because that is PostgreSQL's timestamptz
	// precision. Signing a nanosecond-precision time and then verifying
	// against the value read back would fail on every real device, and the
	// signature would be the thing blamed rather than the round trip.
	exp := p.now().UTC().Add(NonceTTL).Truncate(time.Microsecond)
	c.NonceExpiresAt = &exp

	key, err := p.keys.SigningKey(ctx, tx)
	if err != nil {
		return Command{}, err
	}
	sum := sha256.Sum256([]byte(Payload(tx.Claim().TenantID, c)))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return Command{}, err
	}
	c.Signature = base64.StdEncoding.EncodeToString(sig)

	if _, err := tx.Exec(ctx, `
		UPDATE commands SET signature=$2, nonce=$3, nonce_expires_at=$4
		 WHERE id=$1`, c.ID, c.Signature, c.Nonce, exp); err != nil {
		return Command{}, err
	}
	return c, nil
}
