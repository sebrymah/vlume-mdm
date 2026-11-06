// Package tenantclaim mints and verifies the short-lived internal claim that
// carries the tenant across every call inside the platform.
//
// The technical specification: the gateway resolves the tenant once, from the
// host header for a custom domain, the identity provider claim for a console
// session, or the device identity certificate for a device call. It then mints
// a signed claim carrying the tenant, the subject, the role and the request
// identifier. Every module call carries that claim, and the data layer reads
// the tenant from it rather than from an argument.
//
// When a module is later extracted into its own service, this claim is already
// the transport, so nothing about the isolation model changes.
package tenantclaim

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrMalformed = errors.New("tenantclaim: malformed token")
	ErrSignature = errors.New("tenantclaim: signature does not verify")
	ErrExpired   = errors.New("tenantclaim: expired")
	ErrInvalid   = errors.New("tenantclaim: invalid claim contents")
)

// Claim is what travels. Deliberately small: anything larger invites callers
// to start passing business data around inside it.
type Claim struct {
	TenantID uuid.UUID `json:"tid"`
	Subject  string    `json:"sub"`
	// Email is here, and nothing else about the person is, because the data
	// layer has one question that needs it: which devices belong to whoever
	// is asking. An administrator assigns a device by typing an email, so
	// matching on the subject alone would mean nobody could be assigned
	// anything without someone typing a provider GUID.
	//
	// This is the line the "deliberately small" rule above is drawn at: an
	// identifier for the person in front of us, never an attribute about
	// them.
	Email     string    `json:"em,omitempty"`
	Role      string    `json:"role"`
	RequestID string    `json:"rid"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// Signer holds the key the gateway signs with. In production this is a
// per-deployment key held in the vault and rotated there; the shape of the
// code does not change when it moves.
type Signer struct {
	mu  sync.RWMutex
	key []byte
	// previous is the key before the last rotation (0044): a claim it
	// signed still verifies for the seconds it lives; nothing new is
	// signed with it.
	previous []byte
}

func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("tenantclaim: signing key must be at least 32 bytes, got %d", len(key))
	}
	return &Signer{key: append([]byte(nil), key...)}, nil
}

// Rotate makes key the one new claims are signed with and keeps the one
// before it for verifying what it signed.
func (s *Signer) Rotate(key []byte) error {
	if len(key) < 32 {
		return fmt.Errorf("tenantclaim: signing key must be at least 32 bytes, got %d", len(key))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if hmac.Equal(key, s.key) {
		return nil
	}
	s.previous = s.key
	s.key = append([]byte(nil), key...)
	return nil
}

func (s *Signer) keys() (current, previous []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key, s.previous
}

// Mint produces a token for the given tenant. ttl is deliberately short: the
// claim exists to cross a call boundary inside one request, not to be stored.
func (s *Signer) Mint(c Claim, ttl time.Duration) (string, error) {
	if c.TenantID == uuid.Nil {
		return "", fmt.Errorf("%w: tenant id is empty", ErrInvalid)
	}
	if c.Subject == "" || c.Role == "" {
		return "", fmt.Errorf("%w: subject and role are required", ErrInvalid)
	}
	now := time.Now().UTC()
	c.IssuedAt = now
	c.ExpiresAt = now.Add(ttl)

	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString(body)
	return b + "." + base64.RawURLEncoding.EncodeToString(s.sign([]byte(b))), nil
}

// Verify checks the signature and the expiry, then returns the claim. A
// caller that cannot produce a verifying token gets no tenant, and with no
// tenant the data layer refuses to run a query at all.
func (s *Signer) Verify(token string) (Claim, error) {
	var c Claim

	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot == len(token)-1 {
		return c, ErrMalformed
	}
	bodyB64, sigB64 := token[:dot], token[dot+1:]

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return c, ErrMalformed
	}
	// Constant time, so a wrong signature leaks nothing about the right one.
	// The current key first, then the one before the last rotation.
	cur, prev := s.keys()
	if !hmac.Equal(sig, mac(cur, []byte(bodyB64))) && (prev == nil || !hmac.Equal(sig, mac(prev, []byte(bodyB64)))) {
		return c, ErrSignature
	}

	body, err := base64.RawURLEncoding.DecodeString(bodyB64)
	if err != nil {
		return c, ErrMalformed
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, ErrMalformed
	}
	if c.TenantID == uuid.Nil {
		return c, fmt.Errorf("%w: tenant id is empty", ErrInvalid)
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		return c, ErrExpired
	}
	return c, nil
}

func (s *Signer) sign(b []byte) []byte {
	cur, _ := s.keys()
	return mac(cur, b)
}

func mac(key, b []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return m.Sum(nil)
}
