// Package session is the console's sign-in state: who a browser is, which
// tenant they belong to, and for how long.
//
// A session is a signed token, not a row. That is a decision with a cost, so
// here is the reasoning on both sides.
//
// For: the tenant is decided by the hostname before anything else happens.
// A session stored as a row would have to be looked up BEFORE the tenant is
// known, which means a lookup outside row-level security, which means a
// cross-tenant read path in the one place the whole design is built to avoid
// having one. A signed token carries its own tenant and is checked against
// the hostname, so a session for Kalesi presented to Arbor's hostname fails
// on the comparison the gateway already makes.
//
// Against: a token cannot be revoked one at a time. A stolen session stays
// good until it expires. Two things hold that down. The idle timeout is
// thirty minutes, so a token taken from a closed laptop is usually already
// dead. And tenants.sessions_invalid_before revokes every session a tenant
// has at once, checked against StartedAt, which never moves when a session
// renews. Per-session revocation needs a row and is listed as not built.
package session

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

const (
	// Lifetime is the longest a session can live however active the person
	// is. At the end of it they sign in again and the provider gets to
	// reapply its own rules, which is the point: multi-factor, conditional
	// access and account disablement all live at the provider, and they only
	// bite when we go back.
	Lifetime = 12 * time.Hour

	// IdleTimeout is the gap after which a session stops working.
	IdleTimeout = 30 * time.Minute

	// RenewAfter is how stale a token has to be before a request re-mints
	// it. Without it every request would issue a new cookie.
	RenewAfter = 5 * time.Minute
)

var (
	ErrMalformed = errors.New("session: malformed token")
	ErrSignature = errors.New("session: signature does not verify")
	ErrExpired   = errors.New("session: expired")
	ErrIdle      = errors.New("session: idle for too long")
	ErrInvalid   = errors.New("session: invalid contents")
)

// Session is what the cookie carries.
type Session struct {
	TenantID uuid.UUID `json:"tid"`
	Subject  string    `json:"sub"`
	Email    string    `json:"em,omitempty"`
	Name     string    `json:"nm,omitempty"`
	Role     string    `json:"role"`

	// StartedAt is when the person signed in. It never moves, which is what
	// makes tenant-wide revocation work: renewal cannot outrun it.
	StartedAt time.Time `json:"sat"`
	IssuedAt  time.Time `json:"iat"`
	IdleUntil time.Time `json:"idl"`
	ExpiresAt time.Time `json:"exp"`
}

func (s Session) ShouldRenew() bool {
	return time.Now().UTC().Sub(s.IssuedAt) > RenewAfter
}

type Signer struct {
	mu  sync.RWMutex
	key []byte
	// previous is the key before the last rotation. A token it signed
	// still verifies, so a session that was open when the key turned over
	// stays open; nothing new is signed with it. It lasts until the next
	// rotation, which is longer than any session.
	previous []byte
	// Now is the clock. It is a field rather than a call to time.Now so
	// that the expiry rules can be tested at the minute rather than by
	// sleeping through them. Production never sets it.
	Now func() time.Time
}

func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("session: signing key must be at least 32 bytes, got %d", len(key))
	}
	return &Signer{key: append([]byte(nil), key...), Now: func() time.Time {
		return time.Now().UTC()
	}}, nil
}

// Rotate makes key the one new tokens are signed with and keeps the one
// before it for verifying what it signed (0044). The control
// --break-rotategrace forgets the previous key.
func (s *Signer) Rotate(key []byte) error {
	if len(key) < 32 {
		return fmt.Errorf("session: signing key must be at least 32 bytes, got %d", len(key))
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

// Start mints a brand new session. Only the sign-in callback calls it.
func (s *Signer) Start(sess Session) (string, Session, error) {
	if sess.TenantID == uuid.Nil {
		return "", Session{}, fmt.Errorf("%w: tenant id is empty", ErrInvalid)
	}
	if sess.Subject == "" || sess.Role == "" {
		return "", Session{}, fmt.Errorf("%w: subject and role are required", ErrInvalid)
	}
	now := s.Now()
	sess.StartedAt = now
	sess.IssuedAt = now
	sess.IdleUntil = now.Add(IdleTimeout)
	sess.ExpiresAt = now.Add(Lifetime)
	tok, err := s.mint(sess)
	return tok, sess, err
}

// Renew pushes the idle deadline forward without touching StartedAt or the
// absolute expiry. A session cannot be extended past Lifetime by using it.
func (s *Signer) Renew(sess Session) (string, Session, error) {
	now := s.Now()
	sess.IssuedAt = now
	sess.IdleUntil = now.Add(IdleTimeout)
	if sess.IdleUntil.After(sess.ExpiresAt) {
		sess.IdleUntil = sess.ExpiresAt
	}
	tok, err := s.mint(sess)
	return tok, sess, err
}

func (s *Signer) mint(sess Session) (string, error) {
	body, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString(body)
	return b + "." + base64.RawURLEncoding.EncodeToString(s.sign([]byte(b))), nil
}

func (s *Signer) Verify(token string) (Session, error) {
	var sess Session
	body, err := s.open(token)
	if err != nil {
		return sess, err
	}
	if err := json.Unmarshal(body, &sess); err != nil {
		return sess, ErrMalformed
	}
	if sess.TenantID == uuid.Nil || sess.Subject == "" || sess.Role == "" {
		return sess, ErrInvalid
	}
	now := s.Now()
	// Absolute expiry first: it is the one that cannot be argued with.
	if now.After(sess.ExpiresAt) {
		return sess, ErrExpired
	}
	if now.After(sess.IdleUntil) {
		return sess, ErrIdle
	}
	return sess, nil
}

// ---------------------------------------------------------------- the flow
//
// Between the redirect out to the provider and the callback back, three
// things have to survive: the state value that proves the callback belongs to
// this browser's request, the nonce that ties the identity token to it, and
// the code verifier for PKCE. They go in a short-lived signed cookie of their
// own, which is why this type is here and not in the identity package: it is
// the same signing machinery, and the identity package has no business
// knowing how we sign things.

const FlowLifetime = 10 * time.Minute

type Flow struct {
	TenantID  uuid.UUID `json:"tid"`
	State     string    `json:"st"`
	Nonce     string    `json:"nc"`
	Verifier  string    `json:"vf"`
	Return    string    `json:"rt,omitempty"`
	ExpiresAt time.Time `json:"exp"`
}

func (s *Signer) MintFlow(f Flow) (string, error) {
	if f.TenantID == uuid.Nil || f.State == "" || f.Nonce == "" {
		return "", fmt.Errorf("%w: flow needs a tenant, a state and a nonce", ErrInvalid)
	}
	f.ExpiresAt = s.Now().Add(FlowLifetime)
	body, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString(body)
	// The prefix keeps a flow token from ever verifying as a session. They
	// are signed with the same key, and without it a flow token in the
	// session cookie would be a token the signer vouches for.
	return "f1." + b + "." + base64.RawURLEncoding.EncodeToString(s.sign([]byte("f1."+b))), nil
}

func (s *Signer) VerifyFlow(token string) (Flow, error) {
	var f Flow
	if len(token) < 3 || token[:3] != "f1." {
		return f, ErrMalformed
	}
	body, err := s.open(token)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(body, &f); err != nil {
		return f, ErrMalformed
	}
	if s.Now().After(f.ExpiresAt) {
		return f, ErrExpired
	}
	return f, nil
}

// open checks the signature and returns the decoded body. It does not look at
// the contents, so both token kinds share it.
func (s *Signer) open(token string) ([]byte, error) {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 || dot == len(token)-1 {
		return nil, ErrMalformed
	}
	signed, sigB64 := token[:dot], token[dot+1:]

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrMalformed
	}
	// Constant time, so a wrong signature says nothing about the right one.
	// The current key first, then the one before the last rotation.
	cur, prev := s.keys()
	if !hmac.Equal(sig, mac(cur, []byte(signed))) && (prev == nil || !hmac.Equal(sig, mac(prev, []byte(signed)))) {
		return nil, ErrSignature
	}

	// A flow token's signed part carries the version prefix; strip it before
	// decoding the body.
	if len(signed) > 3 && signed[:3] == "f1." {
		signed = signed[3:]
	}
	body, err := base64.RawURLEncoding.DecodeString(signed)
	if err != nil {
		return nil, ErrMalformed
	}
	return body, nil
}

func (s *Signer) sign(b []byte) []byte {
	cur, _ := s.keys()
	return mac(cur, b)
}

func (s *Signer) keys() (current, previous []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key, s.previous
}

func mac(key, b []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return m.Sum(nil)
}
