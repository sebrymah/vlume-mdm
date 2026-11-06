// Package secrets holds the port for sealing a value the platform must store
// but must not store in the clear.
//
// There is exactly one such value today: a tenant's identity provider client
// secret. It has to survive a restart, so it goes in the database, and the
// database is the wrong place to keep a usable credential. Sealing moves the
// usable form into the process, where the key comes from the vault.
//
// The port matters more than this implementation. AESSealer takes its key
// from configuration; the production sealer will take it from the tenant key
// vault with rotation, and nothing that calls Seal or Open will change.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var ErrNotSealed = errors.New("secrets: value is not sealed, or was sealed under another key")

// AESSealer is AES-256-GCM with a random nonce per value.
type AESSealer struct {
	aead cipher.AEAD
}

func NewAESSealer(key []byte) (*AESSealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secrets: sealing key must be exactly 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESSealer{aead: aead}, nil
}

func (s *AESSealer) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// The nonce travels in front of the ciphertext. It is not secret; it only
	// has to be unique, which rand gives us.
	return s.aead.Seal(nonce, nonce, plain, nil), nil
}

func (s *AESSealer) Open(sealed []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, ErrNotSealed
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], nil)
	if err != nil {
		// Deliberately opaque. The caller cannot tell a wrong key from a
		// tampered value, and does not need to.
		return nil, ErrNotSealed
	}
	return plain, nil
}
