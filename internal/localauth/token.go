package localauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewToken makes the token in an invitation or reset link, and the hash
// that is kept: 256 random bits, so a copy of the table is not a set of
// working links.
func NewToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(raw), sum[:], nil
}

// TokenHash is the hash of a token that arrived in a link, or false for
// anything that could not have been made by NewToken.
func TokenHash(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}
