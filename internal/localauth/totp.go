package localauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238's default, and what every authenticator app speaks
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

// The second factor: RFC 6238 time-based one-time passwords, six digits, a
// thirty-second step, SHA-1, because that is what Google Authenticator,
// Microsoft Authenticator, Authy, 1Password and every other app agree on.

const (
	TOTPStep   = 30 * time.Second
	totpDigits = 6
	// totpWindow is how many steps either side of now a code is accepted,
	// for a phone whose clock is a little off. One step is the usual.
	totpWindow = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret makes twenty random bytes, the length RFC 4226 recommends.
func NewSecret() ([]byte, error) {
	s := make([]byte, 20)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// SecretText is the secret as an authenticator app types it.
func SecretText(secret []byte) string { return b32.EncodeToString(secret) }

// URI is the otpauth address an app reads from a QR code.
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", SecretText(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(TOTPStep/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// QRPNG draws the URI as a QR code.
func QRPNG(uri string) ([]byte, error) {
	c, err := qr.Encode(uri, qr.M)
	if err != nil {
		return nil, err
	}
	c.Scale = 6
	return c.PNG(), nil
}

// codeAt is the code for one step.
func codeAt(secret []byte, step uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], step)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", totpDigits, bin%1000000)
}

// StepAt is the step a moment falls in.
func StepAt(t time.Time) uint64 { return uint64(t.Unix()) / uint64(TOTPStep/time.Second) }

// Code is the code for a moment, for a test and for nothing else.
func Code(secret []byte, t time.Time) string { return codeAt(secret, StepAt(t)) }

// Match says which step a typed code is the code for, within the window, or
// false. The caller then refuses any step it has already accepted: a code is
// good once, so a code somebody watched being typed is no use to them.
func Match(secret []byte, typed string, now time.Time) (step uint64, ok bool) {
	typed = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, typed)
	if len(typed) != totpDigits {
		return 0, false
	}
	cur := StepAt(now)
	found := false
	// Every step is compared, in constant time, so how early the match is
	// found says nothing.
	for d := -totpWindow; d <= totpWindow; d++ {
		s := uint64(int64(cur) + int64(d))
		if subtle.ConstantTimeCompare([]byte(codeAt(secret, s)), []byte(typed)) == 1 {
			step, found = s, true
		}
	}
	return step, found
}

// ---------------------------------------------------------------- recovery

const recoveryCount = 10

var recoveryAlphabet = []byte("abcdefghjkmnpqrstuvwxyz23456789")

// NewRecoveryCodes makes ten one-time codes, shown once, and their hashes,
// which are what is kept. Ten characters from a thirty-one letter alphabet
// is about fifty bits, ample for a code that works once and is behind a
// password.
func NewRecoveryCodes() (codes, hashes []string, err error) {
	for i := 0; i < recoveryCount; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		for j := range b {
			b[j] = recoveryAlphabet[int(b[j])%len(recoveryAlphabet)]
		}
		code := string(b[:5]) + "-" + string(b[5:])
		codes = append(codes, code)
		hashes = append(hashes, HashRecovery(code))
	}
	return codes, hashes, nil
}

// HashRecovery is how a typed code is compared with what is stored: lower
// case, separators and spaces dropped, then SHA-256.
func HashRecovery(code string) string {
	var norm bytes.Buffer
	for _, r := range strings.ToLower(code) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			norm.WriteRune(r)
		}
	}
	sum := sha256.Sum256(norm.Bytes())
	return hex.EncodeToString(sum[:])
}

// LooksLikeRecovery tells a recovery code from a six-digit one, so the
// second-factor page takes either in one box.
func LooksLikeRecovery(typed string) bool {
	n := 0
	for _, r := range typed {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return true
		}
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n > totpDigits
}
