// Package localauth is sign-in for a tenant that has no identity
// provider: passwords, and the second factor that makes a password
// enough for someone who can wipe a fleet.
//
// Nothing here touches a database. It hashes, checks, generates and
// verifies, and the gateway decides what to store; that keeps every
// security-relevant rule in this package testable on its own.
package localauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// The cost. Argon2id at 46 MiB, two passes, one lane: one of the
// combinations OWASP lists as equivalent in strength, chosen over the
// 19 MiB one because a sign-in is rare and a stolen table is not. The
// parameters are written into every hash, so raising them later leaves
// every existing hash verifiable.
const (
	argonMemoryKiB = 47104
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16
)

// maxHashing bounds how many hashes run at once. Each holds 46 MiB, so
// an unthrottled flood of sign-in attempts is a flood of memory; the
// per-address limiter in the gateway is the first line and this is the
// second, which turns "too many" into waiting rather than into an
// out-of-memory kill.
var hashSlots = make(chan struct{}, 4)

func slot() func() {
	hashSlots <- struct{}{}
	return func() { <-hashSlots }
}

// MaxPasswordBytes stops a megabyte of "password" from being hashed. Far
// above what a person types, far below what costs anything.
const MaxPasswordBytes = 1024

// MinPasswordLength is twelve, longer than the usual eight because the
// second factor is not there for every role, and a length is the one rule
// that does not depend on a person's imagination.
const MinPasswordLength = 12

var (
	ErrWrongPassword = errors.New("localauth: wrong password")
	ErrBadHash       = errors.New("localauth: the stored hash is not one this build reads")
)

// Hash returns the PHC string for a password: $argon2id$v=19$m=…,t=…,p=…$salt$hash.
func Hash(password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", errors.New("localauth: that password is too long")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	release := slot()
	defer release()
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks a password against a stored hash in constant time. The
// parameters come from the hash, bounded: a hash row somebody edited to ask
// for 4 GiB is refused rather than obeyed.
func Verify(password, encoded string) error {
	if len(password) > MaxPasswordBytes {
		return ErrWrongPassword
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return ErrBadHash
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return ErrBadHash
	}
	if memory == 0 || memory > 256*1024 || time == 0 || time > 10 || threads == 0 || threads > 8 {
		return ErrBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return ErrBadHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 {
		return ErrBadHash
	}
	release := slot()
	defer release()
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// dummy is a hash of nothing anybody knows, verified against when the
// account does not exist, so an unknown address costs the same time as a
// wrong password and the response gives nothing away.
var dummy string

func init() {
	h, err := Hash("not-a-password-anyone-has-" + base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	if err != nil {
		panic(err)
	}
	dummy = h
}

// VerifyAbsent spends the same time as Verify, for an account that is not
// there, and always fails.
func VerifyAbsent(password string) {
	_ = Verify(password, dummy)
}

// common is what a twelve-character minimum still lets through: the long
// passwords everybody tries first. Short ones are the length rule's.
var common = map[string]bool{
	"passwordpassword": true, "password1234": true, "password12345": true, "password123456": true,
	"1234567890123": true, "123456789012": true, "1234567890ab": true, "qwertyuiopas": true,
	"qwertyuiop12": true, "qwertyuiop123": true, "administrator": true, "administrator1": true,
	"welcome12345": true, "welcome123456": true, "letmein123456": true, "iloveyou1234": true,
	"iloveyou12345": true, "changeme1234": true, "changemechangeme": true, "abcdefghijkl": true,
	"abcd12345678": true, "monkey123456": true, "dragon123456": true, "football1234": true,
	"baseball1234": true, "superman1234": true, "trustno1trustno1": true, "passw0rd1234": true,
	"p@ssw0rd1234": true, "p@ssword1234": true, "admin1234567": true, "admin12345678": true,
	"root12345678": true, "default12345": true, "test12345678": true, "testtesttest": true,
	"loginlogin12": true, "mdmmdmmdmmdm": true, "company12345": true, "nigeria12345": true,
	"babbangona12": true, "babbangona123": true, "lagos1234567": true, "november2026": true,
	"december2026": true, "january2027": true, "summer2026!!": true, "winter2026!!": true,
}

// CheckPassword says, in words a person can act on, why a password will not
// do, or nil. avoid are words it must not be built from: the person's
// address and name, the organisation's name.
func CheckPassword(password string, avoid ...string) error {
	if len(password) > MaxPasswordBytes {
		return errors.New("that password is too long")
	}
	n := 0
	for range password {
		n++
	}
	if n < MinPasswordLength {
		return fmt.Errorf("use at least %d characters; a few ordinary words strung together is easier to remember than a short mix of symbols", MinPasswordLength)
	}
	lower := strings.ToLower(password)
	if common[lower] {
		return errors.New("that password is one of the first anyone tries; choose another")
	}
	if allSame(password) || sequential(lower) {
		return errors.New("that password is a repeat or a run of keys; choose another")
	}
	for _, w := range avoid {
		w = strings.ToLower(strings.TrimSpace(w))
		// The local part of an address, a first name, a company: four or
		// more letters of it inside the password is a guess a stranger
		// makes on the first try.
		if at := strings.IndexByte(w, '@'); at > 0 {
			w = w[:at]
		}
		if len([]rune(w)) >= 4 && strings.Contains(lower, w) {
			return errors.New("do not build the password from your own name, address or your organisation's name")
		}
		for _, part := range strings.FieldsFunc(w, func(r rune) bool { return !unicode.IsLetter(r) }) {
			if len([]rune(part)) >= 5 && strings.Contains(lower, part) {
				return errors.New("do not build the password from your own name, address or your organisation's name")
			}
		}
	}
	return nil
}

func allSame(s string) bool {
	var first rune
	for i, r := range s {
		if i == 0 {
			first = r
			continue
		}
		if r != first {
			return false
		}
	}
	return true
}

// sequential catches 123456789012 and abcdefghijkl and their reverses.
func sequential(s string) bool {
	rs := []rune(s)
	if len(rs) < 8 {
		return false
	}
	up, down := true, true
	for i := 1; i < len(rs); i++ {
		if rs[i] != rs[i-1]+1 {
			up = false
		}
		if rs[i] != rs[i-1]-1 {
			down = false
		}
	}
	return up || down
}
