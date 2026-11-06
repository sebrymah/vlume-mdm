// Package platformkeys is where the platform's own secrets come from.
//
// Three keys, three jobs: the claim signer, the session signer and the
// master sealing key, plus the master being rotated out while tenantctl
// reseal-master runs. Until this package they were literals in the
// environment. The environment is still a source, because a developer's
// laptop has no vault, but it is the one the gateway warns about at start;
// a deployment takes them from a key directory (what Kubernetes, Docker
// and systemd mount a secret as) or from HashiCorp Vault's KV store.
//
// Whatever the source, the keys are checked the same way before anything
// runs: long enough, the sealing keys exactly thirty-two bytes, and the
// three different from each other, because one key doing three jobs is
// one compromise doing three. And whatever the source, the bytes are never
// written anywhere: the start-up line says where they came from and a
// fingerprint, so an operator can tell which key is in use without ever
// seeing it.
package platformkeys

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The names every source uses. In the environment they are the MDM_
// variables below; in a key directory, files of these names; in a vault,
// fields of one secret.
const (
	ClaimName           = "claim_signing_key"
	SessionName         = "session_signing_key"
	SealingName         = "sealing_key"
	SealingPreviousName = "sealing_key_previous"
)

var envNames = map[string]string{
	ClaimName:           "MDM_CLAIM_SIGNING_KEY",
	SessionName:         "MDM_SESSION_SIGNING_KEY",
	SealingName:         "MDM_SEALING_KEY",
	SealingPreviousName: "MDM_SEALING_KEY_PREVIOUS",
}

// ErrNotFound is a secret the source does not hold.
var ErrNotFound = errors.New("platformkeys: not set")

// Source reads one named secret.
type Source interface {
	// Name says what kind of source this is, for the start-up line.
	Name() string
	// Read returns the secret, or ErrNotFound.
	Read(ctx context.Context, name string) ([]byte, error)
	// Where says where a person would set the named secret for this
	// source, for an error that tells them what to do.
	Where(name string) string
}

// Keys are the platform's secrets, checked.
type Keys struct {
	Claim   []byte
	Session []byte
	Sealing []byte
	// SealingPrevious is the master being rotated out, nil when none is.
	SealingPrevious []byte
	// From is the source's name, for the start-up line.
	From string
}

// Load reads and checks every platform key.
func Load(ctx context.Context, src Source) (Keys, error) {
	k := Keys{From: src.Name()}
	var err error
	if k.Claim, err = required(ctx, src, ClaimName, 32, false); err != nil {
		return Keys{}, err
	}
	if k.Session, err = required(ctx, src, SessionName, 32, false); err != nil {
		return Keys{}, err
	}
	if k.Sealing, k.SealingPrevious, err = LoadSealing(ctx, src); err != nil {
		return Keys{}, err
	}
	// Three keys, three jobs. The same bytes under two names is one key
	// doing two jobs, which is what the three names exist to prevent.
	if string(k.Claim) == string(k.Session) || string(k.Claim) == string(k.Sealing) ||
		string(k.Session) == string(k.Sealing) {
		return Keys{}, errors.New("platformkeys: the claim, session and sealing keys must be three different keys")
	}
	return k, nil
}

// LoadSealing reads the sealing master and, if one is set, the master
// being rotated out. tenantctl and sealsecret need these two and nothing
// else, and must not have to be given the signing keys to run.
func LoadSealing(ctx context.Context, src Source) (current, previous []byte, err error) {
	if current, err = required(ctx, src, SealingName, 32, true); err != nil {
		return nil, nil, err
	}
	previous, err = src.Read(ctx, SealingPreviousName)
	switch {
	case errors.Is(err, ErrNotFound):
		return current, nil, nil
	case err != nil:
		return nil, nil, fmt.Errorf("platformkeys: %s: %w", SealingPreviousName, err)
	}
	if len(previous) != 32 {
		return nil, nil, fmt.Errorf("platformkeys: %s must be exactly 32 bytes, got %d (set at %s)",
			SealingPreviousName, len(previous), src.Where(SealingPreviousName))
	}
	if string(previous) == string(current) {
		return nil, nil, fmt.Errorf("platformkeys: %s is the same key as %s; a master being rotated out is a different key",
			SealingPreviousName, SealingName)
	}
	return current, previous, nil
}

func required(ctx context.Context, src Source, name string, size int, exact bool) ([]byte, error) {
	v, err := src.Read(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("platformkeys: %s is not set; set it at %s", name, src.Where(name))
	}
	if err != nil {
		return nil, fmt.Errorf("platformkeys: %s: %w", name, err)
	}
	switch {
	case exact && len(v) != size:
		return nil, fmt.Errorf("platformkeys: %s must be exactly %d bytes, got %d (set at %s)",
			name, size, len(v), src.Where(name))
	case !exact && len(v) < size:
		return nil, fmt.Errorf("platformkeys: %s must be at least %d bytes, got %d (set at %s)",
			name, size, len(v), src.Where(name))
	}
	return v, nil
}

// Describe is the start-up line: where the keys came from, and a
// fingerprint of each so an operator can tell which key is in use. Never
// the bytes, and never enough of a hash to work backwards from.
func (k Keys) Describe() string {
	prev := "none"
	if k.SealingPrevious != nil {
		prev = describe("previous master", k.SealingPrevious)
	}
	return fmt.Sprintf("from %s: %s; %s; %s; %s", k.From,
		describe("claim", k.Claim), describe("session", k.Session),
		describe("sealing", k.Sealing), prev)
}

func describe(name string, v []byte) string {
	return fmt.Sprintf("%s %d bytes, fingerprint %s", name, len(v), fingerprint(v))
}

// fingerprint is the first four bytes of the SHA-256: enough to tell two
// keys apart, far too little to find one.
func fingerprint(v []byte) string {
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:4])
}

// decode reads a secret's text. A value written as base64:... is decoded,
// which is how a key of arbitrary bytes is kept in a vault field or an
// environment variable that can only hold text; anything else is the
// bytes as given, with one trailing line break removed, because a file
// written by an editor ends in one and a key does not.
func decode(text string) ([]byte, error) {
	if strings.HasPrefix(text, "base64:") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(text, "base64:")))
		if err != nil {
			return nil, fmt.Errorf("the value is marked base64 but does not decode: %w", err)
		}
		return b, nil
	}
	text = strings.TrimSuffix(text, "\n")
	text = strings.TrimSuffix(text, "\r")
	return []byte(text), nil
}

// ---------------------------------------------------------------- sources

// Env reads the MDM_ variables. The source a laptop uses, and the one the
// gateway warns about.
type Env struct {
	Getenv func(string) string
}

func (Env) Name() string { return "the environment" }

func (e Env) Where(name string) string { return envNames[name] + " in the environment" }

func (e Env) Read(_ context.Context, name string) ([]byte, error) {
	v := e.Getenv(envNames[name])
	if v == "" {
		return nil, ErrNotFound
	}
	return decode(v)
}

// Files reads one file per key from a directory: the shape Kubernetes,
// Docker and systemd give a mounted secret. Each file must be readable by
// its owner alone, which is how a key file is told apart from a file that
// happens to hold a key: Kubernetes sets that with defaultMode: 0400 on
// the volume, systemd credentials come that way, and a file left at 0644
// is refused by name rather than read.
type Files struct {
	Dir string
}

func (f Files) Name() string { return "the key directory " + f.Dir }

func (f Files) Where(name string) string { return filepath.Join(f.Dir, name) }

func (f Files) Read(_ context.Context, name string) ([]byte, error) {
	path := filepath.Join(f.Dir, name)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %04o); a key file is owner-only (chmod 0400, or defaultMode: 0400 on the volume)",
			path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decode(string(b))
}

// ------------------------------------------------------------- choosing

// Choose picks the source the deployment named in MDM_KEY_SOURCE: "env"
// (the default), "files" (MDM_KEY_DIR, default /run/secrets) or "vault"
// (the MDM_VAULT_ variables, see Vault). A name this build does not know
// is refused rather than falling back to the environment: a deployment
// that asked for a vault and got the environment would be running on
// keys nobody meant it to.
func Choose(getenv func(string) string) (Source, error) {
	switch strings.TrimSpace(strings.ToLower(getenv("MDM_KEY_SOURCE"))) {
	case "", "env", "environment":
		return Env{Getenv: getenv}, nil
	case "files", "dir", "directory":
		dir := getenv("MDM_KEY_DIR")
		if dir == "" {
			dir = "/run/secrets"
		}
		return Files{Dir: dir}, nil
	case "vault":
		v := &Vault{
			Addr:         getenv("MDM_VAULT_ADDR"),
			Path:         getenv("MDM_VAULT_PATH"),
			Namespace:    getenv("MDM_VAULT_NAMESPACE"),
			TokenFile:    getenv("MDM_VAULT_TOKEN_FILE"),
			RoleID:       getenv("MDM_VAULT_ROLE_ID"),
			SecretIDFile: getenv("MDM_VAULT_SECRET_ID_FILE"),
			CAFile:       getenv("MDM_VAULT_CA_FILE"),
		}
		if err := v.check(); err != nil {
			return nil, err
		}
		return v, nil
	}
	return nil, fmt.Errorf("platformkeys: MDM_KEY_SOURCE=%q is not a source this build knows; it is env, files or vault",
		getenv("MDM_KEY_SOURCE"))
}
