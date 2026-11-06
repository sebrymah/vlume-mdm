package platformkeys

import (
	"context"
	"strings"
	"time"
)

// Re-reading the keys while running (0044). A rotated master or signing
// key used to reach the gateway at its next start; now the source is read
// again on a timer, and on SIGHUP, and a set that differs is handed to the
// signers and the keyring, which keep the key before it for what it
// signed or sealed. A set that fails the same checks as at start is logged
// and not applied: the keys that are running keep running.

// Fingerprint is the keys as an identity, never their bytes: changed when
// any of them changed.
func (k Keys) Fingerprint() string {
	parts := []string{fingerprint(k.Claim), fingerprint(k.Session), fingerprint(k.Sealing)}
	if k.SealingPrevious != nil {
		parts = append(parts, fingerprint(k.SealingPrevious))
	}
	return strings.Join(parts, ".")
}

// Watch reads the source every interval, and whenever reload says to, and
// calls apply with a set of keys that differs from the one running. It
// returns when ctx ends. The control --break-keysdiffer lets a set with
// one key doing three jobs through Load, and so through here.
func Watch(ctx context.Context, src Source, every time.Duration, reload <-chan struct{},
	running Keys, apply func(Keys) error, log interface {
		Info(string, ...any)
		Error(string, ...any)
	}) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	current := running.Fingerprint()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		case <-reload:
		}
		keys, err := Load(ctx, src)
		if err != nil {
			log.Error("platform keys could not be re-read; the running keys stay", "err", err)
			continue
		}
		if keys.Fingerprint() == current {
			continue
		}
		if err := apply(keys); err != nil {
			log.Error("platform keys were re-read but could not be applied; the running keys stay", "err", err)
			continue
		}
		current = keys.Fingerprint()
		log.Info("platform keys rotated while running", "keys", keys.Describe())
	}
}
