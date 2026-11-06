package data

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// F11: the disk-encryption recovery key, escrowed sealed and revealed on
// purpose. This package stores bytes it cannot read; the sealing is the
// caller's, under the tenant's key, so the row is useless without it.

var ErrNoRecoveryKey = errors.New("data: no recovery key is escrowed for that device")

type RecoveryKeyStatus struct {
	Kind           string
	EscrowedAt     time.Time
	RevealedCount  int
	LastRevealedAt *time.Time
}

func EscrowRecoveryKey(ctx context.Context, tx *Tx, deviceID uuid.UUID, kind string, sealed []byte) error {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "filevault", "bitlocker":
	default:
		kind = "other"
	}
	if len(sealed) == 0 {
		return errors.New("data: nothing to escrow")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_recovery_keys (tenant_id, device_id, kind, key_sealed)
		VALUES (app.current_tenant(), $1, $2, $3)
		ON CONFLICT (tenant_id, device_id) DO UPDATE SET
		  kind = excluded.kind, key_sealed = excluded.key_sealed, escrowed_at = now()`,
		deviceID, kind, sealed); err != nil {
		return err
	}
	return AppendAudit(ctx, tx, "recovery_key.escrowed", "device:"+deviceID.String()+" kind:"+kind)
}

func RecoveryKeyStatusOf(ctx context.Context, tx *Tx, deviceID uuid.UUID) (RecoveryKeyStatus, bool, error) {
	var s RecoveryKeyStatus
	err := tx.QueryRow(ctx, `
		SELECT kind, escrowed_at, revealed_count, last_revealed_at
		  FROM device_recovery_keys WHERE device_id = $1`, deviceID).Scan(
		&s.Kind, &s.EscrowedAt, &s.RevealedCount, &s.LastRevealedAt)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return RecoveryKeyStatus{}, false, nil
		}
		return RecoveryKeyStatus{}, false, err
	}
	return s, true, nil
}

// RevealRecoveryKey hands back the sealed bytes and records the look: the
// count on the row, and the audit record with who and why. The caller
// opens the seal; this package never sees the key.
func RevealRecoveryKey(ctx context.Context, tx *Tx, deviceID uuid.UUID, by, reason string) ([]byte, string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, "", errors.New("data: a reason is required to reveal a recovery key")
	}
	var sealed []byte
	var kind string
	err := tx.QueryRow(ctx, `
		UPDATE device_recovery_keys
		   SET revealed_count = revealed_count + 1, last_revealed_at = now()
		 WHERE device_id = $1
		 RETURNING key_sealed, kind`, deviceID).Scan(&sealed, &kind)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, "", ErrNoRecoveryKey
		}
		return nil, "", err
	}
	return sealed, kind, AppendAudit(ctx, tx, "recovery_key.revealed",
		"device:"+deviceID.String()+" by:"+by+" reason:"+clip(reason, 200))
}
