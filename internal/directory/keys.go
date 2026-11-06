package directory

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// T3: rotating the master key, from the operator's side.
//
// The operator's role cannot read tenant_keys; the two functions 0033
// gives it can, and nothing else. The plaintext of a tenant key exists
// only inside the tool for the length of one call to reseal, and this
// package never sees it: it moves ciphertext in and ciphertext out.

// KeyBlob is one tenant key as stored: ciphertext under some master.
type KeyBlob struct {
	TenantID uuid.UUID
	Version  int
	Sealed   []byte
	Retired  bool
}

// ResealReport is the in-vs-out block of a run.
type ResealReport struct {
	Total          int
	Resealed       int
	AlreadyCurrent int
}

var ErrKeyChangedUnderneath = errors.New("directory: a tenant key changed while the rotation ran")

// KeyBlobs lists every tenant key's ciphertext, every tenant, every
// version, retired ones included: a retired version still opens old
// values and has to move with the rest.
func (d *Directory) KeyBlobs(ctx context.Context) ([]KeyBlob, error) {
	rows, err := d.pool.Query(ctx, `SELECT tenant_id, version, key_sealed, retired FROM app.tenant_key_blobs()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyBlob
	for rows.Next() {
		var b KeyBlob
		if err := rows.Scan(&b.TenantID, &b.Version, &b.Sealed, &b.Retired); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ResealMasterKeys runs one rotation: every tenant key through reseal, in
// one transaction. A key that reseal cannot handle halts the run and the
// transaction rolls back, so the database is either entirely under the new
// master or exactly as it was; there is no half-rotated state for a
// restart to find. Each write is compare-and-swap on the ciphertext read,
// so a key changed by anything else while the run was going is a halt too.
func (d *Directory) ResealMasterKeys(ctx context.Context,
	reseal func(sealed []byte) (resealed []byte, already bool, err error)) (ResealReport, error) {

	var rep ResealReport
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return rep, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT tenant_id, version, key_sealed, retired FROM app.tenant_key_blobs()`)
	if err != nil {
		return rep, err
	}
	var blobs []KeyBlob
	for rows.Next() {
		var b KeyBlob
		if err := rows.Scan(&b.TenantID, &b.Version, &b.Sealed, &b.Retired); err != nil {
			rows.Close()
			return rep, err
		}
		blobs = append(blobs, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}
	rep.Total = len(blobs)

	for _, b := range blobs {
		moved, already, err := reseal(b.Sealed)
		if err != nil {
			return ResealReport{}, fmt.Errorf("directory: tenant %s key version %d: %w; nothing was changed", b.TenantID, b.Version, err)
		}
		if already {
			rep.AlreadyCurrent++
			continue
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT app.reseal_tenant_key($1, $2, $3, $4)`,
			b.TenantID, b.Version, b.Sealed, moved).Scan(&ok); err != nil {
			return ResealReport{}, err
		}
		if !ok {
			return ResealReport{}, fmt.Errorf("%w: tenant %s version %d; nothing was changed", ErrKeyChangedUnderneath, b.TenantID, b.Version)
		}
		rep.Resealed++
	}
	if err := tx.Commit(ctx); err != nil {
		return ResealReport{}, err
	}
	return rep, nil
}

// VerifyMasterKeys says which tenant keys do not open under the current
// master alone: after a rotation, the answer has to be none before the
// previous master is taken out of the configuration.
func (d *Directory) VerifyMasterKeys(ctx context.Context, open func(sealed []byte) error) (total int, failing []string, err error) {
	blobs, err := d.KeyBlobs(ctx)
	if err != nil {
		return 0, nil, err
	}
	for _, b := range blobs {
		if err := open(b.Sealed); err != nil {
			failing = append(failing, fmt.Sprintf("tenant %s version %d", b.TenantID, b.Version))
		}
	}
	return len(blobs), failing, nil
}
