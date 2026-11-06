package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// T10: the end of a tenant. Deletion runs inside the database as a role
// nobody can log in as, through one function the operator may execute
// only once the tenant is suspended or exporting. The residue is counted
// afterwards and the offboarding is refused as incomplete if any remains.

var ErrNotSuspended = errors.New("directory: suspend the tenant (or mark it exporting) before offboarding it")

type Offboarding struct {
	TenantID uuid.UUID
	Slug     string
	Deleted  map[string]int64
	Residue  int64
}

func (o Offboarding) Total() int64 {
	var n int64
	for _, v := range o.Deleted {
		n += v
	}
	return n
}

func (d *Directory) Offboard(ctx context.Context, slug, by string) (Offboarding, error) {
	var id uuid.UUID
	var status string
	err := d.pool.QueryRow(ctx, `SELECT id, status FROM tenants WHERE slug = $1`, slug).Scan(&id, &status)
	if err != nil {
		return Offboarding{}, ErrNoSuchSlug
	}
	if status != "suspended" && status != "exporting" {
		return Offboarding{}, fmt.Errorf("%w: it is %s", ErrNotSuspended, status)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return Offboarding{}, err
	}
	defer tx.Rollback(ctx)

	out := Offboarding{TenantID: id, Slug: slug, Deleted: map[string]int64{}}
	rows, err := tx.Query(ctx, `SELECT table_name, deleted FROM app.offboard_tenant($1)`, id)
	if err != nil {
		if strings.Contains(err.Error(), "suspend it first") {
			return Offboarding{}, ErrNotSuspended
		}
		return Offboarding{}, err
	}
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			rows.Close()
			return Offboarding{}, err
		}
		out.Deleted[t] = n
	}
	rows.Close()

	// The proof, inside the same transaction: if anything is left, nothing
	// is committed and the operator is told which table.
	rows, err = tx.Query(ctx, `SELECT table_name, remaining FROM app.tenant_residue($1)`, id)
	if err != nil {
		return Offboarding{}, err
	}
	var left []string
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			rows.Close()
			return Offboarding{}, err
		}
		out.Residue += n
		if n > 0 {
			left = append(left, fmt.Sprintf("%s:%d", t, n))
		}
	}
	rows.Close()
	if out.Residue > 0 {
		return Offboarding{}, fmt.Errorf("directory: offboarding incomplete, rows remain in %s; nothing was committed", strings.Join(left, ", "))
	}
	deleted, _ := json.Marshal(out.Deleted)
	if _, err := tx.Exec(ctx, `
		INSERT INTO offboarding_log (tenant_id, slug, offboarded_by, deleted, residue)
		VALUES ($1, $2, $3, $4, $5)`, id, slug, by, deleted, out.Residue); err != nil {
		return Offboarding{}, err
	}
	return out, tx.Commit(ctx)
}

// Residue is the standing check: how many rows a tenant has in each table.
func (d *Directory) Residue(ctx context.Context, id uuid.UUID) (map[string]int64, error) {
	rows, err := d.pool.Query(ctx, `SELECT table_name, remaining FROM app.tenant_residue($1)`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}
