package directory

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/google/uuid"

	"platform/internal/secrets"
)

// T11: importing a move bundle on the destination region.
//
// One transaction. The tenant row, then every table's rows in an order
// foreign keys allow, each through app.import_tenant_row, which checks the
// row is this tenant's and the table is a tenant table. The tenant's keys
// come in under the transport key and go into the row under this region's
// master. Then the count: every table in the bundle has to hold here
// exactly the rows the manifest says it sent, or nothing is committed. A
// tenant that half-arrived is a tenant that answers some requests and not
// others, which is worse than one that has not arrived at all.

type ImportInput struct {
	// Transport opens the tenant's keys as the bundle carries them.
	Transport *secrets.AESSealer
	// Master seals them for this region's rows.
	Master *secrets.AESSealer
	// Region is this deployment's. The bundle's says where it came from.
	Region string
	By     string
}

type ImportReport struct {
	TenantID uuid.UUID
	Slug     string
	// Rows per table as the manifest said, and as landed. Equal, or the
	// import did not commit.
	Sent, Landed map[string]int
	FromRegion   string
}

var (
	ErrNotAMoveBundle   = errors.New("directory: this is an export, not a move bundle; a move bundle carries sealed values and is made from the Sign-in page with the destination's transport key")
	ErrImportMismatch   = errors.New("directory: the import does not add up; nothing was committed")
	ErrTenantExistsHere = errors.New("directory: a tenant with this id or slug already exists in this region")
)

type bundle struct {
	tenant struct {
		ID            uuid.UUID       `json:"id"`
		Name          string          `json:"name"`
		Slug          string          `json:"slug"`
		Plan          string          `json:"plan"`
		APIRatePerMin int             `json:"api_rate_per_min"`
		DeviceCap     int             `json:"device_cap"`
		AdminSeats    int             `json:"admin_seats"`
		Features      map[string]bool `json:"features"`
		Region        string          `json:"region"`
	}
	counts map[string]int
	rows   map[string][]json.RawMessage
}

func readBundle(b []byte) (*bundle, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("directory: not a zip: %w", err)
	}
	out := &bundle{counts: map[string]int{}, rows: map[string][]json.RawMessage{}}
	var sawManifest bool
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(io.LimitReader(rc, 1<<30))
		rc.Close()
		if err != nil {
			return nil, err
		}
		switch {
		case zf.Name == "manifest.json":
			var m struct {
				Move   bool           `json:"move"`
				Tables map[string]int `json:"tables"`
				Tenant json.RawMessage
			}
			if err := json.Unmarshal(content, &m); err != nil {
				return nil, fmt.Errorf("directory: manifest: %w", err)
			}
			if !m.Move {
				return nil, ErrNotAMoveBundle
			}
			if err := json.Unmarshal(m.Tenant, &out.tenant); err != nil {
				return nil, fmt.Errorf("directory: manifest tenant: %w", err)
			}
			out.counts = m.Tables
			sawManifest = true
		case strings.HasSuffix(zf.Name, ".jsonl"):
			table := strings.TrimSuffix(zf.Name, ".jsonl")
			sc := bufio.NewScanner(bytes.NewReader(content))
			sc.Buffer(make([]byte, 1<<20), 64<<20)
			for sc.Scan() {
				line := bytes.TrimSpace(sc.Bytes())
				if len(line) == 0 {
					continue
				}
				out.rows[table] = append(out.rows[table], json.RawMessage(append([]byte{}, line...)))
			}
			if err := sc.Err(); err != nil {
				return nil, fmt.Errorf("directory: %s: %w", zf.Name, err)
			}
		}
	}
	if !sawManifest {
		return nil, ErrNotAMoveBundle
	}
	if out.tenant.ID == uuid.Nil || out.tenant.Slug == "" {
		return nil, errors.New("directory: the manifest names no tenant")
	}
	return out, nil
}

// ImportTenant lands a move bundle here, whole or not at all.
func (d *Directory) ImportTenant(ctx context.Context, raw []byte, in ImportInput) (ImportReport, error) {
	var rep ImportReport
	if in.Transport == nil || in.Master == nil {
		return rep, errors.New("directory: an import needs the transport key and this region's master key")
	}
	b, err := readBundle(raw)
	if err != nil {
		return rep, err
	}
	rep.TenantID, rep.Slug, rep.FromRegion = b.tenant.ID, b.tenant.Slug, b.tenant.Region
	rep.Sent, rep.Landed = b.counts, map[string]int{}

	// The tables, in an order foreign keys allow: the reverse of the
	// deletion order the database already knows.
	var order []string
	if err := d.pool.QueryRow(ctx, `SELECT app.tenant_tables()`).Scan(&order); err != nil {
		return rep, err
	}
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	known := map[string]bool{}
	for _, t := range order {
		known[t] = true
	}
	for table := range b.rows {
		if !known[table] {
			return rep, fmt.Errorf("%w: %s is not a tenant table", ErrImportMismatch, table)
		}
	}

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return rep, err
	}
	defer tx.Rollback(ctx)

	region := strings.TrimSpace(in.Region)
	if region == "" {
		region = "eu-west"
	}
	features, _ := json.Marshal(b.tenant.Features)
	if len(features) == 0 || string(features) == "null" {
		features = []byte("{}")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO tenants (id, name, slug, plan, status, region, api_rate_per_min, device_cap, admin_seats, features)
		VALUES ($1, $2, $3, $4, 'suspended', $5, $6, $7, $8, $9::jsonb)`,
		b.tenant.ID, b.tenant.Name, b.tenant.Slug, b.tenant.Plan, region,
		b.tenant.APIRatePerMin, b.tenant.DeviceCap, b.tenant.AdminSeats, string(features))
	if isUnique(err) {
		return rep, ErrTenantExistsHere
	}
	if err != nil {
		return rep, err
	}

	for _, table := range order {
		for _, line := range b.rows[table] {
			row := line
			if table == "tenant_keys" {
				row, err = rewrapKey(line, in.Transport, in.Master)
				if err != nil {
					return rep, err
				}
			}
			if _, err := tx.Exec(ctx, `SELECT app.import_tenant_row($1, $2, $3::jsonb)`, b.tenant.ID, table, string(row)); err != nil {
				return rep, fmt.Errorf("%w: %s: %v", ErrImportMismatch, table, err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `SELECT app.import_tenant_finish($1)`, b.tenant.ID); err != nil {
		return rep, err
	}
	// The record, in the tenant's own audit log, chained after what it
	// brought.
	audit, _ := json.Marshal(map[string]any{
		"tenant_id": b.tenant.ID, "actor": in.By, "action": "tenant.imported",
		"object_ref": "from:" + b.tenant.Region + " to:" + region, "detail": map[string]any{},
	})
	if _, err := tx.Exec(ctx, `SELECT app.import_tenant_row($1, 'audit_events', $2::jsonb)`, b.tenant.ID, string(audit)); err != nil {
		return rep, err
	}

	// In versus out. Every table the manifest counted has to hold exactly
	// that many rows here (plus the one audit row above).
	rows, err := tx.Query(ctx, `SELECT table_name, remaining FROM app.tenant_residue($1)`, b.tenant.ID)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			rows.Close()
			return rep, err
		}
		rep.Landed[name] = int(n)
	}
	rows.Close()
	var bad []string
	for table, want := range b.counts {
		got := rep.Landed[table]
		if table == "audit_events" {
			got--
		}
		if got != want {
			bad = append(bad, fmt.Sprintf("%s: sent %d, landed %d", table, want, got))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return rep, fmt.Errorf("%w: %s", ErrImportMismatch, strings.Join(bad, "; "))
	}
	if err := tx.Commit(ctx); err != nil {
		return rep, err
	}
	return rep, nil
}

// rewrapKey takes a tenant_keys row from under the transport key to under
// this region's master. The plaintext exists for the length of this call.
func rewrapKey(line json.RawMessage, transport, master *secrets.AESSealer) (json.RawMessage, error) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, err
	}
	s, _ := m["key_sealed"].(string)
	if !strings.HasPrefix(s, "\\x") {
		return nil, errors.New("directory: tenant_keys.key_sealed is not a bytea value")
	}
	under, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, err
	}
	plain, err := transport.Open(under)
	if err != nil {
		return nil, fmt.Errorf("directory: tenant key version %v does not open under the transport key: %w", m["version"], err)
	}
	sealed, err := master.Seal(plain)
	if err != nil {
		return nil, err
	}
	m["key_sealed"] = "\\x" + hex.EncodeToString(sealed)
	return json.Marshal(m)
}
