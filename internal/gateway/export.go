package gateway

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/secrets"
)

// T10: the export. Everything the tenant has, as one zip of JSON lines per
// table, read under the tenant's own claim, audited, for the Super Admin.
// Secrets do not travel: every sealed column, every token hash and every
// one-time code is replaced with a marker, because an export is a file
// that will be emailed, and a file that will be emailed is not a vault.

var exportTables = []string{
	"devices", "device_compliance", "device_certificates", "enrolments", "policies",
	"commands", "command_approvals", "audit_events", "notifications", "notification_targets",
	"sending_domains", "tenant_branding", "tenant_identity", "tenant_role_map",
	"integration_tokens", "android_enterprises", "android_enrollment_tokens", "siem_cursors",
	"tenant_keys", "device_apps", "device_recovery_keys", "command_signing_keys",
}

// redacted names the columns that never leave: anything sealed, hashed or
// one-time.
func redacted(column string) bool {
	switch {
	case strings.HasSuffix(column, "_sealed"), strings.HasSuffix(column, "_hash"),
		column == "nonce", column == "signature", column == "private_key_sealed":
		return true
	}
	return false
}

func (g *Gateway) exportTenant(ctx context.Context, tx *data.Tx, by string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	counts := map[string]int{}
	for _, table := range exportTables {
		w, err := zw.Create(table + ".jsonl")
		if err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT row_to_json(t)::text FROM %s t`, table))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return nil, err
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				rows.Close()
				return nil, err
			}
			for k := range m {
				if redacted(k) {
					m[k] = "[not exported]"
				}
			}
			line, _ := json.Marshal(m)
			if _, err := w.Write(append(line, '\n')); err != nil {
				rows.Close()
				return nil, err
			}
			counts[table]++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", table, err)
		}
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"exported_at": time.Now().UTC(), "exported_by": by, "tables": counts,
		"note": "Sealed secrets, token hashes and one-time codes are not exported.",
	}, "", "  ")
	w, err := zw.Create("manifest.json")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(manifest); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := data.AppendAudit(ctx, tx, "tenant.exported", fmt.Sprintf("tables:%d bytes:%d by:%s", len(counts), buf.Len(), by)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (g *Gateway) apiExport(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	var body []byte
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			body, e = g.exportTenant(ctx, tx, res.Subject)
			return e
		})
	if err != nil {
		g.log.Error("export", "tenant", res.Tenant.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "the export could not be made")
		return
	}
	g.log.Info("tenant exported", "tenant", res.Tenant.Slug, "by", res.Subject, "bytes", len(body))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-export-%s.zip"`,
		res.Tenant.Slug, time.Now().UTC().Format("2006-01-02")))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// ---------------------------------------------------------------- the move

// T11: a move bundle. The export above is for leaving or keeping, and
// secrets stay behind. A move is for continuing somewhere else: every
// table, sealed values intact (they are under the tenant's own key, and
// are nothing without it), and the tenant's keys re-sealed under a
// transport key the destination operator chose and handed to this
// tenant's Super Admin out of band. The master key never travels; the
// destination re-seals the tenant's keys under its own.

var moveTables = append(append([]string{}, exportTables...), "tenant_ca", "tenant_domains", "tenant_admins")

// TransportKeySize is what the destination's tenantctl move-key makes.
const TransportKeySize = 32

func (g *Gateway) moveBundle(ctx context.Context, tx *data.Tx, tenant directory.Tenant, by string,
	transport *secrets.AESSealer) ([]byte, error) {

	if g.keys == nil {
		return nil, errors.New("a move needs the keyring")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	counts := map[string]int{}
	for _, table := range moveTables {
		w, err := zw.Create(table + ".jsonl")
		if err != nil {
			return nil, err
		}
		order := ""
		if table == "audit_events" || table == "command_approvals" {
			// Serial ids: in order, so the destination's audit chain is
			// rebuilt in the order it was written.
			order = " ORDER BY id"
		}
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT row_to_json(t)::text FROM %s t%s`, table, order))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return nil, err
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				rows.Close()
				return nil, err
			}
			if table == "tenant_keys" {
				sealed, err := byteaFromJSON(m["key_sealed"])
				if err != nil {
					rows.Close()
					return nil, err
				}
				plain, err := g.keys.OpenMaster(sealed)
				if err != nil {
					rows.Close()
					return nil, fmt.Errorf("tenant key version %v: %w", m["version"], err)
				}
				under, err := transport.Seal(plain)
				if err != nil {
					rows.Close()
					return nil, err
				}
				m["key_sealed"] = byteaToJSON(under)
			}
			line, _ := json.Marshal(m)
			if _, err := w.Write(append(line, '\n')); err != nil {
				rows.Close()
				return nil, err
			}
			counts[table]++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", table, err)
		}
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"move": true, "exported_at": time.Now().UTC(), "exported_by": by, "tables": counts,
		"tenant": map[string]any{
			"id": tenant.ID, "name": tenant.Name, "slug": tenant.Slug, "plan": tenant.Plan,
			"api_rate_per_min": tenant.APIRatePerMin, "device_cap": tenant.DeviceCap,
			"admin_seats": tenant.AdminSeats, "features": tenant.Features, "region": tenant.Region,
		},
		"note": "A move bundle. Sealed values are under the tenant's own key; the tenant's keys are under the transport key the destination chose.",
	}, "", "  ")
	w, err := zw.Create("manifest.json")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(manifest); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := data.AppendAudit(ctx, tx, "tenant.move_exported", fmt.Sprintf("tables:%d bytes:%d by:%s", len(counts), buf.Len(), by)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// byteaFromJSON reads PostgreSQL's row_to_json spelling of bytea: a
// string of hex with a \x in front.
func byteaFromJSON(v any) ([]byte, error) {
	s, _ := v.(string)
	if !strings.HasPrefix(s, "\\x") {
		return nil, errors.New("not a bytea value")
	}
	return hex.DecodeString(s[2:])
}

func byteaToJSON(b []byte) string { return "\\x" + hex.EncodeToString(b) }

// apiMoveExport makes the bundle for the Super Admin, with the transport
// key the destination handed them. The key is read from the body and
// never stored: it is the destination's, and this side needs it for the
// length of one request.
func (g *Gateway) apiMoveExport(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	var in struct {
		TransportKey string `json:"transport_key"`
	}
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		in.TransportKey = r.FormValue("transport_key")
	} else if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "a JSON body with transport_key is needed")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.TransportKey))
	if err != nil || len(raw) != TransportKeySize {
		writeError(w, http.StatusBadRequest, "transport_key is the base64 of the 32-byte key the destination gave you (tenantctl move-key)")
		return
	}
	transport, err := secrets.NewAESSealer(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var body []byte
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			body, e = g.moveBundle(ctx, tx, res.Tenant, res.Subject, transport)
			return e
		})
	if err != nil {
		g.log.Error("move export", "tenant", res.Tenant.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "the move bundle could not be made")
		return
	}
	g.log.Info("tenant move bundle made", "tenant", res.Tenant.Slug, "by", res.Subject, "bytes", len(body))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-move-%s.zip"`,
		res.Tenant.Slug, time.Now().UTC().Format("2006-01-02")))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
