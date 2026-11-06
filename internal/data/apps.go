package data

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// F3: the installed-app inventory, one row per app per device, replaced on
// every report that carries a list.

type App struct {
	Identifier string
	Name       string
	Version    string
	SeenAt     time.Time
}

const maxApps = 2000

// ReplaceApps makes the table say what the device just said. An app the
// device no longer lists is gone from the row set, which is the point of
// an inventory rather than a history.
func ReplaceApps(ctx context.Context, tx *Tx, deviceID uuid.UUID, apps []App, now time.Time) error {
	if _, err := tx.Exec(ctx, `DELETE FROM device_apps WHERE device_id = $1`, deviceID); err != nil {
		return err
	}
	seen := map[string]bool{}
	n := 0
	for _, a := range apps {
		id := strings.TrimSpace(a.Identifier)
		name := strings.TrimSpace(a.Name)
		if id == "" {
			id = strings.ToLower(name)
		}
		if id == "" || seen[id] {
			continue
		}
		if name == "" {
			name = id
		}
		seen[id] = true
		if n++; n > maxApps {
			break
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_apps (tenant_id, device_id, identifier, name, version, seen_at)
			VALUES (app.current_tenant(), $1, $2, $3, $4, $5)`,
			deviceID, clip(id, 200), clip(name, 200), clip(strings.TrimSpace(a.Version), 80), now); err != nil {
			return err
		}
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func AppsOf(ctx context.Context, tx *Tx, deviceID uuid.UUID) ([]App, error) {
	rows, err := tx.Query(ctx, `
		SELECT identifier, name, version, seen_at FROM device_apps
		 WHERE device_id = $1 ORDER BY lower(name)`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []App{}
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.Identifier, &a.Name, &a.Version, &a.SeenAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AppHolder is one device that has an app: the fleet-wide answer to
// "who has this".
type AppHolder struct {
	DeviceID   uuid.UUID
	DeviceName string
	Serial     string
	AssignedTo string
	Name       string
	Version    string
}

// FindApp searches the fleet by app name (substring, case-insensitive).
func FindApp(ctx context.Context, tx *Tx, query string, limit int) ([]AppHolder, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return []AppHolder{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	rows, err := tx.Query(ctx, `
		SELECT d.id, d.name, d.serial, d.assigned_to, a.name, a.version
		  FROM device_apps a JOIN devices d ON d.id = a.device_id
		 WHERE lower(a.name) LIKE '%' || lower($1) || '%' OR lower(a.identifier) LIKE '%' || lower($1) || '%'
		 ORDER BY a.name, a.version, d.name LIMIT $2`, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppHolder{}
	for rows.Next() {
		var h AppHolder
		if err := rows.Scan(&h.DeviceID, &h.DeviceName, &h.Serial, &h.AssignedTo, &h.Name, &h.Version); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
