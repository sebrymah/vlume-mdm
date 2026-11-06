package data

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The hardware addresses a device reports (0039). A network access control
// knows a device by the address it authenticated with, so the door answers
// by MAC as well as by serial.

// maxMACs bounds what one report may claim. A laptop has a handful of
// interfaces; a report naming hundreds is not describing a laptop.
const maxMACs = 16

var macDigits = regexp.MustCompile(`^[0-9a-f]{12}$`)

// NormaliseMAC turns any of the ways a MAC is written into the one the
// table holds: aa:bb:cc:dd:ee:ff. Cisco's aabb.ccdd.eeff, Windows'
// AA-BB-CC-DD-EE-FF and bare aabbccddeeff all arrive from real equipment.
// Anything that is not twelve hex digits once the separators are gone is
// not a MAC and is refused rather than guessed at.
func NormaliseMAC(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s)
	if !macDigits.MatchString(s) {
		return "", false
	}
	// Not an address anybody has: all zeros, or the broadcast address.
	if s == "000000000000" || s == "ffffffffffff" {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String(), true
}

// ReplaceMACs records what a device reported, in place of what it
// reported before.
//
// An address another device of this tenant holds is NOT simply taken: a
// report is the device's own word, and a word that could move a clean
// laptop's address onto a quarantined one would let the quarantined one
// borrow the clean one's answer at the door. The address moves only when
// its holder has let go of it: the holder is retired, or has not reported
// within maxAge (the engine's own limit), and never from a device in
// quarantine. A holder that is reporting and still lists the address keeps
// it, and the claim is written down (device.mac_contested) for a person to
// look at. The common honest case, a dock moved between laptops, needs no
// contest: the first laptop's next report no longer lists the dock, the
// row goes, and the second laptop's claim lands on nothing.
func ReplaceMACs(ctx context.Context, tx *Tx, deviceID uuid.UUID, macs []string, now time.Time, maxAge time.Duration) error {
	keep := make([]string, 0, len(macs))
	seen := map[string]bool{}
	for _, m := range macs {
		n, ok := NormaliseMAC(m)
		if !ok || seen[n] {
			continue
		}
		seen[n] = true
		keep = append(keep, n)
		if len(keep) >= maxMACs {
			break
		}
	}
	// Addresses this device no longer reports are forgotten.
	if _, err := tx.Exec(ctx, `
		DELETE FROM device_macs WHERE device_id = $1 AND NOT (mac = ANY($2::text[]))`,
		deviceID, keep); err != nil {
		return err
	}
	for _, mac := range keep {
		var previous *uuid.UUID
		var holderState string
		var holderLast *time.Time
		err := tx.QueryRow(ctx, `
			SELECT m.device_id, d.state, d.last_report_at
			  FROM device_macs m JOIN devices d ON d.id = m.device_id
			 WHERE m.mac = $1 AND m.device_id <> $2`,
			mac, deviceID).Scan(&previous, &holderState, &holderLast)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if previous != nil {
			letGo := holderState == "retired" ||
				(holderState != "quarantined" && (holderLast == nil || now.Sub(*holderLast) > maxAge))
			if !letGo {
				if err := AppendAudit(ctx, tx, "device.mac_contested",
					"mac:"+mac+" held_by:"+previous.String()+" claimed_by:"+deviceID.String()); err != nil {
					return err
				}
				continue
			}
			if err := AppendAudit(ctx, tx, "device.mac_moved",
				"mac:"+mac+" from:"+previous.String()+" to:"+deviceID.String()); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_macs (tenant_id, device_id, mac, first_seen, last_seen)
			VALUES (app.current_tenant(), $1, $2, $3, $3)
			ON CONFLICT (tenant_id, mac) DO UPDATE
			   SET device_id = excluded.device_id,
			       last_seen = excluded.last_seen,
			       first_seen = CASE WHEN device_macs.device_id = excluded.device_id
			                         THEN device_macs.first_seen ELSE excluded.first_seen END`,
			deviceID, mac, now); err != nil {
			return err
		}
	}
	return nil
}

// MACsOf lists a device's addresses, for its page.
func MACsOf(ctx context.Context, tx *Tx, deviceID uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT mac FROM device_macs WHERE device_id = $1 ORDER BY mac`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeviceByMAC finds the device that reported an address. Not found is
// not an error: it is the network's question answered "unknown".
func DeviceByMAC(ctx context.Context, tx *Tx, mac string) (uuid.UUID, bool, error) {
	n, ok := NormaliseMAC(mac)
	if !ok {
		return uuid.Nil, false, nil
	}
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT device_id FROM device_macs WHERE mac = $1`, n).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return id, true, nil
}

// MACsByDevice is every device's addresses in one read, for the report.
func MACsByDevice(ctx context.Context, tx *Tx) (map[uuid.UUID][]string, error) {
	rows, err := tx.Query(ctx, `SELECT device_id, mac FROM device_macs ORDER BY device_id, mac`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID][]string{}
	for rows.Next() {
		var id uuid.UUID
		var mac string
		if err := rows.Scan(&id, &mac); err != nil {
			return nil, err
		}
		out[id] = append(out[id], mac)
	}
	return out, rows.Err()
}
