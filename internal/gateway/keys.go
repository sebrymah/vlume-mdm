package gateway

import (
	"context"
	"errors"
	"net/http"

	"platform/internal/data"
)

// T3: rotating a tenant's key.
//
// A new version is made and the old one retired, then every sealed value
// of THIS tenant's is opened under whatever sealed it and sealed again
// under the new version, in one transaction. Nothing of any other tenant's
// is read or written: the transaction's claim names one tenant and the
// rows are reached under row-level security. Retired versions stay
// readable, so a value this list somehow missed still opens; the audit
// record says how many values moved.

type resealed struct {
	Identity int `json:"identity"`
	Targets  int `json:"notification_targets"`
	DKIM     int `json:"sending_domains"`
	CA       int `json:"tenant_ca"`
}

func (g *Gateway) rotateKey(ctx context.Context, tx *data.Tx, by string) (int, resealed, error) {
	var out resealed
	if g.keys == nil {
		return 0, out, errors.New("gateway: this deployment has no keyring")
	}
	version, err := g.keys.Rotate(ctx, tx)
	if err != nil {
		return 0, out, err
	}
	reseal := func(table, keyCol, column string, counter *int) error {
		rows, err := tx.Query(ctx, "SELECT "+keyCol+", "+column+" FROM "+table+" WHERE length("+column+") > 0")
		if err != nil {
			return err
		}
		type row struct {
			key    string
			sealed []byte
		}
		var found []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.key, &r.sealed); err != nil {
				rows.Close()
				return err
			}
			found = append(found, r)
		}
		rows.Close()
		for _, r := range found {
			fresh, err := g.keys.Reseal(ctx, tx, r.sealed)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "UPDATE "+table+" SET "+column+" = $2 WHERE "+keyCol+"::text = $1", r.key, fresh); err != nil {
				return err
			}
			*counter++
		}
		return nil
	}
	if err := reseal("tenant_identity", "tenant_id", "client_secret_sealed", &out.Identity); err != nil {
		return 0, out, err
	}
	if err := reseal("notification_targets", "topic", "endpoint_sealed", &out.Targets); err != nil {
		return 0, out, err
	}
	if err := reseal("sending_domains", "domain", "dkim_private_sealed", &out.DKIM); err != nil {
		return 0, out, err
	}
	if err := reseal("tenant_ca", "tenant_id", "private_key_sealed", &out.CA); err != nil {
		return 0, out, err
	}
	return version, out, data.AppendAudit(ctx, tx, "keys.rotated",
		"version:"+itoa(version)+" resealed:"+itoa(out.Identity+out.Targets+out.DKIM+out.CA)+" by:"+by)
}

func (g *Gateway) apiRotateKey(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	var version int
	var moved resealed
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			version, moved, e = g.rotateKey(ctx, tx, res.Subject)
			return e
		})
	if err != nil {
		g.log.Error("key rotation", "tenant", res.Tenant.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "the key could not be rotated; nothing was changed")
		return
	}
	g.log.Info("tenant key rotated", "tenant", res.Tenant.Slug, "version", version, "by", res.Subject)
	writeJSON(w, http.StatusOK, map[string]any{"version": version, "resealed": moved})
}

func (g *Gateway) consoleRotateKey(w http.ResponseWriter, r *http.Request, res Resolution) {
	var version int
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			version, _, e = g.rotateKey(ctx, tx, res.Subject)
			return e
		})
	if err != nil {
		back(w, r, "/identity", "The key could not be rotated; nothing was changed.")
		return
	}
	back(w, r, "/identity", "Rotated. This tenant's values are sealed under key version "+itoa(version)+".")
}
