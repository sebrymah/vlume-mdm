package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"platform/internal/console"
	"platform/internal/data"
)

// F3: who has what. F11: the recovery key, escrowed and revealed on purpose.

func (g *Gateway) deviceApps(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var apps []data.App
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if _, derr := data.GetDevice(ctx, tx, id); derr != nil {
				return data.ErrNoSuchDevice
			}
			var aerr error
			apps, aerr = data.AppsOf(ctx, tx, id)
			return aerr
		})
	if errors.Is(err, data.ErrNoSuchDevice) {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the apps")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

func (g *Gateway) findApp(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("name"))
	var found []data.AppHolder
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var ferr error
			found, ferr = data.FindApp(ctx, tx, q, 200)
			return ferr
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not search")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "devices": found})
}

func (g *Gateway) consoleApps(w http.ResponseWriter, r *http.Request, s console.Session) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	g.console.AppsPage(w, r, s, q, func(ctx context.Context, tx *data.Tx) ([]data.AppHolder, error) {
		return data.FindApp(ctx, tx, q, 200)
	})
}

// ---------------------------------------------------------------- escrow

type escrowInput struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

// escrowKey is the device handing its recovery key up. Sealed under the
// tenant's key before the row sees it.
func (g *Gateway) escrowKey(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	if res.Source != "device_certificate" {
		writeError(w, http.StatusForbidden, "only a device may escrow its own recovery key")
		return
	}
	var in escrowInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil ||
		strings.TrimSpace(in.Key) == "" {
		writeError(w, http.StatusBadRequest, "a kind and a key are needed")
		return
	}
	if g.sealer == nil {
		writeError(w, http.StatusInternalServerError, "this deployment has no sealing key")
		return
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			sealed, serr := g.sealer.Seal(ctx, tx, []byte(strings.TrimSpace(in.Key)))
			if serr != nil {
				return serr
			}
			return data.EscrowRecoveryKey(ctx, tx, res.DeviceID, in.Kind, sealed)
		})
	if err != nil {
		g.log.Error("escrow", "device", res.DeviceID, "err", err)
		writeError(w, http.StatusInternalServerError, "the key could not be escrowed")
		return
	}
	g.log.Info("recovery key escrowed", "tenant", res.Tenant.Slug, "device", res.DeviceID, "kind", in.Kind)
	writeJSON(w, http.StatusOK, map[string]any{"escrowed": true})
}

func (g *Gateway) reveal(ctx context.Context, tx *data.Tx, id uuid.UUID, by, reason string) (string, string, error) {
	sealed, kind, err := data.RevealRecoveryKey(ctx, tx, id, by, reason)
	if err != nil {
		return "", "", err
	}
	open, err := g.sealer.Open(ctx, tx, sealed)
	if err != nil {
		return "", "", err
	}
	return string(open), kind, nil
}

func (g *Gateway) apiRevealKey(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	reason := readInput(r).Reason
	if strings.TrimSpace(reason) == "" {
		writeError(w, http.StatusBadRequest, "a reason is required and is written to the audit log")
		return
	}
	var key, kind string
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var rerr error
			key, kind, rerr = g.reveal(ctx, tx, id, res.Subject, reason)
			return rerr
		})
	if errors.Is(err, data.ErrNoRecoveryKey) {
		writeError(w, http.StatusNotFound, "no recovery key is escrowed for that device")
		return
	}
	if err != nil {
		g.log.Error("reveal", "device", id, "err", err)
		writeError(w, http.StatusInternalServerError, "the key could not be revealed")
		return
	}
	g.log.Warn("recovery key revealed", "tenant", res.Tenant.Slug, "device", id, "by", res.Subject)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"kind": kind, "key": key})
}

func (g *Gateway) consoleRevealKey(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/devices", "No such device.")
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		back(w, r, "/devices/"+id.String(), "A reason is needed. It is written to the audit log with your name.")
		return
	}
	var key, kind string
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var rerr error
			key, kind, rerr = g.reveal(ctx, tx, id, res.Subject, reason)
			return rerr
		})
	if errors.Is(err, data.ErrNoRecoveryKey) {
		back(w, r, "/devices/"+id.String(), "No recovery key is escrowed for this device.")
		return
	}
	if err != nil {
		back(w, r, "/devices/"+id.String(), "The key could not be revealed.")
		return
	}
	g.log.Warn("recovery key revealed", "tenant", res.Tenant.Slug, "device", id, "by", res.Subject)
	// Shown once, on its own page, never through a redirect.
	w.Header().Set("Cache-Control", "no-store")
	g.console.RevealedKeyPage(w, r, console.Session{
		Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject, CSRF: g.csrfToken(res),
	}, id, kind, key)
}
