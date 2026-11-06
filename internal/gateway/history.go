package gateway

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/tenantclaim"
)

// Compliance over time (0041): the device's verdict history and the
// fleet's daily snapshot, and the job that takes the snapshot.

// RunComplianceSnapshots takes every tenant's snapshot now and then once
// a day, under a tenant claim per tenant so the counts are read inside
// row-level security. Its own job rather than a line in the usage
// snapshot: that one runs on the operator's pool, whose role may not read
// devices, and must not be given the right to for a count.
func (g *Gateway) RunComplianceSnapshots(ctx context.Context, tenants func(context.Context) ([]uuid.UUID, error), every time.Duration) {
	if every <= 0 {
		every = 24 * time.Hour
	}
	g.log.Info("compliance snapshots running", "every", every)
	for {
		ids, err := tenants(ctx)
		if err != nil {
			g.log.Error("compliance snapshots: could not list tenants", "err", err)
		}
		for _, id := range ids {
			if _, err := g.SnapshotTenant(ctx, id); err != nil {
				g.log.Error("compliance snapshot", "tenant", id, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// SnapshotTenant takes one tenant's snapshot for today.
func (g *Gateway) SnapshotTenant(ctx context.Context, id uuid.UUID) (data.ComplianceSnapshot, error) {
	claim, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: id, Subject: "system:compliance-snapshot",
		Role: string(authz.Operator), RequestID: uuid.NewString(),
	}, 2*time.Minute)
	if err != nil {
		return data.ComplianceSnapshot{}, err
	}
	var s data.ComplianceSnapshot
	err = g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
		var terr error
		s, terr = data.TakeComplianceSnapshot(ctx, tx, time.Now().UTC())
		return terr
	})
	return s, err
}

func (g *Gateway) complianceTrend(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	var out []data.ComplianceSnapshot
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var terr error
			out, terr = data.ComplianceTrend(ctx, tx, days)
			return terr
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the trend")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": out})
}

func (g *Gateway) deviceHistory(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var out []data.VerdictChange
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if _, derr := data.GetDevice(ctx, tx, id); derr != nil {
				return data.ErrNoSuchDevice
			}
			var herr error
			out, herr = data.VerdictHistory(ctx, tx, id, 50)
			return herr
		})
	if err == data.ErrNoSuchDevice {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the history")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": out})
}
