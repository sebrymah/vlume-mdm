package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/siem"
	"platform/internal/tenantclaim"
)

// F19: the SIEM stream. A sweep every minute ships what is new for every
// tenant with a target; the API lets an administrator push it now and see
// where the cursor is.

func (g *Gateway) exportSIEM(ctx context.Context, tx *data.Tx, slug string) (siem.Result, error) {
	return siem.Export(ctx, tx, g.notify, slug, 200)
}

func (g *Gateway) apiSIEMExport(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	var out siem.Result
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			out, e = g.exportSIEM(ctx, tx, res.Tenant.Slug)
			return e
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the export could not run")
		return
	}
	body := map[string]any{"from": out.From, "to": out.To, "sent": out.Sent, "remaining": out.Remaining}
	if out.Err != nil {
		body["error"] = out.Err.Error()
		writeJSON(w, http.StatusBadGateway, body)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (g *Gateway) apiSIEMStatus(w http.ResponseWriter, r *http.Request) {
	var c siem.Cursor
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			c, e = siem.Status(ctx, tx)
			return e
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the stream's position")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"last_audit_id": c.LastAuditID, "sent_total": c.SentTotal, "last_sent_at": c.LastSentAt,
		"last_error": c.LastError, "behind": c.Behind,
	})
}

func (g *Gateway) RunSIEMExport(ctx context.Context, tenants func(context.Context) ([]uuid.UUID, error),
	slugOf func(context.Context, uuid.UUID) (string, error), every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	g.log.Info("siem export running", "every", every)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		ids, err := tenants(ctx)
		if err != nil {
			g.log.Error("siem export: could not list tenants", "err", err)
			continue
		}
		for _, id := range ids {
			slug, err := slugOf(ctx, id)
			if err != nil {
				continue
			}
			claim, err := g.signer.Mint(tenantclaim.Claim{
				TenantID: id, Subject: "system:siem-export",
				Role: string(authz.Operator), RequestID: uuid.NewString(),
			}, 2*time.Minute)
			if err != nil {
				continue
			}
			if err := g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
				out, e := g.exportSIEM(ctx, tx, slug)
				if e == nil && out.Err != nil {
					g.log.Warn("siem export stopped", "tenant", id, "sent", out.Sent, "err", out.Err)
				} else if e == nil && out.Sent > 0 {
					g.log.Info("siem exported", "tenant", id, "sent", out.Sent, "remaining", out.Remaining)
				}
				return e
			}); err != nil {
				g.log.Error("siem export", "tenant", id, "err", err)
			}
		}
	}
}
