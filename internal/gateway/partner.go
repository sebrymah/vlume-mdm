package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"platform/internal/directory"
	"platform/internal/secrets"
)

// T7: the partner API, on the operator's hostname (the sign-up host),
// authenticated by the partner's token. A partner creates tenants under
// itself, lists its own, reads their usage, suspends and resumes them.
// Every call resolves the tenant within the partner's own list first, so
// another partner's tenant is "not yours" before anything else happens;
// and the whole API runs on the operator's role, which cannot see inside
// any tenant.

func (g *Gateway) partnerFrom(w http.ResponseWriter, r *http.Request) (directory.Partner, bool) {
	bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	if !strings.HasPrefix(bearer, directory.PartnerTokenPrefix) {
		writeError(w, http.StatusUnauthorized, "a partner token is required")
		return directory.Partner{}, false
	}
	if !g.limiter.allowKey("partner:"+g.callerIP(r), 60) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return directory.Partner{}, false
	}
	p, err := g.dir.PartnerByToken(r.Context(), bearer)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "partner token not accepted")
		return directory.Partner{}, false
	}
	return p, true
}

func (g *Gateway) partnerRoutes(mux *http.ServeMux) {
	mux.Handle("GET /partner/tenants", http.HandlerFunc(g.partnerList))
	mux.Handle("POST /partner/tenants", http.HandlerFunc(g.partnerCreate))
	mux.Handle("GET /partner/tenants/{slug}/usage", http.HandlerFunc(g.partnerUsage))
	mux.Handle("POST /partner/tenants/{slug}/suspend", g.partnerStatus("suspended"))
	mux.Handle("POST /partner/tenants/{slug}/resume", g.partnerStatus("active"))
}

func (g *Gateway) partnerList(w http.ResponseWriter, r *http.Request) {
	p, ok := g.partnerFrom(w, r)
	if !ok {
		return
	}
	ts, err := g.dir.TenantsOf(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"partner": p.Slug, "tenants": ts, "cap": p.TenantCap})
}

type partnerCreateInput struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	Host         string `json:"host"`
	Plan         string `json:"plan"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RoleClaim    string `json:"role_claim"`
	AdminGroup   string `json:"admin_group"`
}

func (g *Gateway) partnerCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := g.partnerFrom(w, r)
	if !ok {
		return
	}
	var in partnerCreateInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "the tenant could not be read")
		return
	}
	if g.keys == nil || strings.TrimSpace(in.ClientSecret) == "" {
		writeError(w, http.StatusBadRequest, "a client secret is required")
		return
	}
	tenantKey, keySealed, err := g.keys.NewTenantKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not make the tenant's key")
		return
	}
	sealed, err := secrets.SealWith(tenantKey, 1, []byte(strings.TrimSpace(in.ClientSecret)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not seal the secret")
		return
	}
	id, err := g.dir.CreateTenantFor(r.Context(), p, directory.NewTenant{
		Name: in.Name, Slug: in.Slug, Host: in.Host, Plan: in.Plan,
		Issuer: in.Issuer, ClientID: in.ClientID, ClientSecretSealed: sealed,
		RoleClaim: in.RoleClaim, AdminGroup: in.AdminGroup, KeySealed: keySealed,
	})
	switch {
	case errors.Is(err, directory.ErrPartnerCap):
		writeError(w, http.StatusConflict, strings.TrimPrefix(err.Error(), "directory: "))
		return
	case errors.Is(err, directory.ErrSlugTaken), errors.Is(err, directory.ErrHostTaken):
		writeError(w, http.StatusConflict, strings.TrimPrefix(err.Error(), "directory: "))
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "directory: "))
		return
	}
	g.log.Info("partner created a tenant", "partner", p.Slug, "tenant", id, "slug", in.Slug)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "slug": in.Slug, "host": in.Host})
}

func (g *Gateway) partnerUsage(w http.ResponseWriter, r *http.Request) {
	p, ok := g.partnerFrom(w, r)
	if !ok {
		return
	}
	t, err := g.dir.OwnTenant(r.Context(), p, r.PathValue("slug"))
	if errors.Is(err, directory.ErrNotYourTenant) {
		writeError(w, http.StatusNotFound, "no such tenant")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read")
		return
	}
	u, err := g.dir.Usage(r.Context(), t.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not meter")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"slug": t.Slug, "plan": u.Plan, "active_devices": u.ActiveDevices, "device_cap": u.DeviceCap,
		"commands_30d": u.Commands30d, "storage_bytes": u.StorageBytes,
	})
}

func (g *Gateway) partnerStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := g.partnerFrom(w, r)
		if !ok {
			return
		}
		t, err := g.dir.OwnTenant(r.Context(), p, r.PathValue("slug"))
		if errors.Is(err, directory.ErrNotYourTenant) {
			writeError(w, http.StatusNotFound, "no such tenant")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not read")
			return
		}
		if err := g.dir.SetStatus(r.Context(), t.Slug, status); err != nil {
			writeError(w, http.StatusInternalServerError, "could not change the status")
			return
		}
		g.log.Info("partner changed a tenant's status", "partner", p.Slug, "tenant", t.Slug, "status", status)
		writeJSON(w, http.StatusOK, map[string]any{"slug": t.Slug, "status": status})
	}
}
