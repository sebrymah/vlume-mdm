package gateway

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/branding"
	"platform/internal/data"
	"platform/internal/tenantclaim"
)

// T4: the logo and the favicon, served per hostname with no session, so
// the error page and the browser tab carry them before anyone signs in.
// The tenant comes from the hostname, the read runs under a claim with no
// identity, and the bytes are whatever that tenant's row holds: a logo
// requested on tenant B's hostname is tenant B's or nothing.

func (g *Gateway) brandImage(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := g.publicHost(w, r)
		if !ok {
			return
		}
		claim, err := g.signer.Mint(tenantclaim.Claim{
			TenantID: host.ID, Subject: "anonymous", Role: string(authz.Bootstrap),
			RequestID: uuid.NewString(),
		}, 30*time.Second)
		if err != nil {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		var b []byte
		var typ string
		var found bool
		if err := g.store.WithTenant(r.Context(), claim, func(ctx context.Context, tx *data.Tx) error {
			var ierr error
			b, typ, found, ierr = branding.Image(ctx, tx, kind)
			return ierr
		}); err != nil || !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", typ)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(b)
	}
}

// consoleUploadImage takes the logo or the favicon from the branding form.
func (g *Gateway) consoleUploadImage(w http.ResponseWriter, r *http.Request, res Resolution) {
	kind := strings.TrimSpace(r.FormValue("kind"))
	if r.FormValue("remove") != "" {
		err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error { return branding.RemoveImage(ctx, tx, kind) })
		if err != nil {
			back(w, r, "/branding", "Not removed.")
			return
		}
		back(w, r, "/branding", "Removed.")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		back(w, r, "/branding", "Choose a file first.")
		return
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, branding.MaxLogoBytes+1))
	if err != nil {
		back(w, r, "/branding", "The file could not be read.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error { return branding.SaveImage(ctx, tx, kind, b) })
	if err != nil {
		back(w, r, "/branding", "Not saved. "+strings.TrimPrefix(err.Error(), "branding: ")+".")
		return
	}
	g.log.Info("brand image saved", "tenant", res.Tenant.Slug, "kind", kind, "bytes", len(b), "by", res.Subject)
	back(w, r, "/branding", "Saved. It shows on every page from now.")
}
