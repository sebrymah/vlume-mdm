package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/tenantclaim"
)

// Signing one person out.
//
// A session is a signed token, so it cannot be deleted; it can be
// compared, on every request, against a stamp that says "nothing started
// before this counts". The tenant has one such stamp for everybody; this
// gives each person one of their own, on their row in tenant_admins, set
// by a Super Admin from the Sign-in page. The stamp is read under a
// bootstrap claim, like the role at sign-in, and remembered for a short
// while per instance: the person who was signed out is gone from this
// instance at once and from the others within the cache's life.

const revocationCacheFor = 30 * time.Second

type revocationCache struct {
	mu sync.Mutex
	at map[string]revocationEntry
}

type revocationEntry struct {
	before  time.Time
	checked time.Time
}

func newRevocationCache() *revocationCache { return &revocationCache{at: map[string]revocationEntry{}} }

func cacheKeyFor(tenant uuid.UUID, subject string) string { return tenant.String() + "|" + subject }

func (c *revocationCache) get(tenant uuid.UUID, subject string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.at[cacheKeyFor(tenant, subject)]
	if !ok || time.Since(e.checked) > revocationCacheFor {
		return time.Time{}, false
	}
	return e.before, true
}

func (c *revocationCache) put(tenant uuid.UUID, subject string, before time.Time) {
	c.mu.Lock()
	c.at[cacheKeyFor(tenant, subject)] = revocationEntry{before: before, checked: time.Now()}
	c.mu.Unlock()
}

func (c *revocationCache) forget(tenant uuid.UUID, subject string) {
	c.mu.Lock()
	delete(c.at, cacheKeyFor(tenant, subject))
	c.mu.Unlock()
}

// subjectInvalidBefore is the person's stamp, zero when they have none. A
// read that fails is treated as "no stamp" and logged: a database blip
// must not sign everybody out, and the tenant-wide stamp still applies.
func (g *Gateway) subjectInvalidBefore(ctx context.Context, host directory.Tenant, subject string) time.Time {
	if t, ok := g.revoked.get(host.ID, subject); ok {
		return t
	}
	bootstrap, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: subject, Role: string(authz.Bootstrap), RequestID: uuid.NewString(),
	}, 30*time.Second)
	if err != nil {
		return time.Time{}
	}
	var before time.Time
	err = g.store.WithTenant(ctx, bootstrap, func(ctx context.Context, tx *data.Tx) error {
		err := tx.QueryRow(ctx, `SELECT sessions_invalid_before FROM tenant_admins WHERE subject = $1`, subject).Scan(&before)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		g.log.Warn("could not read a session revocation stamp", "tenant", host.Slug, "err", err)
		return time.Time{}
	}
	g.revoked.put(host.ID, subject, before)
	return before
}

// consoleSignOutPerson ends every session one person has, now. Their row
// is stamped (made if they have none, lapsed so it takes no seat), the
// cache on this instance forgets them, and the next request they make is
// told the session was ended by an administrator.
func (g *Gateway) consoleSignOutPerson(w http.ResponseWriter, r *http.Request, res Resolution) {
	subject := strings.TrimSpace(r.FormValue("subject"))
	if subject == "" {
		back(w, r, "/identity", "Nothing named.")
		return
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if _, err := tx.Exec(ctx, `
				INSERT INTO tenant_admins (tenant_id, subject, role, last_seen_at, sessions_invalid_before)
				VALUES (app.current_tenant(), $1, 'employee', to_timestamp(0), now())
				ON CONFLICT (tenant_id, subject) DO UPDATE SET sessions_invalid_before = now()`, subject); err != nil {
				return err
			}
			return data.AppendAudit(ctx, tx, "session.revoked", subject)
		})
	if err != nil {
		g.log.Error("sign out person", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/identity", "They could not be signed out.")
		return
	}
	g.revoked.forget(res.Tenant.ID, subject)
	g.log.Info("person signed out everywhere", "tenant", res.Tenant.Slug, "subject", subject, "by", res.Subject)
	back(w, r, "/identity", "Signed out everywhere. Their next request is refused and they can sign in again if they still have a role.")
}
