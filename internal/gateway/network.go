package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/policy"
	"platform/internal/tenantclaim"
)

// Network-side revocation. The tenant's network equipment holds an
// integration token and asks the access feed; the feed says allow or deny.
// Pushes go out on device.quarantined and device.released through the
// notification channels the tenant already has, and the feed is the source
// of truth between them.

// tokenPrefix makes an integration token recognisable before any lookup, so
// a session token and an integration token never go down each other's path.
const tokenPrefix = "mdm_net_"

func newIntegrationToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = tokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	return token, sum[:], nil
}

func integrationHash(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(token, tokenPrefix))
	if err != nil || len(raw) != 32 {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

// resolveIntegration turns a presented integration token into an identity,
// or refuses. The lookup is a tenant read under row-level security, on a
// claim minted for the hostname's tenant and nobody: a token minted by
// tenant A, presented at tenant B's hostname, is looked up in B's rows and
// is not there.
func (g *Gateway) resolveIntegration(ctx context.Context, host directory.Tenant, token string) (Identity, error) {
	hash, ok := integrationHash(token)
	if !ok {
		return Identity{}, data.ErrNoSuchToken
	}
	claim, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: "integration-lookup", Role: string(authz.Network),
		RequestID: uuid.NewString(),
	}, 30*time.Second)
	if err != nil {
		return Identity{}, err
	}
	var tok data.IntegrationToken
	err = g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
		var lerr error
		tok, lerr = data.LookupIntegrationToken(ctx, tx, hash)
		return lerr
	})
	if err != nil {
		return Identity{}, err
	}
	role := authz.Network
	if tok.Scope == "hr" {
		role = authz.HRFeed
	}
	return Identity{Subject: "integration:" + tok.Name, TenantID: host.ID, Role: role}, nil
}

// ---------------------------------------------------------------- the feed

func (g *Gateway) networkAccess(w http.ResponseWriter, r *http.Request) {
	serial := strings.TrimSpace(r.PathValue("serial"))
	if serial == "" {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var (
		v     data.NetworkVerdict
		found bool
	)
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var aerr error
			v, found, aerr = data.NetworkAccess(ctx, tx, serial, policy.MaxReportAge)
			return aerr
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the device")
		return
	}
	if !found {
		// Not managed here. The network's own policy decides what an
		// unmanaged device gets; we do not say allow for a device we
		// have never seen.
		writeJSON(w, http.StatusNotFound, map[string]any{"serial": serial, "access": "unknown"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// networkAccessByMAC is the same question asked the way a NAC can ask it:
// by the address the device authenticated with. Any of the ways a MAC is
// written is accepted; an address no device of this tenant has reported
// is unknown, exactly as an unmanaged serial is.
func (g *Gateway) networkAccessByMAC(w http.ResponseWriter, r *http.Request) {
	mac, ok := data.NormaliseMAC(r.PathValue("mac"))
	if !ok {
		writeError(w, http.StatusBadRequest, "that is not a MAC address")
		return
	}
	var (
		v     data.NetworkVerdict
		found bool
	)
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			id, has, derr := data.DeviceByMAC(ctx, tx, mac)
			if derr != nil || !has {
				return derr
			}
			var aerr error
			v, found, aerr = data.NetworkAccessByID(ctx, tx, id, policy.MaxReportAge)
			return aerr
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the device")
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"mac": mac, "access": "unknown"})
		return
	}
	v.MAC = mac
	writeJSON(w, http.StatusOK, v)
}

func (g *Gateway) networkDenied(w http.ResponseWriter, r *http.Request) {
	var out []data.NetworkVerdict
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var lerr error
			out, lerr = data.NetworkDenied(ctx, tx, policy.MaxReportAge)
			return lerr
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the fleet")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"denied": out, "as_of": time.Now().UTC()})
}

// ---------------------------------------------------------------- the console

func (g *Gateway) loadTokens(ctx context.Context, tx *data.Tx, out *console.Identity) error {
	ts, err := data.ListIntegrationTokens(ctx, tx)
	if err != nil {
		return err
	}
	out.Tokens = ts
	return nil
}

// consoleCreateToken mints a token and shows it ONCE, on the page itself
// rather than through a redirect: a secret in a query string is a secret in
// the browser history and the access log.
func (g *Gateway) consoleCreateToken(w http.ResponseWriter, r *http.Request, res Resolution) {
	if !res.Tenant.Feature(directory.FeatureNetworkFeed) {
		back(w, r, "/identity", "The network access feed is not part of this tenant's plan. Ask the operator to move you to a plan that includes it.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	scope := strings.TrimSpace(r.FormValue("scope"))
	if name == "" {
		back(w, r, "/identity", "Name the integration: the Wi-Fi controller, the VPN, the NAC, the HR system.")
		return
	}
	token, hash, err := newIntegrationToken()
	if err != nil {
		back(w, r, "/identity", "Something went wrong minting the token.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			_, cerr := data.CreateIntegrationToken(ctx, tx, name, scope, hash, res.Subject)
			return cerr
		})
	if err != nil {
		back(w, r, "/identity", "Not created. "+strings.TrimPrefix(err.Error(), "data: "))
		return
	}
	g.log.Info("integration token created", "tenant", res.Tenant.Slug, "name", name, "by", res.Subject)
	s := console.Session{Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject,
		CSRF: g.csrfToken(res)}
	g.console.IdentityPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Identity) error {
		if err := g.loadIdentity(ctx, tx, out); err != nil {
			return err
		}
		out.NewToken, out.NewTokenName = token, name
		return nil
	})
}

func (g *Gateway) consoleRevokeToken(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/identity", "No such integration.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return data.RevokeIntegrationToken(ctx, tx, id, res.Subject)
		})
	if errors.Is(err, data.ErrNoSuchToken) {
		back(w, r, "/identity", "That integration is already revoked, or never existed.")
		return
	}
	if err != nil {
		back(w, r, "/identity", "Not revoked.")
		return
	}
	g.log.Info("integration token revoked", "tenant", res.Tenant.Slug, "id", id, "by", res.Subject)
	back(w, r, "/identity", "Revoked. The network will be refused from its next request.")
}
