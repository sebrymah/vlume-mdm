package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/identity"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

// The SAML side of sign-in. The shape is the OIDC one with the protocol
// swapped: the browser goes to the provider carrying a request id, the
// signed flow cookie remembers that id, and the provider's answer has to
// name it. What differs is the way back. OIDC returns on a GET with a code
// in the query string; SAML returns on a POST from the provider's origin
// with the whole assertion in the body.
//
// That one difference decides the cookie. A SameSite=Lax cookie, which is
// what the OIDC flow uses, is withheld from a cross-site POST by every
// current browser, so the flow would arrive without its cookie and every
// SAML sign-in would fail as "expired". The SAML flow cookie is therefore
// SameSite=None, which browsers accept only with Secure, which is one more
// reason the console runs on https. (In development with insecure cookies
// it falls back to Lax, and a real browser then cannot finish a SAML
// sign-in; the tests use a client that does not enforce SameSite.)

func (g *Gateway) setSAMLFlowCookie(w http.ResponseWriter, value string) {
	c := &http.Cookie{
		Name: flowCookie, Value: value, Path: "/", HttpOnly: true,
		MaxAge:   int(session.FlowLifetime / time.Second),
		Secure:   !g.insecureCookies,
		SameSite: http.SameSiteNoneMode,
	}
	if g.insecureCookies {
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
}

// samlSignIn sends the browser to the tenant's SAML provider.
func (g *Gateway) samlSignIn(w http.ResponseWriter, r *http.Request, host directory.Tenant, cfg identity.Config) {
	if g.saml == nil {
		g.signInProblem(w, r, host, http.StatusNotImplemented,
			"Sign-in is not available", "This deployment has no SAML adapter wired up.")
		return
	}
	to, requestID, err := g.saml.AuthURL(cfg)
	if err != nil {
		g.log.Error("saml auth url", "tenant", host.Slug, "err", err)
		g.signInProblem(w, r, host, http.StatusInternalServerError,
			"Sign-in is unavailable", "This organisation's SAML settings could not be used to start a sign-in.")
		return
	}
	// The request id sits where OIDC keeps its state: it is the value the
	// provider's answer has to carry back. The nonce and verifier have no
	// SAML meaning; the flow signer insists on a nonce, so it gets one.
	flow, err := g.sessions.MintFlow(session.Flow{
		TenantID: host.ID, State: requestID, Nonce: g.randomToken(),
		Return: localPath(r.URL.Query().Get("next")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start sign-in")
		return
	}
	g.setSAMLFlowCookie(w, flow)
	http.Redirect(w, r, to, http.StatusFound)
}

// samlCallback is the provider posting the assertion back.
//
// The order is the OIDC callback's: retire the flow cookie first, verify it,
// insist it names this hostname's tenant, and only then open the assertion,
// which the adapter checks against the request id the flow remembers, the
// certificate the tenant pinned, our own entity id and the clock.
func (g *Gateway) samlCallback(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	if g.sessions == nil || g.saml == nil {
		writeError(w, http.StatusNotImplemented, "sign-in is not available")
		return
	}
	ck, err := r.Cookie(flowCookie)
	g.clearCookie(w, flowCookie)
	if err != nil || ck.Value == "" {
		g.signInProblem(w, r, host, http.StatusBadRequest,
			"That sign-in has expired", "Start again from the sign-in page.")
		return
	}
	flow, err := g.sessions.VerifyFlow(ck.Value)
	if err != nil {
		g.signInProblem(w, r, host, http.StatusBadRequest,
			"That sign-in has expired", "Start again from the sign-in page.")
		return
	}
	if flow.TenantID != host.ID {
		g.log.Warn("sign-in flow and hostname name different tenants",
			"host", host.Slug, "flow_tenant", flow.TenantID)
		writeError(w, http.StatusForbidden, "sign-in flow and hostname name different tenants")
		return
	}

	// An assertion is a few kilobytes; a megabyte is somebody else's
	// problem being posted at us.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "could not read the response")
		return
	}
	encoded := r.PostFormValue("SAMLResponse")
	if encoded == "" {
		g.signInProblem(w, r, host, http.StatusBadRequest,
			"That sign-in did not complete", "Your identity provider sent nothing back. Start again from the sign-in page.")
		return
	}

	cfg, err := g.identityConfig(r.Context(), host)
	if errors.Is(err, directory.ErrNoIdentityConfig) || (err == nil && !cfg.IsSAML()) {
		writeError(w, http.StatusBadRequest, "this organisation does not sign in with SAML")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read sign-in settings")
		return
	}

	claims, err := g.saml.Consume(cfg, encoded, flow.State)
	if err != nil {
		// The reason stays in the log. The page says the same thing it
		// says for OIDC, because the person at the keyboard can do the
		// same thing about it: try again, then ask their administrator.
		g.log.Warn("saml sign-in rejected", "tenant", host.Slug, "err", err)
		g.signInProblem(w, r, host, http.StatusForbidden,
			"We could not confirm who you are",
			"Your identity provider's answer did not pass our checks. Try signing in again.")
		return
	}
	g.finishSignIn(w, r, host, flow, claims)
}

// samlMetadata serves our entity descriptor for the tenant on this
// hostname, for the administrator to hand to their provider. It is public
// because the provider fetches it, and it says nothing that the sign-in
// redirect does not already say.
func (g *Gateway) samlMetadata(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	if g.saml == nil {
		writeError(w, http.StatusNotImplemented, "SAML is not available")
		return
	}
	cfg, err := g.identityConfig(r.Context(), host)
	if errors.Is(err, directory.ErrNoIdentityConfig) || (err == nil && !cfg.IsSAML()) {
		writeError(w, http.StatusNotFound, "this organisation does not sign in with SAML")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read sign-in settings")
		return
	}
	md, err := g.saml.Metadata(cfg)
	if err != nil {
		g.log.Error("saml metadata", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "could not build the metadata")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", `inline; filename="`+host.Slug+`-saml-metadata.xml"`)
	_, _ = w.Write(md)
}

// ---------------------------------------------------------- single logout

// ensureSAMLSigningKey gives a SAML tenant a signing key of its own the
// first time one is needed (0043): the key sealed under the tenant's key
// in its identity row, the certificate beside it in the clear, because it
// is what we publish. Made once; a tenant that already has one keeps it,
// because the provider has pinned it.
func (g *Gateway) ensureSAMLSigningKey(ctx context.Context, t directory.Tenant, cfg identity.Config) (identity.Config, error) {
	if g.sealer == nil {
		return cfg, nil
	}
	host := t.Slug
	if u, err := url.Parse(cfg.ClientID); err == nil && u.Host != "" {
		host = u.Host
	}
	keyPEM, certPEM, err := identity.GenerateSigningKey(host, time.Now().UTC())
	if err != nil {
		return identity.Config{}, err
	}
	claim, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: t.ID, Subject: "system:saml-signing-key", Role: string(authz.Bootstrap),
		RequestID: uuid.NewString(),
	}, 30*time.Second)
	if err != nil {
		return identity.Config{}, err
	}
	err = g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
		sealed, serr := g.sealer.Seal(ctx, tx, []byte(keyPEM))
		if serr != nil {
			return serr
		}
		// Only where none is held: two requests arriving together must
		// not each make one and publish different certificates.
		tag, uerr := tx.Exec(ctx, `
			UPDATE tenant_identity SET saml_sp_key_sealed = $1, saml_sp_cert = $2
			 WHERE saml_sp_key_sealed IS NULL`, sealed, certPEM)
		if uerr != nil {
			return uerr
		}
		if tag.RowsAffected() == 0 {
			return errRaced
		}
		return data.AppendAudit(ctx, tx, "identity.signing_key", "saml:made")
	})
	if errors.Is(err, errRaced) {
		return g.identityConfig(ctx, t)
	}
	if err != nil {
		return identity.Config{}, err
	}
	cfg.SAMLSigningKey, cfg.SAMLSigningCert = keyPEM, certPEM
	return cfg, nil
}

var errRaced = errors.New("another request made the key first")

// samlLogout is our single logout endpoint: the provider's answer to a
// logout we started (SAMLResponse), or the provider telling us a person
// has signed out elsewhere (SAMLRequest). Either way our cookies go;
// what differs is what is checked and where the browser goes next.
func (g *Gateway) samlLogout(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	if g.saml == nil || g.sessions == nil {
		writeError(w, http.StatusNotImplemented, "single logout is not available")
		return
	}
	cfg, err := g.identityConfig(r.Context(), host)
	if errors.Is(err, directory.ErrNoIdentityConfig) || (err == nil && !cfg.IsSAML()) {
		writeError(w, http.StatusNotFound, "this organisation does not sign in with SAML")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read sign-in settings")
		return
	}
	q := r.URL.Query()
	switch {
	case q.Get("SAMLResponse") != "":
		// The provider answering us. The flow cookie remembers which
		// request we made; an answer to another, or to none, is logged
		// and ignored. Our session is already gone either way, so the
		// browser goes to the sign-in page whatever the answer said.
		ck, cerr := r.Cookie(flowCookie)
		g.clearCookie(w, flowCookie)
		g.clearCookie(w, sessionCookie)
		requestID := ""
		if cerr == nil && ck.Value != "" {
			if flow, ferr := g.sessions.VerifyFlow(ck.Value); ferr == nil && flow.TenantID == host.ID {
				requestID = flow.State
			}
		}
		if err := g.saml.FinishLogout(cfg, q.Get("SAMLResponse"), requestID); err != nil {
			g.log.Warn("saml logout response rejected", "tenant", host.Slug, "err", err)
		} else {
			g.log.Info("saml single logout finished", "tenant", host.Slug)
		}
		http.Redirect(w, r, "/signin", http.StatusFound)

	case q.Get("SAMLRequest") != "":
		// The provider telling us. Signed by the certificate the tenant
		// pinned, from the provider's entity id, addressed to us: then
		// our cookies go and the provider gets a signed answer.
		requestID, nameID, err := g.saml.ProviderLogoutRequest(cfg, q.Get("SAMLRequest"))
		if err != nil {
			g.log.Warn("saml logout request rejected", "tenant", host.Slug, "err", err)
			writeError(w, http.StatusBadRequest, "the logout request did not pass our checks")
			return
		}
		g.clearCookie(w, sessionCookie)
		g.clearCookie(w, flowCookie)
		g.log.Info("saml single logout from the provider", "tenant", host.Slug, "subject", nameID)
		to, err := g.saml.LogoutResponseURL(cfg, requestID)
		if err != nil {
			g.log.Error("saml logout response", "tenant", host.Slug, "err", err)
			http.Redirect(w, r, "/signin", http.StatusFound)
			return
		}
		http.Redirect(w, r, to, http.StatusFound)

	default:
		writeError(w, http.StatusBadRequest, "no SAML logout message")
	}
}
