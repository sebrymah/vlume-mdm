package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/identity"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

const (
	sessionCookie = "session"
	flowCookie    = "signin_flow"
)

// The sign-in routes are the only ones mounted outside entry, because entry
// requires a credential and these exist to get one. That makes them the
// platform's entire unauthenticated surface, which is why it is three
// handlers and not more.

func (g *Gateway) randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not a condition to carry on through. A
		// predictable state value is a sign-in anyone can finish.
		panic("gateway: no randomness available: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (g *Gateway) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
		// Lax rather than Strict: the callback arrives as a top-level
		// navigation from the provider, and Strict would drop the flow
		// cookie on exactly that request. Lax still withholds it from
		// cross-site POSTs, which is where it matters.
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   !g.insecureCookies,
		MaxAge:   maxAge,
	})
}

func (g *Gateway) clearCookie(w http.ResponseWriter, name string) {
	g.setCookie(w, name, "", -1)
}

// identityConfig reads a tenant's provider settings and unseals the client
// secret. The sealed form is what the database holds; the usable form exists
// only here, for the length of one sign-in.
func (g *Gateway) identityConfig(ctx context.Context, t directory.Tenant) (identity.Config, error) {
	raw, err := g.dir.Identity(ctx, t.ID)
	if err != nil {
		return identity.Config{}, err
	}
	cfg := identity.Config{
		TenantID: raw.TenantID, Issuer: raw.Issuer, ClientID: raw.ClientID,
		RedirectURL: raw.RedirectURL, RoleClaim: raw.RoleClaim,
		Protocol: raw.Protocol, SAMLSSOURL: raw.SAMLSSOURL, SAMLCertificate: raw.SAMLCertificate,
		SAMLSLOURL: raw.SAMLSLOURL, SAMLSigningCert: raw.SAMLSigningCert,
	}
	// The sealed values: the OIDC client secret, or the SAML signing key.
	// Opened under the tenant's own key, which lives in the tenant's
	// rows: a short transaction on a claim that carries no identity,
	// because nobody has signed in yet.
	if len(raw.SecretSealed) > 0 || len(raw.SAMLSigningKeySealed) > 0 {
		if g.sealer == nil {
			return identity.Config{}, errors.New("gateway: no sealing key is configured")
		}
		claim, err := g.signer.Mint(tenantclaim.Claim{
			TenantID: t.ID, Subject: "anonymous", Role: string(authz.Bootstrap),
			RequestID: uuid.NewString(),
		}, 30*time.Second)
		if err != nil {
			return identity.Config{}, err
		}
		if err := g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
			if len(raw.SecretSealed) > 0 {
				open, oerr := g.sealer.Open(ctx, tx, raw.SecretSealed)
				if oerr != nil {
					return oerr
				}
				cfg.ClientSecret = string(open)
			}
			if len(raw.SAMLSigningKeySealed) > 0 {
				open, oerr := g.sealer.Open(ctx, tx, raw.SAMLSigningKeySealed)
				if oerr != nil {
					return oerr
				}
				cfg.SAMLSigningKey = string(open)
			}
			return nil
		}); err != nil {
			return identity.Config{}, err
		}
	}
	if cfg.IsSAML() && cfg.SAMLSigningKey == "" {
		return g.ensureSAMLSigningKey(ctx, t, cfg)
	}
	return cfg, nil
}

// localPath keeps the "where was I going" parameter from becoming an open
// redirect. Anything that is not a plain path on this site is dropped rather
// than argued with.
func localPath(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return ""
	}
	// A backslash is a slash to a browser. Chrome and Firefox both normalise
	// it before resolving, so "/\\evil.example" is read as "//evil.example",
	// which is protocol-relative and leaves the site. Refusing the character
	// outright is simpler than tracking how each browser normalises, and
	// nothing legitimate on this site has one in its path.
	if strings.ContainsAny(s, "\\\r\n") {
		return ""
	}
	// And every other control character, which a header or a browser may
	// treat as a separator of its own.
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return s
}

// signIn sends the browser to the tenant's own provider.
func (g *Gateway) signIn(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	if g.sessions == nil || (g.oidc == nil && g.saml == nil) {
		g.signInProblem(w, r, host, http.StatusNotImplemented,
			"Sign-in is not available", "This deployment has no identity provider wired up.")
		return
	}

	cfg, err := g.identityConfig(r.Context(), host)
	if errors.Is(err, directory.ErrNoIdentityConfig) {
		// Not an error: a tenant partway through setup. Say which step.
		g.signInProblem(w, r, host, http.StatusConflict,
			"Identity provider not set up yet",
			"Nobody can sign in to "+host.Name+" until an administrator connects "+
				"your organisation's identity provider in the setup wizard.")
		return
	}
	if err != nil {
		g.log.Error("identity config", "tenant", host.Slug, "err", err)
		g.signInProblem(w, r, host, http.StatusInternalServerError,
			"Sign-in is unavailable", "We could not read this organisation's sign-in settings.")
		return
	}

	if cfg.IsSAML() {
		g.samlSignIn(w, r, host, cfg)
		return
	}
	if g.oidc == nil {
		g.signInProblem(w, r, host, http.StatusNotImplemented,
			"Sign-in is not available", "This deployment has no OpenID Connect adapter wired up.")
		return
	}

	state := g.randomToken()
	nonce := g.randomToken()
	verifier := identity.NewVerifier()

	url, err := g.oidc.AuthURL(r.Context(), cfg, state, nonce, verifier)
	if err != nil {
		g.log.Error("auth url", "tenant", host.Slug, "issuer", cfg.Issuer, "err", err)
		g.signInProblem(w, r, host, http.StatusBadGateway,
			"Your identity provider did not answer",
			"We could not reach "+cfg.Issuer+" to start the sign-in.")
		return
	}

	flow, err := g.sessions.MintFlow(session.Flow{
		TenantID: host.ID, State: state, Nonce: nonce, Verifier: verifier,
		Return: localPath(r.URL.Query().Get("next")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start sign-in")
		return
	}
	g.setCookie(w, flowCookie, flow, int(session.FlowLifetime/time.Second))
	http.Redirect(w, r, url, http.StatusFound)
}

// callback is the provider sending the person back.
//
// Everything here is checked before anything is trusted: the flow cookie must
// verify, it must name this hostname's tenant, the state must match it, the
// identity token must verify against the provider's keys with this tenant's
// client id as its audience, and the nonce must be the one we sent. Only then
// does a group become a role.
func (g *Gateway) callback(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	if g.sessions == nil || g.oidc == nil {
		writeError(w, http.StatusNotImplemented, "sign-in is not available")
		return
	}

	// The flow is spent whatever happens next, so retire the cookie first.
	// A failed sign-in that leaves a reusable flow is a replay waiting to be
	// found.
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
		// A sign-in begun on one tenant's hostname, finished on another's.
		g.log.Warn("sign-in flow and hostname name different tenants",
			"host", host.Slug, "flow_tenant", flow.TenantID)
		writeError(w, http.StatusForbidden, "sign-in flow and hostname name different tenants")
		return
	}

	q := r.URL.Query()
	if msg := q.Get("error"); msg != "" {
		g.log.Warn("provider refused sign-in", "tenant", host.Slug, "error", msg)
		g.signInProblem(w, r, host, http.StatusForbidden,
			"Your identity provider refused the sign-in", q.Get("error_description"))
		return
	}
	// Constant-time is unnecessary here and would be cargo cult: state is a
	// value we minted and the browser returns, not a secret being guessed
	// against a timer. It still has to match.
	if q.Get("state") != flow.State {
		g.log.Warn("sign-in state mismatch", "tenant", host.Slug)
		writeError(w, http.StatusForbidden, "this sign-in did not start here")
		return
	}
	code := q.Get("code")
	if code == "" {
		g.signInProblem(w, r, host, http.StatusBadRequest,
			"That sign-in did not complete", "Start again from the sign-in page.")
		return
	}

	cfg, err := g.identityConfig(r.Context(), host)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read sign-in settings")
		return
	}

	if cfg.IsSAML() {
		// A SAML tenant's browser arrives at the OIDC callback only if
		// somebody sent it there; there is nothing here for it.
		writeError(w, http.StatusBadRequest, "this organisation signs in with SAML")
		return
	}
	claims, err := g.oidc.Exchange(r.Context(), cfg, code, flow.Verifier, flow.Nonce)
	if err != nil {
		g.log.Warn("sign-in rejected", "tenant", host.Slug, "err", err)
		g.signInProblem(w, r, host, http.StatusForbidden,
			"We could not confirm who you are",
			"Your identity provider's answer did not pass our checks. Try signing in again.")
		return
	}
	g.finishSignIn(w, r, host, flow, claims)
}

// finishSignIn is the half of a sign-in that does not depend on the
// protocol: the role, the seat, the audit row and the session cookie. Both
// adapters hand a verified identity here and nothing else.
func (g *Gateway) finishSignIn(w http.ResponseWriter, r *http.Request,
	host directory.Tenant, flow session.Flow, claims identity.Claims) {

	role, err := g.roleFor(r.Context(), host, claims)
	if errors.Is(err, identity.ErrNoRole) {
		// Worth its own message. This is the single most common first-day
		// support call for any product that maps groups to roles, and an
		// unexplained "forbidden" turns it into a ticket for us instead of a
		// group membership their own administrator can fix in a minute.
		g.log.Warn("no role for signed-in person", "tenant", host.Slug,
			"subject", claims.Subject, "groups", len(claims.Groups))
		g.signInProblem(w, r, host, http.StatusForbidden,
			"You do not have access to "+host.Name+" yet",
			"Your sign-in worked, but none of your groups is mapped to a role here. "+
				"Ask an administrator to add one of your groups in Settings, Roles.")
		return
	}
	if errors.Is(err, ErrNoSeat) {
		// The other first-day call: the plan, not the person. Said plainly,
		// with the number and the two ways out, so it reaches the right
		// desk rather than ours.
		g.log.Warn("sign-in refused: no administrator seat", "tenant", host.Slug,
			"subject", claims.Subject, "seats", host.AdminSeats)
		g.signInProblem(w, r, host, http.StatusForbidden,
			"Every administrator seat is in use",
			fmt.Sprintf("Your sign-in worked, but %s has %d administrator seats and all of them are taken "+
				"by people who have signed in within the last 30 days. Ask a Super Admin to release a seat "+
				"on the Sign-in page, or to ask for a plan with more seats.", host.Name, host.AdminSeats))
		return
	}
	if err != nil {
		g.log.Error("role lookup", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "could not work out your role")
		return
	}

	token, sess, err := g.sessions.Start(session.Session{
		TenantID: host.ID, Subject: claims.Subject, Email: claims.Email,
		Name: claims.Name, Role: string(role),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start a session")
		return
	}
	g.setCookie(w, sessionCookie, token, int(session.Lifetime/time.Second))
	g.log.Info("signed in", "tenant", host.Slug, "subject", sess.Subject, "role", sess.Role)
	// The person is now someone the platform has met (0040). Recorded
	// under their own claim, inside row-level security; a failure here is
	// logged and does not undo a sign-in that already worked.
	if claim, cerr := g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: claims.Subject, Email: claims.Email,
		Role: string(role), RequestID: uuid.NewString(),
	}, 30*time.Second); cerr == nil {
		if err := g.store.WithTenant(r.Context(), claim, func(ctx context.Context, tx *data.Tx) error {
			_, perr := data.SeenAtSignIn(ctx, tx, claims.Subject, claims.Email, claims.Name, time.Now().UTC())
			return perr
		}); err != nil {
			g.log.Error("could not record the person", "tenant", host.Slug, "subject", claims.Subject, "err", err)
		}
	}

	to := flow.Return
	if to == "" {
		to = "/"
	}
	http.Redirect(w, r, to, http.StatusFound)
}

// roleFor maps the person's groups to a role, reading the mapping inside a
// tenant transaction.
//
// The claim minted here is the narrowest one the signer will accept: the
// subject is the person the identity token just proved, and the role is
// employee, which can do almost nothing. It exists for one SELECT. Reading
// the mapping this way, rather than through the directory's cross-tenant
// pool, keeps tenant_role_map inside row-level security like every other
// tenant table.
func (g *Gateway) roleFor(ctx context.Context, host directory.Tenant,
	claims identity.Claims) (authz.Role, error) {

	bootstrap, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: claims.Subject,
		Role: string(authz.Bootstrap), RequestID: uuid.NewString(),
	}, 30*time.Second)
	if err != nil {
		return "", err
	}

	var role authz.Role
	var refused bool
	err = g.store.WithTenant(ctx, bootstrap, func(ctx context.Context, tx *data.Tx) error {
		m, err := identity.LoadRoleMap(ctx, tx)
		if err != nil {
			return err
		}
		r, err := identity.MapRole(claims.Groups, m)
		if err != nil {
			return err
		}
		role = r
		// The seat, in the same transaction: an administrator with a
		// session is an administrator with a seat, and never one without.
		seated, err := takeSeat(ctx, tx, host.AdminSeats, claims, r)
		if err != nil {
			return err
		}
		if !seated {
			refused = true
			return seatRefused(ctx, tx, host.AdminSeats, claims, r)
		}
		// A sign-in belongs in the tenant's own audit log. It is written in
		// the same transaction as the role lookup, so there is no sign-in
		// that happened without a record of it.
		return data.AppendAudit(ctx, tx, "session.start", "role:"+string(r))
	})
	if err != nil {
		return "", err
	}
	if refused {
		return "", ErrNoSeat
	}
	return role, nil
}

func (g *Gateway) signOut(w http.ResponseWriter, r *http.Request) {
	// Sign-out is POST-only and carries the same form token as every other
	// console form. A forced sign-out is a nuisance rather than a breach, so
	// this is not the strongest control in the building, but the token is
	// already there and checking it costs one comparison.
	//
	// It is checked against the session rather than a Resolution because
	// this route runs outside entry, so there is no Resolution to check
	// against. A request with no readable session skips the check and still
	// clears the cookies: someone whose session already died should not have
	// to keep a dead cookie because they cannot prove who they were.
	subject := ""
	if ck, err := r.Cookie(sessionCookie); err == nil && ck.Value != "" {
		if sess, verr := g.verifySession(ck.Value); verr == nil {
			subject = sess.Subject
			got := r.FormValue("csrf")
			if got == "" {
				got = r.Header.Get("X-CSRF-Token")
			}
			if !g.csrfMatches(got, sess.TenantID, sess.Subject, sess.Role) {
				writeError(w, http.StatusForbidden, "missing or wrong form token")
				return
			}
		}
	}
	g.clearCookie(w, sessionCookie)
	g.clearCookie(w, flowCookie)
	// Ours is ended. The person is still signed in at their provider, and
	// on a shared machine that is the session that matters: the next
	// sign-in would not ask for a password. So the browser is sent to the
	// provider's end-session page when it has one (RP-initiated logout),
	// with our sign-in page as the place to come back to. A provider
	// without one gets the plain sign-in page.
	if host, ok := g.resolveHostQuietly(r); ok && g.oidc != nil {
		cfg, err := g.identityConfig(r.Context(), host)
		switch {
		case err != nil:
		case cfg.IsSAML():
			// A SAML tenant with a logout URL and a key of ours to sign
			// with (0043) is sent to its provider with a signed logout
			// request naming the person; the provider's answer comes
			// back to /signout/saml. Without either, the plain sign-in
			// page: an unsigned request a provider refuses is a sign-out
			// that looks finished and is not.
			if cfg.CanLogout() && g.saml != nil && g.sessions != nil && subject != "" {
				to, requestID, lerr := g.saml.LogoutURL(cfg, subject)
				if lerr != nil {
					g.log.Error("saml logout url", "tenant", host.Slug, "err", lerr)
					break
				}
				flow, ferr := g.sessions.MintFlow(session.Flow{
					TenantID: host.ID, State: requestID, Nonce: g.randomToken(),
				})
				if ferr != nil {
					break
				}
				g.setSAMLFlowCookie(w, flow)
				http.Redirect(w, r, to, http.StatusFound)
				return
			}
		default:
			back := g.signupSchemeFor(r) + "://" + r.Host + "/signin"
			if u, err := g.oidc.EndSessionURL(r.Context(), cfg, back); err == nil && u != "" {
				http.Redirect(w, r, u, http.StatusFound)
				return
			}
		}
	}
	http.Redirect(w, r, "/signin", http.StatusFound)
}

// resolveHostQuietly is publicHost without writing an error: sign-out on
// a hostname nobody knows still clears the cookies and goes to sign-in.
func (g *Gateway) resolveHostQuietly(r *http.Request) (directory.Tenant, bool) {
	host, err := g.dir.ResolveHost(r.Context(), r.Host)
	if err != nil {
		return directory.Tenant{}, false
	}
	return host, true
}

// publicHost resolves the tenant for a route that runs before any credential
// exists. It answers exactly as entry does, so an unknown hostname says the
// same thing whether or not you are signed in.
//
// It also applies the rate limit, and that is the whole reason every public
// route goes through this one function rather than calling the directory
// itself. The limiter lives in entry, and these routes are the ones that do
// NOT go through entry, so without this they were unlimited. That mattered
// least for the sign-in redirect and most for enrolment, which parses a
// certificate signing request, verifies a signature and opens a database
// transaction before it has any idea who is asking.
func (g *Gateway) publicHost(w http.ResponseWriter, r *http.Request) (directory.Tenant, bool) {
	host, err := g.dir.ResolveHost(r.Context(), r.Host)
	if errors.Is(err, directory.ErrUnknownHost) {
		writeError(w, http.StatusNotFound, "unknown host")
		return directory.Tenant{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "host lookup failed")
		return directory.Tenant{}, false
	}
	if !host.Active() {
		writeError(w, http.StatusForbidden, "tenant is not active")
		return directory.Tenant{}, false
	}
	if !g.limiter.allow(host.ID, host.APIRatePerMin) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate limit for this plan exceeded")
		return directory.Tenant{}, false
	}
	return host, true
}

// wantsHTML decides whether to answer a browser or a program. It is the
// difference between a sign-in page and a 401 an API client can read.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// signInProblem tells the person what went wrong, in their tenant's own
// branding, without naming the platform operator.
func (g *Gateway) signInProblem(w http.ResponseWriter, r *http.Request,
	host directory.Tenant, status int, title, detail string) {

	if !wantsHTML(r) {
		writeError(w, status, title)
		return
	}
	if g.console == nil {
		http.Error(w, title+"\n\n"+detail, status)
		return
	}
	// The page still renders the tenant's own branding, and branding is
	// tenant data, so it still goes through row-level security. The claim
	// minted for it carries no identity at all: nobody has signed in, which
	// is why we are on this page.
	claim, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: "anonymous",
		Role: string(authz.Bootstrap), RequestID: uuid.NewString(),
	}, 30*time.Second)
	if err != nil {
		http.Error(w, title+"\n\n"+detail, status)
		return
	}
	g.console.Problem(w, r, claim, status, title, detail)
}
