package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/identity"
	"platform/internal/localauth"
	"platform/internal/notify"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

// Sign-in for a tenant that has no identity provider (0044).
//
// The shape, in the order a person meets it:
//
//	GET  /signin                  the form (signIn, which knows the tenant's mode)
//	POST /signin/local            email and password
//	GET/POST /signin/local/mfa    the second factor, for an account that has one
//	GET/POST /signin/local/enrol  setting it up, for a role that must have one
//	GET/POST /signin/local/accept/{token}   an invitation: choose a password
//	GET/POST /signin/local/forgot           ask for a reset link
//	GET/POST /signin/local/reset/{token}    a reset link: choose a new password
//
// Three rules run through all of it.
//
// What a stranger learns is nothing. A wrong password, an address with no
// account, a disabled account, an account that is locked and one that was
// never activated all get the same words and cost the same time, and the
// reset form says the same thing whether or not the address exists.
//
// A password alone is a half sign-in. When the account has a second factor
// the password step ends in a signed, short-lived cookie that is good for
// one thing: the second-factor page. No session exists until both are done,
// and the failure counter does not reset until both are.
//
// What the platform keeps is useless to whoever reads it: the password is an
// argon2id hash, the second-factor secret is sealed under the tenant's own
// key, recovery codes and links are kept as hashes.

const (
	localCookie = "mdm_local"
	pendingMark = "lmfa:"

	// The one answer for every way a sign-in can fail before the second
	// factor. It names the lock because a person who has just been locked
	// out deserves to be told, and it does so for everyone, so it says
	// nothing about any one address.
	localFailed = "That email and password did not match, or the account is locked or not yet active. After five wrong tries an account locks for fifteen minutes."
	codeFailed  = "That code did not work. Try the next one the app shows, or a recovery code."
)

// notices are the only good news a sign-in page will say, by code: the
// text comes from here, never from the query string.
var localNotices = map[string]string{
	"set":    "Your password is set. Sign in with it.",
	"reset":  "Your password is changed, and you have been signed out everywhere. Sign in with the new one.",
	"closed": "You are signed out.",
}

func (g *Gateway) anonClaim(host directory.Tenant, subject string) (string, error) {
	return g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: subject, Role: string(authz.Bootstrap), RequestID: uuid.NewString(),
	}, 30*time.Second)
}

// asBootstrap runs a tenant transaction for a request that has no session:
// the narrowest claim the signer will mint, naming whoever the work is about
// so the audit log has an actor.
func (g *Gateway) asBootstrap(ctx context.Context, host directory.Tenant, subject string,
	fn func(context.Context, *data.Tx) error) error {
	claim, err := g.anonClaim(host, subject)
	if err != nil {
		return err
	}
	return g.store.WithTenant(ctx, claim, fn)
}

// sameOrigin refuses a form posted from another site. A sign-in form is
// not worth a token of its own (the worst a forged one does is sign a
// person into somebody else's account), but the browser says where a POST
// came from and refusing the ones from elsewhere costs a comparison.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true // not a browser, or an old one
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

// localTenant resolves the hostname's tenant and insists it signs in with
// accounts held here. Everything below goes through it.
func (g *Gateway) localTenant(w http.ResponseWriter, r *http.Request) (directory.Tenant, identity.Config, bool) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return directory.Tenant{}, identity.Config{}, false
	}
	if g.sessions == nil || g.console == nil {
		g.signInProblem(w, r, host, http.StatusNotImplemented,
			"Sign-in is not available", "This deployment cannot sign people in.")
		return host, identity.Config{}, false
	}
	cfg, err := g.identityConfig(r.Context(), host)
	if errors.Is(err, directory.ErrNoIdentityConfig) || (err == nil && !cfg.IsLocal()) {
		// The control --break-localprotocol drops this refusal.
		g.signInProblem(w, r, host, http.StatusNotFound,
			"Not available", host.Name+" does not sign in with an email and a password.")
		return host, cfg, false
	}
	if err != nil {
		g.log.Error("identity config", "tenant", host.Slug, "err", err)
		g.signInProblem(w, r, host, http.StatusInternalServerError,
			"Sign-in is unavailable", "We could not read this organisation's sign-in settings.")
		return host, cfg, false
	}
	return host, cfg, true
}

func (g *Gateway) localRender(w http.ResponseWriter, r *http.Request, host directory.Tenant, status int, v console.LocalView) {
	claim, err := g.anonClaim(host, "anonymous")
	if err != nil {
		http.Error(w, v.Title, status)
		return
	}
	v.CanReset = g.mail != nil && g.notify != nil
	g.console.LocalPage(w, r, claim, status, v)
}

// localSignInPage is the email and password form.
func (g *Gateway) localSignInPage(w http.ResponseWriter, r *http.Request, host directory.Tenant, said string) {
	v := console.LocalView{Mode: "signin", Title: "Sign in to " + host.Name, Said: said,
		Next: localPath(r.URL.Query().Get("next")), Notice: localNotices[r.URL.Query().Get("notice")]}
	status := http.StatusOK
	if said != "" {
		status = http.StatusUnauthorized
	}
	g.localRender(w, r, host, status, v)
}

// limited applies the per-address limit shared by every form here: a guesser
// has one address, or a few, and the per-account lock below deals with the
// ones who have many.
func (g *Gateway) limited(w http.ResponseWriter, r *http.Request, host directory.Tenant, what string, perMinute int) bool {
	if g.limiter.allowKey("local:"+what+":"+g.callerIP(r), perMinute) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	g.signInProblem(w, r, host, http.StatusTooManyRequests,
		"Too many tries", "Too many attempts from this address. Wait a minute and try again.")
	return true
}

// ----------------------------------------------------------- the password

func (g *Gateway) localSignIn(w http.ResponseWriter, r *http.Request) {
	host, cfg, ok := g.localTenant(w, r)
	if !ok {
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "that form was not posted from this site")
		return
	}
	if g.limited(w, r, host, "signin", 10) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	email := data.NormaliseEmail(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	next := localPath(r.PostFormValue("next"))
	now := time.Now().UTC()

	failed := func() {
		v := console.LocalView{Mode: "signin", Title: "Sign in to " + host.Name, Said: localFailed, Email: email, Next: next}
		g.localRender(w, r, host, http.StatusUnauthorized, v)
	}

	var acct data.LocalAccount
	var found bool
	if err := g.asBootstrap(r.Context(), host, "anonymous", func(ctx context.Context, tx *data.Tx) error {
		var e error
		acct, found, e = data.LocalAccountByEmail(ctx, tx, email)
		return e
	}); err != nil {
		g.log.Error("local sign-in lookup", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}

	// An address with no account, an account that is not active, one that
	// has no password yet and one that is locked all end here, after
	// spending the time a real check would have. A locked account is not
	// checked at all: a guesser must not be told, by a correct answer
	// during the lock, that the lock was in the way.
	usable := found && acct.Status == "active" && acct.PasswordHash != "" && !acct.Locked(now)
	if !usable {
		localauth.VerifyAbsent(password)
		failed()
		return
	}
	if err := localauth.Verify(password, acct.PasswordHash); err != nil {
		if errors.Is(err, localauth.ErrBadHash) {
			g.log.Error("a stored password hash is unreadable", "tenant", host.Slug, "account", acct.ID)
		}
		g.countFailure(r.Context(), host, acct)
		failed()
		return
	}

	switch {
	case acct.TOTPEnabled:
		g.pendThen(w, r, host, "verify", acct.ID, next, "/signin/local/mfa")
	case data.MFARequired(cfg.LocalMFA, acct.Role):
		g.pendThen(w, r, host, "enrol", acct.ID, next, "/signin/local/enrol")
	default:
		g.completeLocalSignIn(w, r, host, acct.ID, next, nil)
	}
}

// countFailure adds one to the account's wrong-answer count and locks it
// when the count is reached. The control --break-lockout never locks.
func (g *Gateway) countFailure(ctx context.Context, host directory.Tenant, acct data.LocalAccount) {
	err := g.asBootstrap(ctx, host, acct.Subject(), func(ctx context.Context, tx *data.Tx) error {
		_, e := data.RecordLocalFailure(ctx, tx, acct.ID, time.Now().UTC())
		return e
	})
	if err != nil {
		g.log.Error("could not count a failed sign-in", "tenant", host.Slug, "account", acct.ID, "err", err)
	}
}

// pendThen ends the password step with a cookie that is good for the second
// factor and nothing else.
func (g *Gateway) pendThen(w http.ResponseWriter, r *http.Request, host directory.Tenant,
	purpose string, id uuid.UUID, next, to string) {

	flow, err := g.sessions.MintFlow(session.Flow{
		TenantID: host.ID, State: pendingMark + purpose + ":" + id.String(),
		Nonce: g.randomToken(), Return: next,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not continue the sign-in")
		return
	}
	g.setCookie(w, localCookie, flow, int(session.FlowLifetime/time.Second))
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// pending reads the cookie pendThen set: whose second step this is, which
// kind, and where to go afterwards.
func (g *Gateway) pending(r *http.Request, host directory.Tenant) (id uuid.UUID, purpose, next string, ok bool) {
	ck, err := r.Cookie(localCookie)
	if err != nil || ck.Value == "" {
		return uuid.Nil, "", "", false
	}
	flow, err := g.sessions.VerifyFlow(ck.Value)
	if err != nil || flow.TenantID != host.ID || !strings.HasPrefix(flow.State, pendingMark) {
		return uuid.Nil, "", "", false
	}
	rest := strings.TrimPrefix(flow.State, pendingMark)
	purpose, idText, found := strings.Cut(rest, ":")
	if !found || (purpose != "verify" && purpose != "enrol") {
		return uuid.Nil, "", "", false
	}
	id, err = uuid.Parse(idText)
	if err != nil {
		return uuid.Nil, "", "", false
	}
	return id, purpose, flow.Return, true
}

// ------------------------------------------------------- the second factor

// secondFactorAccount loads the account a pending cookie names and checks it
// is still one that may sign in. It opens the sealed secret when there is
// one: the secret exists in the clear for the length of this request.
func (g *Gateway) secondFactorAccount(ctx context.Context, host directory.Tenant, id uuid.UUID) (acct data.LocalAccount, secret []byte, ok bool, err error) {
	err = g.asBootstrap(ctx, host, data.LocalSubject(id), func(ctx context.Context, tx *data.Tx) error {
		a, e := data.LocalAccountByID(ctx, tx, id)
		if errors.Is(e, data.ErrNoSuchAccount) {
			return nil
		}
		if e != nil {
			return e
		}
		acct = a
		if a.Status != "active" || a.Locked(time.Now().UTC()) {
			return nil
		}
		ok = true
		if len(a.TOTPSealed) > 0 {
			if g.sealer == nil {
				return errors.New("no sealing key is configured")
			}
			secret, e = g.sealer.Open(ctx, tx, a.TOTPSealed)
		}
		return e
	})
	return acct, secret, ok && err == nil, err
}

func (g *Gateway) localMFA(w http.ResponseWriter, r *http.Request) {
	host, _, ok := g.localTenant(w, r)
	if !ok {
		return
	}
	id, purpose, next, ok := g.pending(r, host)
	if !ok || purpose != "verify" {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	view := console.LocalView{Mode: "mfa", Title: "One more step", Next: next}
	if r.Method == http.MethodGet {
		g.localRender(w, r, host, http.StatusOK, view)
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "that form was not posted from this site")
		return
	}
	if g.limited(w, r, host, "mfa", 10) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	typed := strings.TrimSpace(r.PostFormValue("code"))
	now := time.Now().UTC()

	acct, secret, usable, err := g.secondFactorAccount(r.Context(), host, id)
	if err != nil {
		g.log.Error("second factor lookup", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	if !usable || !acct.TOTPEnabled || secret == nil {
		g.clearCookie(w, localCookie)
		g.localSignInPage(w, r, host, localFailed)
		return
	}

	good := false
	err = g.asBootstrap(r.Context(), host, acct.Subject(), func(ctx context.Context, tx *data.Tx) error {
		if localauth.LooksLikeRecovery(typed) {
			// One statement: two people holding the same code cannot both spend it.
			used, e := data.UseRecoveryCode(ctx, tx, acct.ID, localauth.HashRecovery(typed))
			good = used
			return e
		}
		step, matched := localauth.Match(secret, typed, now)
		if !matched {
			return nil
		}
		// A code is good once: a step already accepted, or an earlier one,
		// is refused, so a code somebody watched being typed is no use.
		fresh, e := data.AcceptTOTPStep(ctx, tx, acct.ID, step)
		good = fresh
		return e
	})
	if err != nil {
		g.log.Error("second factor check", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	if !good {
		g.countFailure(r.Context(), host, acct)
		view.Said = codeFailed
		g.localRender(w, r, host, http.StatusUnauthorized, view)
		return
	}
	g.clearCookie(w, localCookie)
	g.completeLocalSignIn(w, r, host, acct.ID, next, nil)
}

func (g *Gateway) localEnrol(w http.ResponseWriter, r *http.Request) {
	host, _, ok := g.localTenant(w, r)
	if !ok {
		return
	}
	id, purpose, next, ok := g.pending(r, host)
	if !ok || purpose != "enrol" {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "that form was not posted from this site")
			return
		}
		if g.limited(w, r, host, "mfa", 10) {
			return
		}
	}

	// The secret: the one already waiting for this account if the page was
	// opened before, else a new one, kept sealed. Opening the page twice
	// must not replace what the first one put in somebody's phone.
	var acct data.LocalAccount
	var secret []byte
	usable := false
	err := g.asBootstrap(r.Context(), host, data.LocalSubject(id), func(ctx context.Context, tx *data.Tx) error {
		a, e := data.LocalAccountByID(ctx, tx, id)
		if errors.Is(e, data.ErrNoSuchAccount) {
			return nil
		}
		if e != nil {
			return e
		}
		acct = a
		if a.Status != "active" || a.Locked(time.Now().UTC()) || a.TOTPEnabled || g.sealer == nil {
			return nil
		}
		usable = true
		if len(a.TOTPSealed) == 0 {
			fresh, e := localauth.NewSecret()
			if e != nil {
				return e
			}
			sealed, e := g.sealer.Seal(ctx, tx, fresh)
			if e != nil {
				return e
			}
			set, e := data.SetPendingTOTP(ctx, tx, id, sealed)
			if e != nil {
				return e
			}
			if set {
				secret = fresh
				return nil
			}
			// Another request set one a moment ago: use that.
			a, e = data.LocalAccountByID(ctx, tx, id)
			if e != nil {
				return e
			}
		}
		secret, e = g.sealer.Open(ctx, tx, a.TOTPSealed)
		return e
	})
	if err != nil {
		g.log.Error("second factor enrolment", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	if !usable {
		g.clearCookie(w, localCookie)
		g.localSignInPage(w, r, host, localFailed)
		return
	}

	view := console.LocalView{Mode: "enrol", Title: "Set up the second step", Next: next,
		Secret: localauth.SecretText(secret)}
	uri := localauth.URI(host.Name, acct.Email, secret)
	if png, e := localauth.QRPNG(uri); e == nil {
		view.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	if r.Method == http.MethodGet {
		g.localRender(w, r, host, http.StatusOK, view)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	step, matched := localauth.Match(secret, r.PostFormValue("code"), time.Now().UTC())
	if !matched {
		g.countFailure(r.Context(), host, acct)
		view.Said = "That code did not match. Check that the app shows the entry for this organisation and try the next code."
		g.localRender(w, r, host, http.StatusUnauthorized, view)
		return
	}
	codes, hashes, err := localauth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not make recovery codes")
		return
	}
	if err := g.asBootstrap(r.Context(), host, acct.Subject(), func(ctx context.Context, tx *data.Tx) error {
		return data.EnableTOTP(ctx, tx, acct.ID, step, hashes)
	}); err != nil {
		g.log.Error("could not turn the second factor on", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	g.clearCookie(w, localCookie)
	g.completeLocalSignIn(w, r, host, acct.ID, next, codes)
}

// ------------------------------------------------------------ the session

// completeLocalSignIn is the end of a sign-in that has passed everything it
// needs to: the seat, the audit record and the session, in the order
// finishSignIn does them for a provider's sign-in. Codes, when given, are the
// recovery codes to show once before going on.
func (g *Gateway) completeLocalSignIn(w http.ResponseWriter, r *http.Request, host directory.Tenant,
	id uuid.UUID, next string, codes []string) {

	var acct data.LocalAccount
	refused := false
	err := g.asBootstrap(r.Context(), host, data.LocalSubject(id), func(ctx context.Context, tx *data.Tx) error {
		a, e := data.LocalAccountByID(ctx, tx, id)
		if e != nil {
			return e
		}
		acct = a
		if a.Status != "active" {
			refused = true
			return nil
		}
		claims := identity.Claims{Subject: a.Subject(), Email: a.Email, Name: a.Name}
		role := authz.Role(a.Role)
		// The seat, in the same transaction as the record that a sign-in
		// happened: an administrator with a session is an administrator
		// with a seat, and never one without.
		seated, e := takeSeat(ctx, tx, host.AdminSeats, claims, role)
		if e != nil {
			return e
		}
		if !seated {
			refused = true
			return seatRefused(ctx, tx, host.AdminSeats, claims, role)
		}
		if e := data.RecordLocalSuccess(ctx, tx, a.ID, time.Now().UTC()); e != nil {
			return e
		}
		return data.AppendAudit(ctx, tx, "session.start", "role:"+a.Role)
	})
	if err != nil {
		g.log.Error("local sign-in", "tenant", host.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	if refused {
		if acct.Status == "active" {
			g.signInProblem(w, r, host, http.StatusForbidden,
				"Every administrator seat is in use",
				fmt.Sprintf("Your sign-in worked, but %s has %d administrator seats and all of them are taken "+
					"by people who have signed in within the last 30 days. Ask a Super Admin to release a seat, "+
					"or to ask for a plan with more seats.", host.Name, host.AdminSeats))
			return
		}
		g.localSignInPage(w, r, host, localFailed)
		return
	}
	claims := identity.Claims{Subject: acct.Subject(), Email: acct.Email, Name: acct.Name}
	if !g.startSession(w, r, host, claims, authz.Role(acct.Role)) {
		return
	}
	to := next
	if to == "" {
		to = "/"
	}
	if len(codes) > 0 {
		g.localRender(w, r, host, http.StatusOK, console.LocalView{
			Mode: "codes", Title: "Save your recovery codes", Codes: codes, Continue: to})
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// endSessions ends every session one subject has, now. The stamp is the
// application's clock, not the database's, because a new session is often
// started a moment later (a password change) and the two clocks are not
// the same clock.
func (g *Gateway) endSessions(ctx context.Context, tx *data.Tx, host directory.Tenant, subject string, now time.Time) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_admins (tenant_id, subject, role, last_seen_at, sessions_invalid_before)
		VALUES (app.current_tenant(), $1, 'employee', to_timestamp(0), $2)
		ON CONFLICT (tenant_id, subject) DO UPDATE
		   SET sessions_invalid_before = GREATEST(tenant_admins.sessions_invalid_before, $2)`, subject, now); err != nil {
		return err
	}
	g.revoked.forget(host.ID, subject)
	return data.AppendAudit(ctx, tx, "session.revoked", subject)
}

// -------------------------------------------------------------- the links

// newLocalToken makes a link's token and the hash that is kept.
func newLocalToken() (token string, hash []byte, err error) { return localauth.NewToken() }

func localTokenHash(token string) ([]byte, bool) { return localauth.TokenHash(token) }

// consoleBaseOf is where this tenant's console is, for a link in an email:
// the host the request arrived on, which publicHost has already checked is
// one of the tenant's own.
func (g *Gateway) consoleBaseOf(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && g.insecureCookies {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// linkPage is the page a link opens: the password form if the link is good,
// and an honest dead end if it is not.
func (g *Gateway) linkPage(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, ok := g.localTenant(w, r)
		if !ok {
			return
		}
		token := r.PathValue("token")
		hash, valid := localTokenHash(token)
		var acct data.LocalAccount
		found := false
		if valid {
			_ = g.asBootstrap(r.Context(), host, "anonymous", func(ctx context.Context, tx *data.Tx) error {
				var e error
				acct, found, e = data.PeekLocalToken(ctx, tx, hash, purpose, time.Now().UTC())
				return e
			})
		}
		if !found {
			g.localRender(w, r, host, http.StatusGone, console.LocalView{
				Mode: "notice", Title: "That link has expired",
				Said: "It was already used, or it ran out. Ask your administrator for a new one, or use \"Forgot your password?\" on the sign-in page."})
			return
		}
		title := "Choose a password"
		if purpose == "reset" {
			title = "Choose a new password"
		}
		g.localRender(w, r, host, http.StatusOK, console.LocalView{
			Mode: purpose2mode(purpose), Title: title, Email: acct.Email, Name: acct.Name, Token: token})
	}
}

func purpose2mode(purpose string) string {
	if purpose == "invite" {
		return "accept"
	}
	return "reset"
}

// setPassword is the POST of the two pages above: check the password, spend
// the link, store the hash, in one transaction. A password the policy
// refuses does not cost the person their link.
func (g *Gateway) setPassword(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, ok := g.localTenant(w, r)
		if !ok {
			return
		}
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "that form was not posted from this site")
			return
		}
		if g.limited(w, r, host, "setpw", 10) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "that form could not be read")
			return
		}
		token := r.PathValue("token")
		hash, valid := localTokenHash(token)
		now := time.Now().UTC()
		var acct data.LocalAccount
		found := false
		if valid {
			_ = g.asBootstrap(r.Context(), host, "anonymous", func(ctx context.Context, tx *data.Tx) error {
				var e error
				acct, found, e = data.PeekLocalToken(ctx, tx, hash, purpose, now)
				return e
			})
		}
		if !found {
			g.localRender(w, r, host, http.StatusGone, console.LocalView{
				Mode: "notice", Title: "That link has expired",
				Said: "It was already used, or it ran out. Ask your administrator for a new one."})
			return
		}
		redo := func(msg string) {
			g.localRender(w, r, host, http.StatusUnprocessableEntity, console.LocalView{
				Mode: purpose2mode(purpose), Title: "Choose a password", Said: msg,
				Email: acct.Email, Name: acct.Name, Token: token})
		}
		pw := r.PostFormValue("password")
		if pw != r.PostFormValue("confirm") {
			redo("The two passwords are not the same.")
			return
		}
		if err := localauth.CheckPassword(pw, acct.Email, acct.Name, host.Name); err != nil {
			redo("That password will not do: " + err.Error() + ".")
			return
		}
		encoded, err := localauth.Hash(pw)
		if err != nil {
			redo("That password could not be used.")
			return
		}
		err = g.asBootstrap(r.Context(), host, acct.Subject(), func(ctx context.Context, tx *data.Tx) error {
			// The control --break-localtoken does not spend the link.
			id, e := data.SpendLocalToken(ctx, tx, hash, purpose, now)
			if e != nil {
				return e
			}
			if id != acct.ID {
				return data.ErrTokenNotUsable
			}
			if e := data.SetLocalPassword(ctx, tx, acct.ID, encoded, now); e != nil {
				return e
			}
			if purpose == "reset" {
				// Whoever had the old password, or a session made with
				// it, is signed out. The second factor is not touched: a
				// reset link in an inbox must not be a way round it.
				return g.endSessions(ctx, tx, host, acct.Subject(), now)
			}
			return nil
		})
		if errors.Is(err, data.ErrTokenNotUsable) {
			g.localRender(w, r, host, http.StatusGone, console.LocalView{
				Mode: "notice", Title: "That link has expired",
				Said: "It was used a moment ago. Ask your administrator for a new one."})
			return
		}
		if err != nil {
			g.log.Error("could not set a password", "tenant", host.Slug, "err", err)
			writeError(w, http.StatusInternalServerError, "could not set the password")
			return
		}
		notice := "set"
		if purpose == "reset" {
			notice = "reset"
		}
		http.Redirect(w, r, "/signin?notice="+notice, http.StatusSeeOther)
	}
}

// ------------------------------------------------------------- forgotten

func (g *Gateway) localForgot(w http.ResponseWriter, r *http.Request) {
	host, _, ok := g.localTenant(w, r)
	if !ok {
		return
	}
	view := console.LocalView{Mode: "forgot", Title: "Reset your password"}
	if r.Method == http.MethodGet {
		g.localRender(w, r, host, http.StatusOK, view)
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "that form was not posted from this site")
		return
	}
	if g.limited(w, r, host, "forgot", 5) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	email := data.NormaliseEmail(r.PostFormValue("email"))

	// The answer is the same whether or not the address has an account,
	// and arrives in the same time: the lookup, the token and the mail all
	// happen after it has been sent. One link a minute per address, so the
	// form cannot be used to fill somebody's inbox.
	if email != "" && g.mail != nil && g.notify != nil &&
		g.limiter.allowKey("local:forgot-for:"+host.ID.String()+":"+email, 1) {
		base := g.consoleBaseOf(r)
		go g.sendResetLink(host, email, base)
	}
	view.Notice = "If that address has an account here, a link is on its way. It works once, for an hour."
	view.CanReset = false
	g.localRender(w, r, host, http.StatusOK, view)
}

// sendResetLink makes the link and mails it, off the request. Its failures
// are logged and go no further: the person at the form has already been
// told what they will be told.
func (g *Gateway) sendResetLink(host directory.Tenant, email, base string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	token, hash, err := newLocalToken()
	if err != nil {
		g.log.Error("reset token", "err", err)
		return
	}
	var msg notify.Message
	send := false
	err = g.asBootstrap(ctx, host, "anonymous", func(ctx context.Context, tx *data.Tx) error {
		acct, found, e := data.LocalAccountByEmail(ctx, tx, email)
		if e != nil || !found || acct.Status == "disabled" {
			return e
		}
		now := time.Now().UTC()
		if e := data.IssueLocalToken(ctx, tx, acct.ID, "reset", hash, now.Add(data.ResetLife), now); e != nil {
			return e
		}
		msg = notify.Message{
			Subject: "Reset your password for " + host.Name,
			Body: "Someone asked to reset the password for " + acct.Email + " at " + host.Name + ".\n\n" +
				"If that was you, choose a new one here. The link works once, for an hour:\n\n  " +
				base + "/signin/local/reset/" + token + "\n\n" +
				"If it was not you, ignore this message: nothing has changed, and your password still works.\n",
		}
		if e := g.notify.Stamp(ctx, tx, &msg); e != nil {
			return e
		}
		send = true
		return data.AppendAudit(ctx, tx, "local.reset_requested", "account:"+acct.ID.String())
	})
	if err != nil {
		g.log.Error("reset link", "tenant", host.Slug, "err", err)
		return
	}
	if !send {
		return
	}
	if err := g.mail.Deliver(ctx, email, msg); err != nil {
		g.log.Error("reset email", "tenant", host.Slug, "err", err)
	}
}
