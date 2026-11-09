package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"platform/internal/console"
	"platform/internal/directory"
	"platform/internal/localauth"
	"platform/internal/session"
)

// The platform owner's console (0048).
//
// It is served on its own hostname and on nothing else, decided before the
// tenant router looks at the request, so a customer's hostname never serves a
// page from here and this hostname never serves a customer. It has its own
// accounts, which no customer-facing database role can read; every owner signs
// in with a password and an authenticator, and the database refuses an active
// owner who lacks either. What it shows is what the operator's database role
// may read: organisations as a shell and usage as counts, never a device, a
// person or a policy.
//
//	GET  /signin                 the form
//	POST /signin                 email and password
//	GET/POST /signin/mfa         the second factor
//	GET/POST /signin/enrol       setting the second factor up (only after a link)
//	GET/POST /accept/{token}     an invitation: choose a password, then enrol
//	GET/POST /reset/{token}      a reset link: choose a new password
//	POST /signout
//	GET  /, /orgs, /orgs/{slug}, /signups, /licences, /operators, /events, /account

const (
	opsCookie  = "mdm_ops"
	opsPending = "mdm_ops_pending"
	opsRole    = "platform_operator"
	opsMark    = "ops:"

	opsFailed     = "That email and password did not match, or the account is locked or not yet active. After five wrong tries an account locks for fifteen minutes."
	opsCodeFailed = "That code did not work. Try the next one the app shows, or a recovery code."
)

// opsRealm is the "tenant" an owner's session carries. It is a fixed number no
// organisation can have (their ids are random), so an owner's session never
// verifies on an organisation's hostname and an organisation's never verifies
// here: the comparison every request already makes does the work.
var opsRealm = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")

// OperatorConfig turns the owner's console on. Nil means it is absent, not
// refused: the routes do not exist.
type OperatorConfig struct {
	// Host is the one hostname that serves it.
	Host string
}

func hostIs(reqHost, want string) bool {
	h := strings.ToLower(reqHost)
	if i := strings.LastIndex(h, ":"); i != -1 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	return h == strings.ToLower(want)
}

var opsNotices = map[string]string{
	"set":    "Your password is changed. Sign in with it.",
	"closed": "You are signed out.",
}

// opsSession is what an owner's page handler is given.
type opsSession struct {
	Op   directory.Operator
	Sess session.Session
	CSRF string
}

func opsSubject(id uuid.UUID) string { return opsMark + id.String() }

// ------------------------------------------------------------- the handler

func (g *Gateway) opsHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /signin", g.opsSignInPage)
	m.HandleFunc("POST /signin", g.opsSignIn)
	m.HandleFunc("GET /signin/mfa", g.opsMFA)
	m.HandleFunc("POST /signin/mfa", g.opsMFA)
	m.HandleFunc("GET /signin/enrol", g.opsEnrol)
	m.HandleFunc("POST /signin/enrol", g.opsEnrol)
	m.HandleFunc("GET /accept/{token}", g.opsLinkPage("invite"))
	m.HandleFunc("POST /accept/{token}", g.opsSetPassword("invite"))
	m.HandleFunc("GET /reset/{token}", g.opsLinkPage("reset"))
	m.HandleFunc("POST /reset/{token}", g.opsSetPassword("reset"))
	m.HandleFunc("POST /signout", g.opsSignOut)

	m.Handle("GET /{$}", g.opsAuthed("/", g.opsDash))
	m.Handle("GET /orgs", g.opsAuthed("/orgs", g.opsOrgList))
	m.Handle("GET /orgs/{slug}", g.opsAuthed("/orgs", g.opsOrgPage))
	m.Handle("GET /signups", g.opsAuthed("/signups", g.opsSignups))
	m.Handle("GET /licences", g.opsAuthed("/licences", g.opsLicences))
	m.Handle("GET /operators", g.opsAuthed("/operators", g.opsOperators))
	m.Handle("GET /events", g.opsAuthed("/events", g.opsEvents))

	// What an owner can change (ops_actions.go).
	m.Handle("POST /orgs/{slug}/suspend", g.opsSuspend())
	m.Handle("POST /orgs/{slug}/resume", g.opsResume())
	m.Handle("POST /orgs/{slug}/plan", g.opsPlan())
	m.Handle("POST /orgs/{slug}/quota", g.opsQuota())
	m.Handle("POST /orgs/{slug}/feature", g.opsFeature())
	m.Handle("POST /signups/cancel", g.opsCancelSignup())
	m.Handle("POST /operators/invite", g.opsInvite())
	m.Handle("POST /operators/{id}/link", g.opsOwnerAct(true, func(*http.Request, opsSession, directory.Operator) error { return nil }, ""))
	m.Handle("POST /operators/{id}/disable", g.opsOwnerAct(false, func(r *http.Request, s opsSession, o directory.Operator) error {
		return g.dir.SetOperatorStatus(r.Context(), o.ID, true, s.Op.Email)
	}, "disabled"))
	m.Handle("POST /operators/{id}/enable", g.opsOwnerAct(true, func(r *http.Request, s opsSession, o directory.Operator) error {
		return g.dir.SetOperatorStatus(r.Context(), o.ID, false, s.Op.Email)
	}, "enabled"))
	m.Handle("POST /operators/{id}/reset-mfa", g.opsOwnerAct(false, func(r *http.Request, s opsSession, o directory.Operator) error {
		return g.dir.ResetOperatorMFA(r.Context(), o.ID, s.Op.Email)
	}, "mfareset"))
	m.Handle("GET /account", g.opsAuthed("/account", g.opsAccount))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		console.RenderOps(w, http.StatusNotFound, console.OpsView{Page: "ops_closed", Title: "Not found",
			Said: "There is nothing at that address."})
	})
	return m
}

func (g *Gateway) setOpsCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/",
		// Strict: nothing on the owner's console is reached from another site,
		// so the cookie is not sent when it is.
		SameSite: http.SameSiteStrictMode, HttpOnly: true, Secure: !g.insecureCookies, MaxAge: maxAge,
	})
}

func (g *Gateway) clearOpsCookie(w http.ResponseWriter, name string) { g.setOpsCookie(w, name, "", -1) }

// opsLimited applies the per-address limit shared by the forms here.
func (g *Gateway) opsLimited(w http.ResponseWriter, r *http.Request, what string, perMinute int) bool {
	if g.limiter.allowKey("ops:"+what+":"+g.callerIP(r), perMinute) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	console.RenderOps(w, http.StatusTooManyRequests, console.OpsView{Page: "ops_closed", Title: "Too many tries",
		Said: "Too many attempts from this address. Wait a minute and try again."})
	return true
}

// opsSessionFrom checks the cookie and the account behind it. The account is
// read on every request: disabling an owner, or resetting their second factor,
// ends their session at the next click rather than at its expiry.
func (g *Gateway) opsSessionFrom(r *http.Request) (opsSession, bool) {
	ck, err := r.Cookie(opsCookie)
	if err != nil || ck.Value == "" || g.sessions == nil {
		return opsSession{}, false
	}
	sess, err := g.sessions.Verify(ck.Value)
	if err != nil || sess.TenantID != opsRealm || sess.Role != opsRole || !strings.HasPrefix(sess.Subject, opsMark) {
		return opsSession{}, false
	}
	id, err := uuid.Parse(strings.TrimPrefix(sess.Subject, opsMark))
	if err != nil {
		return opsSession{}, false
	}
	op, err := g.dir.OperatorByID(r.Context(), id)
	if err != nil || op.Status != "active" || !op.TOTPEnabled {
		return opsSession{}, false
	}
	// A password changed, a second factor reset or an account disabled after
	// this session began ends it, even if the account is active again.
	if op.SessionsInvalidBefore != nil && op.SessionsInvalidBefore.After(sess.StartedAt) {
		return opsSession{}, false
	}
	return opsSession{Op: op, Sess: sess, CSRF: g.csrfFor(opsRealm, sess.Subject, opsRole)}, true
}

func (g *Gateway) opsAuthed(active string, h func(http.ResponseWriter, *http.Request, opsSession)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := g.opsSessionFrom(r)
		if !ok {
			g.clearOpsCookie(w, opsCookie)
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}
		if s.Sess.ShouldRenew() {
			if tok, _, err := g.sessions.Renew(s.Sess); err == nil {
				g.setOpsCookie(w, opsCookie, tok, int(session.Lifetime/time.Second))
			}
		}
		h(w, r, s)
	})
}

func (g *Gateway) opsBase(s opsSession, active, page, title string) console.OpsView {
	return console.OpsView{Page: page, Title: title, CSRF: s.CSRF, Nav: console.OpsNavFor(active),
		Who: &console.OpsWho{Email: s.Op.Email, Name: s.Op.Name}}
}

// --------------------------------------------------------------- sign-in

func (g *Gateway) opsSignInPage(w http.ResponseWriter, r *http.Request) {
	v := console.OpsView{Page: "ops_signin", Title: "Sign in", Notice: opsNotices[r.URL.Query().Get("notice")]}
	console.RenderOps(w, http.StatusOK, v)
}

func (g *Gateway) opsFail(w http.ResponseWriter, email string) {
	console.RenderOps(w, http.StatusUnauthorized, console.OpsView{Page: "ops_signin", Title: "Sign in", Said: opsFailed, Email: email})
}

func (g *Gateway) opsSignIn(w http.ResponseWriter, r *http.Request) {
	if g.sessions == nil || g.keys == nil {
		console.RenderOps(w, http.StatusNotImplemented, console.OpsView{Page: "ops_closed", Title: "Not available",
			Said: "This deployment cannot sign owners in."})
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "that form was not posted from this site")
		return
	}
	if g.opsLimited(w, r, "signin", 10) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	email := directory.NormaliseOperatorEmail(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	now := time.Now().UTC()

	op, err := g.dir.OperatorByEmail(r.Context(), email)
	found := err == nil
	if err != nil && !errors.Is(err, directory.ErrNoSuchOperator) {
		g.log.Error("owner sign-in lookup", "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	// Active only. An invited account has no way in but its link: a password
	// set by somebody else must not be a route to choosing the second factor.
	usable := found && op.Status == "active" && op.PasswordHash != "" && op.TOTPEnabled && !op.Locked(now)
	if !usable {
		localauth.VerifyAbsent(password)
		g.opsFail(w, email)
		return
	}
	if err := localauth.Verify(password, op.PasswordHash); err != nil {
		if errors.Is(err, localauth.ErrBadHash) {
			g.log.Error("an owner's stored password hash is unreadable", "operator", op.ID)
		}
		if _, e := g.dir.RecordOperatorFailure(r.Context(), op.ID, now); e != nil {
			g.log.Error("could not count a failed owner sign-in", "err", e)
		}
		g.opsFail(w, email)
		return
	}
	if !g.opsPend(w, op.ID, "verify") {
		return
	}
	http.Redirect(w, r, "/signin/mfa", http.StatusSeeOther)
}

// opsPend ends a step with a cookie good for the next step and nothing else.
func (g *Gateway) opsPend(w http.ResponseWriter, id uuid.UUID, purpose string) bool {
	flow, err := g.sessions.MintFlow(session.Flow{TenantID: opsRealm,
		State: opsMark + purpose + ":" + id.String(), Nonce: g.randomToken()})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not continue the sign-in")
		return false
	}
	g.setOpsCookie(w, opsPending, flow, int(session.FlowLifetime/time.Second))
	return true
}

func (g *Gateway) opsPendingFrom(r *http.Request) (id uuid.UUID, purpose string, started time.Time, ok bool) {
	ck, err := r.Cookie(opsPending)
	if err != nil || ck.Value == "" || g.sessions == nil {
		return uuid.Nil, "", time.Time{}, false
	}
	flow, err := g.sessions.VerifyFlow(ck.Value)
	if err != nil || flow.TenantID != opsRealm || !strings.HasPrefix(flow.State, opsMark) {
		return uuid.Nil, "", time.Time{}, false
	}
	purpose, idText, found := strings.Cut(strings.TrimPrefix(flow.State, opsMark), ":")
	if !found || (purpose != "verify" && purpose != "enrol") {
		return uuid.Nil, "", time.Time{}, false
	}
	id, err = uuid.Parse(idText)
	if err != nil {
		return uuid.Nil, "", time.Time{}, false
	}
	return id, purpose, flow.ExpiresAt.Add(-session.FlowLifetime), true
}

func (g *Gateway) opsMFA(w http.ResponseWriter, r *http.Request) {
	id, purpose, started, ok := g.opsPendingFrom(r)
	if !ok || purpose != "verify" {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	view := console.OpsView{Page: "ops_mfa", Title: "Second step"}
	if r.Method == http.MethodGet {
		console.RenderOps(w, http.StatusOK, view)
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "that form was not posted from this site")
		return
	}
	if g.opsLimited(w, r, "mfa", 10) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	typed := strings.TrimSpace(r.PostFormValue("code"))
	now := time.Now().UTC()

	op, err := g.dir.OperatorByID(r.Context(), id)
	if err != nil || op.Status != "active" || !op.TOTPEnabled || op.Locked(now) || len(op.TOTPSealed) == 0 || opsPendingStale(op, started) {
		g.clearOpsCookie(w, opsPending)
		g.opsFail(w, "")
		return
	}
	secret, err := g.keys.OpenMaster(op.TOTPSealed)
	if err != nil {
		g.log.Error("an owner's second-factor secret will not open", "operator", op.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	good := false
	if localauth.LooksLikeRecovery(typed) {
		good, err = g.dir.UseOperatorRecovery(r.Context(), op.ID, localauth.HashRecovery(typed))
	} else if step, matched := localauth.Match(secret, typed, now); matched {
		// A code is good once: a step already accepted is refused, so a code
		// somebody watched being typed is no use.
		good, err = g.dir.AcceptOperatorTOTPStep(r.Context(), op.ID, step)
	}
	if err != nil {
		g.log.Error("owner second factor", "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	if !good {
		if _, e := g.dir.RecordOperatorFailure(r.Context(), op.ID, now); e != nil {
			g.log.Error("could not count a failed owner code", "err", e)
		}
		view.Said = opsCodeFailed
		console.RenderOps(w, http.StatusUnauthorized, view)
		return
	}
	g.clearOpsCookie(w, opsPending)
	g.opsStart(w, r, op, nil)
}

// opsPendingStale says a half-finished sign-in began before the account was
// disabled, reset or given a new password, and so is not to be finished.
func opsPendingStale(op directory.Operator, started time.Time) bool {
	return op.SessionsInvalidBefore != nil && op.SessionsInvalidBefore.After(started)
}

// opsLinkFits says a link is for the state the account is in now. An
// invitation sets up an authenticator, so it fits only an account without one;
// a reset changes a password and fits only an account that has one. A reset
// link must never be a way to choose an authenticator.
func opsLinkFits(purpose string, op directory.Operator) bool {
	if purpose == "reset" {
		return op.TOTPEnabled
	}
	return !op.TOTPEnabled
}

// opsEnrol sets the second factor up. It is reached only from a link, which
// is what proves who is doing it.
func (g *Gateway) opsEnrol(w http.ResponseWriter, r *http.Request) {
	id, purpose, started, ok := g.opsPendingFrom(r)
	if !ok || purpose != "enrol" {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "that form was not posted from this site")
			return
		}
		if g.opsLimited(w, r, "mfa", 10) {
			return
		}
	}
	now := time.Now().UTC()
	op, err := g.dir.OperatorByID(r.Context(), id)
	if err != nil || op.Status == "disabled" || op.TOTPEnabled || op.PasswordHash == "" || op.Locked(now) || g.keys == nil || opsPendingStale(op, started) {
		g.clearOpsCookie(w, opsPending)
		g.opsFail(w, "")
		return
	}
	// The secret already waiting for this account if the page was opened
	// before, else a new one: opening the page twice must not replace what the
	// first one put in somebody's phone.
	var secret []byte
	if len(op.TOTPSealed) == 0 {
		fresh, e := localauth.NewSecret()
		if e != nil {
			writeError(w, http.StatusInternalServerError, "could not make a secret")
			return
		}
		sealed, e := g.keys.SealMaster(fresh)
		if e != nil {
			g.log.Error("could not seal an owner's secret", "err", e)
			writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
			return
		}
		set, e := g.dir.SetPendingOperatorTOTP(r.Context(), op.ID, sealed)
		if e != nil {
			g.log.Error("could not store an owner's secret", "err", e)
			writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
			return
		}
		if set {
			secret = fresh
		} else if op, err = g.dir.OperatorByID(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
			return
		}
	}
	if secret == nil {
		if secret, err = g.keys.OpenMaster(op.TOTPSealed); err != nil {
			g.log.Error("an owner's pending secret will not open", "err", err)
			writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
			return
		}
	}
	view := console.OpsView{Page: "ops_enrol", Title: "Set up your authenticator", Secret: localauth.SecretText(secret)}
	if png, e := localauth.QRPNG(localauth.URI("Platform operations", op.Email, secret)); e == nil {
		view.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	if r.Method == http.MethodGet {
		console.RenderOps(w, http.StatusOK, view)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	step, matched := localauth.Match(secret, r.PostFormValue("code"), now)
	if !matched {
		if _, e := g.dir.RecordOperatorFailure(r.Context(), op.ID, now); e != nil {
			g.log.Error("could not count a failed owner code", "err", e)
		}
		view.Said = "That code did not match. Check that the app shows the entry for Platform operations and try the next code."
		console.RenderOps(w, http.StatusUnauthorized, view)
		return
	}
	codes, hashes, err := localauth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not make recovery codes")
		return
	}
	if err := g.dir.EnableOperatorTOTP(r.Context(), op.ID, step, hashes); err != nil {
		g.log.Error("could not turn an owner's second factor on", "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	op, err = g.dir.OperatorByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	g.clearOpsCookie(w, opsPending)
	g.opsStart(w, r, op, codes)
}

// opsStart is the end of a full sign-in: the count cleared, the record made,
// the session set. Codes, when given, are shown once before going on.
func (g *Gateway) opsStart(w http.ResponseWriter, r *http.Request, op directory.Operator, codes []string) {
	now := time.Now().UTC()
	if op.Status != "active" {
		g.opsFail(w, "")
		return
	}
	if err := g.dir.RecordOperatorSuccess(r.Context(), op.ID, now); err != nil {
		g.log.Error("owner sign-in record", "err", err)
		writeError(w, http.StatusInternalServerError, "sign-in is unavailable")
		return
	}
	_ = g.dir.OperatorEvent(r.Context(), op.Email, "operator.signed_in", op.ID.String(), g.callerIP(r))
	tok, _, err := g.sessions.Start(session.Session{TenantID: opsRealm, Subject: opsSubject(op.ID),
		Email: op.Email, Name: op.Name, Role: opsRole})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start the session")
		return
	}
	g.setOpsCookie(w, opsCookie, tok, int(session.Lifetime/time.Second))
	if len(codes) > 0 {
		console.RenderOps(w, http.StatusOK, console.OpsView{Page: "ops_codes", Title: "Recovery codes", Codes: codes})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (g *Gateway) opsSignOut(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "that form was not posted from this site")
		return
	}
	if s, ok := g.opsSessionFrom(r); ok {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if r.ParseForm() == nil && g.csrfMatches(r.PostFormValue("csrf"), opsRealm, s.Sess.Subject, opsRole) {
			_ = g.dir.OperatorEvent(r.Context(), s.Op.Email, "operator.signed_out", s.Op.ID.String(), "")
		}
	}
	g.clearOpsCookie(w, opsCookie)
	g.clearOpsCookie(w, opsPending)
	http.Redirect(w, r, "/signin?notice=closed", http.StatusSeeOther)
}

// ------------------------------------------------------------- the links

func (g *Gateway) opsLinkPage(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash, valid := localauth.TokenHash(r.PathValue("token"))
		var op directory.Operator
		found := false
		if valid {
			var err error
			op, found, err = g.dir.PeekOperatorToken(r.Context(), hash, purpose, time.Now().UTC())
			if err != nil {
				g.log.Error("owner link", "err", err)
				found = false
			}
		}
		if !found || !opsLinkFits(purpose, op) {
			console.RenderOps(w, http.StatusGone, console.OpsView{Page: "ops_closed", Title: "That link has expired",
				Said: "It was already used, or it ran out. Ask another owner for a new one."})
			return
		}
		title := "Choose a password"
		if purpose == "reset" {
			title = "Choose a new password"
		}
		console.RenderOps(w, http.StatusOK, console.OpsView{Page: "ops_link", Title: title, Email: op.Email})
	}
}

func (g *Gateway) opsSetPassword(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "that form was not posted from this site")
			return
		}
		if g.opsLimited(w, r, "setpw", 10) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "that form could not be read")
			return
		}
		now := time.Now().UTC()
		hash, valid := localauth.TokenHash(r.PathValue("token"))
		var op directory.Operator
		found := false
		if valid {
			var err error
			if op, found, err = g.dir.PeekOperatorToken(r.Context(), hash, purpose, now); err != nil {
				g.log.Error("owner link", "err", err)
				found = false
			}
		}
		gone := func(said string) {
			console.RenderOps(w, http.StatusGone, console.OpsView{Page: "ops_closed", Title: "That link has expired", Said: said})
		}
		if !found || !opsLinkFits(purpose, op) {
			gone("It was already used, or it ran out. Ask another owner for a new one.")
			return
		}
		redo := func(msg string) {
			console.RenderOps(w, http.StatusUnprocessableEntity, console.OpsView{Page: "ops_link",
				Title: "Choose a password", Said: msg, Email: op.Email})
		}
		pw := r.PostFormValue("password")
		if pw != r.PostFormValue("confirm") {
			redo("The two passwords are not the same.")
			return
		}
		if err := localauth.CheckPassword(pw, op.Email, op.Name, "platform", "operations", "vlume"); err != nil {
			redo("That password will not do: " + err.Error() + ".")
			return
		}
		encoded, err := localauth.Hash(pw)
		if err != nil {
			redo("That password could not be used.")
			return
		}
		// The link first, atomically: two uses at once cannot both get through.
		id, err := g.dir.SpendOperatorToken(r.Context(), hash, purpose, now)
		if errors.Is(err, directory.ErrOperatorLink) || (err == nil && id != op.ID) {
			gone("It was used a moment ago. Ask another owner for a new one.")
			return
		}
		if err != nil {
			g.log.Error("owner link", "err", err)
			writeError(w, http.StatusInternalServerError, "could not set the password")
			return
		}
		if err := g.dir.SetOperatorPassword(r.Context(), op.ID, encoded, now); err != nil {
			g.log.Error("could not set an owner's password", "err", err)
			writeError(w, http.StatusInternalServerError, "could not set the password")
			return
		}
		_ = g.dir.OperatorEvent(r.Context(), op.Email, "operator.password_set", op.ID.String(), purpose)
		if !op.TOTPEnabled {
			// No authenticator yet (a first sign-in, or one that was reset):
			// the link is the proof of who this is, so go straight to it.
			if g.opsPend(w, op.ID, "enrol") {
				http.Redirect(w, r, "/signin/enrol", http.StatusSeeOther)
			}
			return
		}
		http.Redirect(w, r, "/signin?notice=set", http.StatusSeeOther)
	}
}

// --------------------------------------------------------------- the pages

// opsOrgCache keeps the organisations list for a few seconds, so reloading a
// page does not re-count every customer.
type opsOrgCache struct {
	mu   sync.Mutex
	at   time.Time
	orgs []console.OpsOrg
}

const opsCacheFor = 20 * time.Second

func opsMeasure(s directory.Summary, u directory.Usage, err error) console.OpsOrg {
	o := console.OpsOrg{Summary: s}
	if err != nil {
		o.NoUsage = true
		return o
	}
	o.Devices, o.DeviceCap, o.Seats, o.SeatCap = u.ActiveDevices, u.DeviceCap, u.SeatsUsed, u.AdminSeats
	if o.DeviceCap > 0 {
		p := o.Devices * 100 / o.DeviceCap
		if p > 100 {
			p = 100
		}
		o.Percent = p
		switch {
		case o.Devices >= o.DeviceCap:
			o.Flag = "over"
		case o.Devices*100 >= o.DeviceCap*80:
			o.Flag = "near"
		}
	}
	return o
}

func (g *Gateway) opsOrgs(ctx context.Context) ([]console.OpsOrg, error) {
	c := &g.opsCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.orgs != nil && time.Since(c.at) < opsCacheFor {
		return append([]console.OpsOrg(nil), c.orgs...), nil
	}
	list, err := g.dir.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]console.OpsOrg, 0, len(list))
	for _, s := range list {
		u, uerr := g.dir.Usage(ctx, s.ID)
		if uerr != nil {
			g.log.Error("owner console: usage", "tenant", s.Slug, "err", uerr)
		}
		out = append(out, opsMeasure(s, u, uerr))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	c.orgs, c.at = out, time.Now()
	return append([]console.OpsOrg(nil), out...), nil
}

func (g *Gateway) opsFailPage(w http.ResponseWriter, s opsSession, active string, what string, err error) {
	g.log.Error("owner console: "+what, "err", err)
	v := g.opsBase(s, active, "ops_closed", "Could not read that")
	v.Said = "That could not be read just now. Try again in a moment."
	console.RenderOps(w, http.StatusInternalServerError, v)
}

func (g *Gateway) opsDash(w http.ResponseWriter, r *http.Request, s opsSession) {
	orgs, err := g.opsOrgs(r.Context())
	if err != nil {
		g.opsFailPage(w, s, "/", "organisations", err)
		return
	}
	signups, err := g.dir.ListSignups(r.Context(), true)
	if err != nil {
		g.opsFailPage(w, s, "/", "sign-ups", err)
		return
	}
	d := console.OpsDash{Orgs: len(orgs)}
	now := time.Now()
	plans := map[string]int{}
	for _, o := range orgs {
		switch o.Status {
		case "active", "near_cap":
			d.Active++
		case "suspended":
			d.Suspended++
		default:
			d.Other++
		}
		d.Devices += o.Devices
		if now.Sub(o.CreatedAt) <= 7*24*time.Hour {
			d.NewWeek++
		}
		if now.Sub(o.CreatedAt) <= 30*24*time.Hour {
			d.NewMonth++
		}
		if o.Flag != "" {
			d.NearCap++
		}
		plans[o.Plan]++
	}
	seen := map[string]bool{}
	for _, p := range directory.Plans() {
		if n := plans[p.Name]; n > 0 {
			d.ByPlan = append(d.ByPlan, console.OpsCount{Label: p.Name, N: n})
		}
		seen[p.Name] = true
	}
	var other []string
	for name := range plans {
		if !seen[name] {
			other = append(other, name)
		}
	}
	sort.Strings(other)
	for _, name := range other {
		d.ByPlan = append(d.ByPlan, console.OpsCount{Label: name, N: plans[name]})
	}
	for i := 0; i < len(orgs) && i < 5; i++ {
		d.Newest = append(d.Newest, orgs[i]) // already newest first
	}
	for _, sg := range signups {
		switch sg.State {
		case "waiting", "opened":
			d.PendingSignups++
		case "finished":
			d.FinishedSignups++
		}
	}
	if len(signups) > 5 {
		d.RecentSignups = signups[:5]
	} else {
		d.RecentSignups = signups
	}
	v := g.opsBase(s, "/", "ops_dash", "Overview")
	v.Dash = &d
	console.RenderOps(w, http.StatusOK, v)
}

func (g *Gateway) opsOrgList(w http.ResponseWriter, r *http.Request, s opsSession) {
	orgs, err := g.opsOrgs(r.Context())
	if err != nil {
		g.opsFailPage(w, s, "/orgs", "organisations", err)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filter := r.URL.Query().Get("status")
	var keep []console.OpsOrg
	for _, o := range orgs {
		if q != "" {
			hay := strings.ToLower(o.Name + " " + o.Slug + " " + strings.Join(o.Hosts, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		switch filter {
		case "active":
			if o.Status != "active" && o.Status != "near_cap" {
				continue
			}
		case "suspended":
			if o.Status != "suspended" {
				continue
			}
		case "near":
			if o.Flag == "" {
				continue
			}
		}
		keep = append(keep, o)
	}
	v := g.opsBase(s, "/orgs", "ops_orgs", "Organisations")
	v.Orgs, v.Query, v.Filter = keep, strings.TrimSpace(r.URL.Query().Get("q")), filter
	console.RenderOps(w, http.StatusOK, v)
}

func (g *Gateway) opsOrgPage(w http.ResponseWriter, r *http.Request, s opsSession) {
	g.opsOrgPageWith(w, r, s, strings.ToLower(r.PathValue("slug")), "", orgNotices[r.URL.Query().Get("notice")], http.StatusOK)
}

func (g *Gateway) opsOrgPageWith(w http.ResponseWriter, r *http.Request, s opsSession, slug, said, notice string, status int) {
	g.opsForget() // an owner who has just changed something wants to see it
	orgs, err := g.opsOrgs(r.Context())
	if err != nil {
		g.opsFailPage(w, s, "/orgs", "organisations", err)
		return
	}
	var sum *console.OpsOrg
	for i := range orgs {
		if orgs[i].Slug == slug {
			sum = &orgs[i]
			break
		}
	}
	if sum == nil {
		v := g.opsBase(s, "/orgs", "ops_closed", "Not found")
		v.Said = "No organisation has that short name."
		console.RenderOps(w, http.StatusNotFound, v)
		return
	}
	t, err := g.dir.ResolveID(r.Context(), sum.ID)
	if err != nil {
		g.opsFailPage(w, s, "/orgs", "organisation", err)
		return
	}
	u, uerr := g.dir.Usage(r.Context(), sum.ID)
	if uerr != nil {
		g.log.Error("owner console: usage", "tenant", slug, "err", uerr)
	}
	hist, err := g.dir.UsageHistory(r.Context(), sum.ID, 30)
	if err != nil {
		g.opsFailPage(w, s, "/orgs", "usage history", err)
		return
	}
	d := console.OpsOrgDetail{OpsOrg: opsMeasure(sum.Summary, u, uerr), Tenant: t, History: hist, Usage: u, Plans: directory.Plans()}
	plan, _ := directory.PlanByName(t.Plan)
	for _, name := range directory.Features() {
		_, explicit := t.Features[name]
		d.Features = append(d.Features, console.OpsFeature{
			Name: name, On: t.Feature(name), FromPlan: !explicit, PlanValue: plan.Features[name]})
	}
	v := g.opsBase(s, "/orgs", "ops_org", d.Name)
	v.Org, v.Said, v.Notice = &d, said, notice
	console.RenderOps(w, status, v)
}

func (g *Gateway) opsSignups(w http.ResponseWriter, r *http.Request, s opsSession) {
	g.opsSignupsPage(w, r, s, "", signupNotices[r.URL.Query().Get("notice")], http.StatusOK)
}

func (g *Gateway) opsSignupsPage(w http.ResponseWriter, r *http.Request, s opsSession, said, notice string, status int) {
	rows, err := g.dir.ListSignups(r.Context(), true)
	if err != nil {
		g.opsFailPage(w, s, "/signups", "sign-ups", err)
		return
	}
	v := g.opsBase(s, "/signups", "ops_signups", "Sign-ups")
	v.Signups, v.Said, v.Notice = rows, said, notice
	console.RenderOps(w, status, v)
}

func (g *Gateway) opsLicences(w http.ResponseWriter, r *http.Request, s opsSession) {
	orgs, err := g.opsOrgs(r.Context())
	if err != nil {
		g.opsFailPage(w, s, "/licences", "organisations", err)
		return
	}
	// Those closest to their limit first, because that is who the owner is
	// looking for on this page.
	sort.SliceStable(orgs, func(i, j int) bool { return orgs[i].Percent > orgs[j].Percent })
	v := g.opsBase(s, "/licences", "ops_licences", "Licences")
	v.Orgs, v.Plans = orgs, directory.Plans()
	console.RenderOps(w, http.StatusOK, v)
}

var operatorNotices = map[string]string{
	"disabled": "Disabled. Their sessions ended and they cannot sign in.",
	"enabled":  "Enabled. They sign in as before, with the same password and authenticator.",
	"mfareset": "Their authenticator is removed and their sessions ended. Make them a new link to set one up.",
}

func (g *Gateway) opsOperators(w http.ResponseWriter, r *http.Request, s opsSession) {
	g.opsOperatorsPage(w, r, s, "", operatorNotices[r.URL.Query().Get("notice")], "", "", http.StatusOK)
}

// opsOperatorsPage shows the owners. link, when given, is a link just made,
// shown once for the owner named.
func (g *Gateway) opsOperatorsPage(w http.ResponseWriter, r *http.Request, s opsSession, said, notice, link, linkFor string, status int) {
	ops, err := g.dir.ListOperators(r.Context())
	if err != nil {
		g.opsFailPage(w, s, "/operators", "owners", err)
		return
	}
	v := g.opsBase(s, "/operators", "ops_operators", "Owners")
	for _, o := range ops {
		v.Operators = append(v.Operators, console.OpsOperator{Operator: o, You: o.ID == s.Op.ID})
	}
	v.Said, v.Notice, v.NewLink, v.NewLinkFor = said, notice, link, linkFor
	console.RenderOps(w, status, v)
}

func (g *Gateway) opsEvents(w http.ResponseWriter, r *http.Request, s opsSession) {
	ev, err := g.dir.OperatorEvents(r.Context(), 200)
	if err != nil {
		g.opsFailPage(w, s, "/events", "activity", err)
		return
	}
	v := g.opsBase(s, "/events", "ops_events", "Activity")
	v.Events = ev
	console.RenderOps(w, http.StatusOK, v)
}

func (g *Gateway) opsAccount(w http.ResponseWriter, r *http.Request, s opsSession) {
	console.RenderOps(w, http.StatusOK, g.opsBase(s, "/account", "ops_account", "Your account"))
}
