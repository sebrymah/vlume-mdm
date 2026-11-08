package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/android"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/notify"
)

// Join links (0046). A link anyone can open, a six-digit code sent by another
// route, a limit on how many devices it will enrol and for how long.
//
// The two public routes here are the fifth and sixth outside the signed-in
// middleware, with the written reason the standing rule asks for: every other
// route needs a session, and the person holding a join link has no account
// and is not meant to. What stands in for the session is the link's secret
// (256 random bits, stored only as a hash) AND the code, which travel by
// different routes. The rules, each with a test and a control:
//
//   - nothing is revealed before the right code: Google is asked for nothing
//     and the page shows no way in (--break-joincode checks nothing);
//   - ten wrong codes in an hour pause the link for an hour
//     (--break-joinlock);
//   - the device limit is enforced here, one use per correct code, in one
//     statement that also checks the clock and the state
//     (--break-joincap, --break-joinexpiry);
//   - a cancelled link is dead at once (--break-joincancel).

const (
	joinClosedSaid = "This link does not work any more."
	joinWrongSaid  = "That code is not right. After several wrong tries this link pauses for an hour."
	joinPausedSaid = "This link is paused for a while after too many wrong codes. Try again in an hour."
	// joinPerMinute is the per-address limit on tries at the form. The
	// per-link rule is the one that stops a determined guesser; this stops
	// one address from using the form as a tap.
	joinPerMinute = 20
)

func (g *Gateway) joinView(w http.ResponseWriter, r *http.Request, host directory.Tenant, status int, v console.JoinView) {
	claim, err := g.anonClaim(host, "anonymous")
	if err != nil || g.console == nil {
		http.Error(w, v.Title, status)
		return
	}
	g.console.JoinPage(w, r, claim, status, v)
}

func (g *Gateway) joinClosed(w http.ResponseWriter, r *http.Request, host directory.Tenant) {
	g.joinView(w, r, host, http.StatusNotFound, console.JoinView{Mode: "closed", Title: "This link has finished"})
}

// joinLookup finds the link and says what state it is in. A secret that is
// not one of ours, and every state in which the link cannot be used, look
// the same to the person holding it: closed.
func (g *Gateway) joinLookup(r *http.Request, host directory.Tenant, secret string) (link android.JoinLink, codeHash string, found bool, err error) {
	err = g.asBootstrap(r.Context(), host, "join", func(ctx context.Context, tx *data.Tx) error {
		var e error
		link, codeHash, found, e = android.JoinBySecret(ctx, tx, secret)
		return e
	})
	return
}

// joinPage is the box for the code.
func (g *Gateway) joinPage(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	link, _, found, err := g.joinLookup(r, host, r.PathValue("secret"))
	if err != nil {
		g.log.Error("join lookup", "tenant", host.Slug, "err", err)
		http.Error(w, "This page could not be shown. Try again in a minute.", http.StatusInternalServerError)
		return
	}
	switch state := link.State(time.Now().UTC()); {
	case !found || (state != "active" && state != "paused"):
		g.joinClosed(w, r, host)
	case state == "paused":
		g.joinView(w, r, host, http.StatusOK, console.JoinView{Mode: "closed", Title: "This link is paused", Said: joinPausedSaid})
	default:
		g.joinView(w, r, host, http.StatusOK, console.JoinView{Mode: "code", Title: "Set up your phone", Name: link.Name})
	}
}

// joinSubmit checks the code and, if it is right, gives the way in.
//
// The order matters, and it has been got wrong once. The link's row is locked
// FIRST and the state, the code and the count are all judged while holding it,
// so attempts at one link go through one at a time: ten wrong codes pause it,
// and the eleventh and everyone after are refused without being tried, however
// many arrived together. A right code reserves its place in the same
// transaction (the device limit), and only then is Google asked, outside the
// lock, so a slow call to Google does not queue a whole team behind one phone.
// If Google fails, the place is given back.
func (g *Gateway) joinSubmit(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "that form was not posted from this site")
		return
	}
	if !g.limiter.allowKey("join:"+g.callerIP(r), joinPerMinute) {
		w.Header().Set("Retry-After", "60")
		g.joinView(w, r, host, http.StatusTooManyRequests, console.JoinView{Mode: "code", Title: "Set up your phone",
			Said: "Too many tries from this address. Wait a minute and try again."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "that form could not be read")
		return
	}
	link, _, found, err := g.joinLookup(r, host, r.PathValue("secret"))
	if err != nil {
		g.log.Error("join lookup", "tenant", host.Slug, "err", err)
		http.Error(w, "This page could not be shown. Try again in a minute.", http.StatusInternalServerError)
		return
	}
	if !found {
		g.joinClosed(w, r, host)
		return
	}
	if !host.Feature(directory.FeatureAndroid) || !g.androidReady() {
		g.joinView(w, r, host, http.StatusServiceUnavailable, console.JoinView{Mode: "closed", Title: "Not available",
			Said: "Phones cannot be set up here right now. Tell whoever sent you this link."})
		return
	}

	// Judge it under the lock. outcome says what happened.
	const (
		closed = iota + 1
		paused
		wrong
		reserved
	)
	var outcome int
	var used android.JoinLink
	typed := r.PostFormValue("code")
	err = g.asBootstrap(r.Context(), host, "join", func(ctx context.Context, tx *data.Tx) error {
		now := time.Now().UTC()
		l, codeHash, e := android.LockJoin(ctx, tx, link.ID)
		if errors.Is(e, android.ErrJoinNotUsable) {
			outcome = closed
			return nil
		}
		if e != nil {
			return e
		}
		switch l.State(now) {
		case "active":
		case "paused":
			outcome = paused
			return nil
		default:
			outcome = closed
			return nil
		}
		if !android.VerifyJoinCode(typed, codeHash) {
			outcome = wrong
			return android.JoinWrongCode(ctx, tx, l.ID, now)
		}
		// Reserve the place now, under the same lock.
		if used, e = android.UseJoin(ctx, tx, l.ID, now); e != nil {
			if errors.Is(e, android.ErrJoinNotUsable) {
				outcome = closed
				return nil
			}
			return e
		}
		outcome = reserved
		return nil
	})
	if err != nil {
		g.log.Error("join attempt", "tenant", host.Slug, "link", link.ID, "err", err)
		g.joinView(w, r, host, http.StatusBadGateway, console.JoinView{Mode: "code", Title: "Set up your phone", Name: link.Name,
			Said: "Something went wrong on our side. Try again in a minute."})
		return
	}
	switch outcome {
	case closed:
		g.joinClosed(w, r, host)
		return
	case paused:
		g.joinView(w, r, host, http.StatusTooManyRequests, console.JoinView{Mode: "closed", Title: "This link is paused", Said: joinPausedSaid})
		return
	case wrong:
		g.joinView(w, r, host, http.StatusUnauthorized, console.JoinView{Mode: "code", Title: "Set up your phone", Name: link.Name, Said: joinWrongSaid})
		return
	}

	// The code was right and the place is ours. Now ask Google.
	var tok android.EnrollmentToken
	err = g.asBootstrap(r.Context(), host, "join", func(ctx context.Context, tx *data.Tx) error {
		b, bound, e := android.Bound(ctx, tx)
		if e != nil {
			return e
		}
		if !bound {
			return android.ErrNotBound
		}
		pn, e := android.PolicyFor(ctx, tx, g.android, b, used.Ownership)
		if e != nil {
			return e
		}
		tok, e = g.android.CreateEnrollmentToken(ctx, b.Name, android.TokenInput{
			PolicyName: pn, User: used.AssignedTo, Lifetime: android.JoinTokenLife, OneTime: true,
			PersonalUsage: used.Ownership == "personal",
		})
		if e != nil {
			return e
		}
		label := used.Name
		if used.MaxUses > 1 {
			label = fmt.Sprintf("%s %d", used.Name, used.Uses)
		}
		if e := android.RecordJoinToken(ctx, tx, tok, label, used.AssignedTo, used.Ownership, used.ID); e != nil {
			return e
		}
		return data.AppendAudit(ctx, tx, "android.join_used", fmt.Sprintf("link:%s use:%d of %d", used.ID, used.Uses, used.MaxUses))
	})
	if err != nil {
		// Give the place back: this phone was not set up.
		if rerr := g.asBootstrap(r.Context(), host, "join", func(ctx context.Context, tx *data.Tx) error {
			return android.RefundJoin(ctx, tx, used.ID)
		}); rerr != nil {
			g.log.Error("join refund", "tenant", host.Slug, "link", used.ID, "err", rerr)
		}
		if errors.Is(err, android.ErrNotBound) {
			g.joinView(w, r, host, http.StatusServiceUnavailable, console.JoinView{Mode: "closed", Title: "Not available",
				Said: "Phones cannot be set up here right now. Tell whoever sent you this link."})
			return
		}
		g.log.Error("join token", "tenant", host.Slug, "link", used.ID, "err", err)
		g.joinView(w, r, host, http.StatusBadGateway, console.JoinView{Mode: "code", Title: "Set up your phone", Name: link.Name,
			Said: "Something went wrong on our side and your code was not used up. Try again in a minute."})
		return
	}
	g.log.Info("join link used", "tenant", host.Slug, "link", used.ID, "use", used.Uses, "of", used.MaxUses)

	img, kind := enrolQR(used.Ownership, tok, g.log)
	g.joinView(w, r, host, http.StatusOK, console.JoinView{
		Mode: "done", Title: "Set up your phone", Name: used.Name,
		Link: android.EnrolLink(tok.Value), QRImage: img, QRKind: kind,
		OnPhone: strings.Contains(r.UserAgent(), "Android"), Expires: tok.ExpiresAt.Local(),
	})
}

// ------------------------------------------------------- the administrator

var joinLifetimeLabels = map[int]string{24: "1 day", 48: "2 days", 168: "1 week", 336: "2 weeks", 720: "30 days"}

func joinLifetimes() []console.JoinLifetime {
	var out []console.JoinLifetime
	for _, h := range android.JoinLifetimes {
		out = append(out, console.JoinLifetime{Hours: h, Label: joinLifetimeLabels[h]})
	}
	return out
}

// consoleJoinCreate makes a link and shows it, with its code, once.
func (g *Gateway) consoleJoinCreate(w http.ResponseWriter, r *http.Request, res Resolution) {
	uses, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("uses")))
	if strings.TrimSpace(r.FormValue("uses")) == "" {
		uses = 1
	}
	hours, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("hours")))
	in := android.JoinInput{
		Name: r.FormValue("name"), Ownership: strings.TrimSpace(r.FormValue("ownership")),
		MaxUses: uses, LifeHours: hours, By: res.Subject,
	}
	// A named person only makes sense for a link that enrols one phone.
	if who := strings.TrimSpace(r.FormValue("assigned_to")); who != "" && uses == 1 {
		addrs, err := notify.ParseRecipients(who)
		if err != nil || len(addrs) != 1 {
			back(w, r, "/android", "\"For whom\" has to be one email address, or left empty.")
			return
		}
		in.AssignedTo = addrs[0]
	}
	if !res.Tenant.Feature(directory.FeatureAndroid) || !g.androidReady() {
		back(w, r, "/android", "Android is not available for this organisation yet.")
		return
	}

	var secret, code string
	var id uuid.UUID
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if _, bound, err := android.Bound(ctx, tx); err != nil {
				return err
			} else if !bound {
				return android.ErrNotBound
			}
			var e error
			id, secret, code, e = android.CreateJoin(ctx, tx, in)
			return e
		})
	switch {
	case errors.Is(err, android.ErrNotBound):
		back(w, r, "/android", "Bind an Android Enterprise first.")
		return
	case errors.Is(err, android.ErrJoinName):
		back(w, r, "/android", "Give the link a name, up to 80 characters.")
		return
	case errors.Is(err, android.ErrBadJoinLimit):
		back(w, r, "/android", "A join link is for between 1 and 5000 devices.")
		return
	case errors.Is(err, android.ErrBadJoinLife):
		back(w, r, "/android", "Choose how long the link lasts from the list.")
		return
	case err != nil:
		g.log.Error("join create", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/android", "The link could not be made. Try again.")
		return
	}
	g.log.Info("join link created", "tenant", res.Tenant.Slug, "link", id, "by", res.Subject, "uses", uses, "hours", hours)

	// Shown once, on the page, never through a redirect.
	s := console.Session{Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject, CSRF: g.csrfToken(res)}
	g.console.AndroidPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Android) error {
		if err := g.loadAndroid(ctx, tx, r, res.Tenant, out); err != nil {
			return err
		}
		out.NewJoinLink, out.NewJoinCode, out.NewJoinName = "https://"+r.Host+"/join/"+secret, code, in.Name
		out.NewJoinUses = in.MaxUses
		out.NewJoinExpiry = time.Now().Add(time.Duration(in.LifeHours) * time.Hour).Local()
		return nil
	})
}

// consoleJoinCancel ends a link at once.
func (g *Gateway) consoleJoinCancel(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/android", "No such link.")
		return
	}
	var done bool
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			done, e = android.CancelJoin(ctx, tx, id, res.Subject)
			return e
		})
	switch {
	case err != nil:
		g.log.Error("join cancel", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/android", "The link could not be cancelled. Try again.")
	case !done:
		back(w, r, "/android", "That link was already cancelled, or does not exist.")
	default:
		g.log.Info("join link cancelled", "tenant", res.Tenant.Slug, "link", id, "by", res.Subject)
		back(w, r, "/android", "Cancelled. The link and its code no longer work. Devices already set up stay.")
	}
}
