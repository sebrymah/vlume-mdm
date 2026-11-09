package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/console"
	"platform/internal/directory"
)

// What an owner can do (0048). Every action is a POST behind a session, a form
// token and a same-origin check, and every one that changes something writes
// a line to operator_events naming who, what, on which organisation, and what
// it was before: the record cannot be changed by the person it is about.
//
//	POST /orgs/{slug}/suspend        needs the short name typed and a reason
//	POST /orgs/{slug}/resume
//	POST /orgs/{slug}/plan           takes the plan's numbers, clears switches
//	POST /orgs/{slug}/quota          devices, admin seats, requests a minute
//	POST /orgs/{slug}/feature        on, off, or back to what the plan says
//	POST /signups/cancel             ends an open sign-up link
//	POST /operators/invite           a new owner, and their one link
//	POST /operators/{id}/link        a fresh link for an owner
//	POST /operators/{id}/disable|enable|reset-mfa

// Limits on what a form can ask for: a typo of one extra zero is not a plan.
const (
	opsMaxDevices = 1_000_000
	opsMaxSeats   = 10_000
	opsMaxRate    = 100_000
)

var orgNotices = map[string]string{
	"suspended": "Suspended. Its people cannot sign in and its devices cannot reach the platform until it is resumed.",
	"resumed":   "Resumed.",
	"plan":      "Plan changed. The organisation now has that plan's numbers and switches.",
	"quota":     "Allowance changed.",
	"feature":   "Switch changed.",
}

var signupNotices = map[string]string{"cancelled": "That sign-up link no longer works."}

// opsPost is opsAuthed for a form that changes something.
func (g *Gateway) opsPost(active string, h func(http.ResponseWriter, *http.Request, opsSession)) http.Handler {
	return g.opsAuthed(active, func(w http.ResponseWriter, r *http.Request, s opsSession) {
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "that form was not posted from this site")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "that form could not be read")
			return
		}
		if !g.csrfMatches(r.PostFormValue("csrf"), opsRealm, s.Sess.Subject, opsRole) {
			writeError(w, http.StatusForbidden, "missing or wrong form token")
			return
		}
		if !g.limiter.allowKey("ops:act:"+s.Op.ID.String(), 60) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many changes in a minute")
			return
		}
		h(w, r, s)
	})
}

// opsRecord writes the line. A change that cannot be recorded is reported as
// exactly that: it was made, and the owner is told the record is missing.
func (g *Gateway) opsRecord(w http.ResponseWriter, r *http.Request, s opsSession, action, target, detail string) bool {
	if err := g.dir.OperatorEvent(r.Context(), s.Op.Email, action, target, detail); err != nil {
		g.log.Error("owner console: the record of a change could not be written", "action", action, "target", target, "err", err)
		v := g.opsBase(s, "/orgs", "ops_closed", "Done, but not recorded")
		v.Said = "The change was made, but the record of it could not be written. Tell the other owners and check the activity page."
		console.RenderOps(w, http.StatusInternalServerError, v)
		return false
	}
	g.opsForget()
	return true
}

// opsForget drops the cached counts so the next page reads the change.
func (g *Gateway) opsForget() {
	g.opsCache.mu.Lock()
	g.opsCache.orgs = nil
	g.opsCache.mu.Unlock()
}

// opsOrgTenant is the organisation's row as it is now, by short name.
func (g *Gateway) opsOrgTenant(r *http.Request) (directory.Tenant, bool, error) {
	slug := strings.ToLower(r.PathValue("slug"))
	orgs, err := g.dir.List(r.Context())
	if err != nil {
		return directory.Tenant{}, false, err
	}
	for _, o := range orgs {
		if o.Slug == slug {
			t, err := g.dir.ResolveID(r.Context(), o.ID)
			return t, err == nil, err
		}
	}
	return directory.Tenant{}, false, nil
}

// opsOrgAct runs the shared steps of an organisation action: find it, run the
// change, record it, and go back to its page with a notice. The change returns
// the words for the record, or a message to show the owner instead.
func (g *Gateway) opsOrgAct(action, notice string, change func(r *http.Request, t directory.Tenant) (detail, refused string, err error)) http.Handler {
	return g.opsPost("/orgs", func(w http.ResponseWriter, r *http.Request, s opsSession) {
		t, found, err := g.opsOrgTenant(r)
		if err != nil {
			g.opsFailPage(w, s, "/orgs", "organisation", err)
			return
		}
		if !found {
			v := g.opsBase(s, "/orgs", "ops_closed", "Not found")
			v.Said = "No organisation has that short name."
			console.RenderOps(w, http.StatusNotFound, v)
			return
		}
		detail, refused, err := change(r, t)
		if err != nil {
			g.opsFailPage(w, s, "/orgs", "change", err)
			return
		}
		if refused != "" {
			g.opsOrgPageWith(w, r, s, t.Slug, refused, "", http.StatusUnprocessableEntity)
			return
		}
		if !g.opsRecord(w, r, s, action, t.Slug, detail) {
			return
		}
		http.Redirect(w, r, "/orgs/"+t.Slug+"?notice="+notice, http.StatusSeeOther)
	})
}

func (g *Gateway) opsSuspend() http.Handler {
	return g.opsOrgAct("org.suspended", "suspended", func(r *http.Request, t directory.Tenant) (string, string, error) {
		if !strings.EqualFold(strings.TrimSpace(r.PostFormValue("confirm")), t.Slug) {
			return "", "To suspend " + t.Name + ", type its short name in the box.", nil
		}
		reason := strings.TrimSpace(r.PostFormValue("reason"))
		if reason == "" {
			return "", "Say why. It is written to the activity record.", nil
		}
		if len(reason) > 200 {
			reason = reason[:200]
		}
		if !t.Active() {
			return "", t.Name + " is not active, so it cannot be suspended.", nil
		}
		return reason, "", g.dir.SetStatus(r.Context(), t.Slug, "suspended")
	})
}

func (g *Gateway) opsResume() http.Handler {
	return g.opsOrgAct("org.resumed", "resumed", func(r *http.Request, t directory.Tenant) (string, string, error) {
		if t.Status != "suspended" {
			return "", t.Name + " is not suspended.", nil
		}
		return "", "", g.dir.SetStatus(r.Context(), t.Slug, "active")
	})
}

func (g *Gateway) opsPlan() http.Handler {
	return g.opsOrgAct("org.plan_set", "plan", func(r *http.Request, t directory.Tenant) (string, string, error) {
		name := r.PostFormValue("plan")
		p, ok := directory.PlanByName(name)
		if !ok {
			return "", "That is not a plan.", nil
		}
		return fmt.Sprintf("%s (was %s)", p.Name, t.Plan), "", g.dir.SetPlan(r.Context(), t.Slug, p.Name)
	})
}

func (g *Gateway) opsQuota() http.Handler {
	return g.opsOrgAct("org.quota_set", "quota", func(r *http.Request, t directory.Tenant) (string, string, error) {
		get := func(name string, max int) (int, bool) {
			n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(name)))
			return n, err == nil && n >= 1 && n <= max
		}
		devices, ok1 := get("devices", opsMaxDevices)
		seats, ok2 := get("seats", opsMaxSeats)
		rate, ok3 := get("rate", opsMaxRate)
		if !ok1 || !ok2 || !ok3 {
			return "", fmt.Sprintf("Each number must be a whole number from 1 up to its limit (devices %d, admin seats %d, requests a minute %d).",
				opsMaxDevices, opsMaxSeats, opsMaxRate), nil
		}
		detail := fmt.Sprintf("devices %d to %d, admin seats %d to %d, requests a minute %d to %d",
			t.DeviceCap, devices, t.AdminSeats, seats, t.APIRatePerMin, rate)
		return detail, "", g.dir.SetQuota(r.Context(), t.Slug, devices, seats, rate)
	})
}

func (g *Gateway) opsFeature() http.Handler {
	return g.opsOrgAct("org.feature_set", "feature", func(r *http.Request, t directory.Tenant) (string, string, error) {
		name, to := r.PostFormValue("feature"), r.PostFormValue("to")
		known := false
		for _, f := range directory.Features() {
			known = known || f == name
		}
		if !known || (to != "on" && to != "off" && to != "plan") {
			return "", "That is not a switch or not a setting for one.", nil
		}
		was := "off"
		if t.Feature(name) {
			was = "on"
		}
		var err error
		switch to {
		case "plan":
			err = g.dir.ClearFeature(r.Context(), t.Slug, name)
		default:
			err = g.dir.SetFeature(r.Context(), t.Slug, name, to == "on")
		}
		return fmt.Sprintf("%s %s (was %s)", name, to, was), "", err
	})
}

func (g *Gateway) opsCancelSignup() http.Handler {
	return g.opsPost("/signups", func(w http.ResponseWriter, r *http.Request, s opsSession) {
		email := strings.TrimSpace(r.PostFormValue("email"))
		err := g.dir.CancelSignup(r.Context(), email)
		if errors.Is(err, directory.ErrNoSuchSignup) {
			g.opsSignupsPage(w, r, s, "That sign-up has no open link any more.", "", http.StatusUnprocessableEntity)
			return
		}
		if err != nil {
			g.opsFailPage(w, s, "/signups", "sign-up", err)
			return
		}
		if !g.opsRecord(w, r, s, "signup.cancelled", strings.ToLower(email), "") {
			return
		}
		http.Redirect(w, r, "/signups?notice=cancelled", http.StatusSeeOther)
	})
}

// --------------------------------------------------------------- the owners

func (g *Gateway) opsInvite() http.Handler {
	return g.opsPost("/operators", func(w http.ResponseWriter, r *http.Request, s opsSession) {
		email, name := r.PostFormValue("email"), r.PostFormValue("name")
		if len(name) > 100 {
			name = name[:100]
		}
		o, err := g.dir.CreateOperator(r.Context(), email, name, s.Op.Email)
		switch {
		case errors.Is(err, directory.ErrOperatorExists):
			g.opsOperatorsPage(w, r, s, "There is already an owner with that address. Use \"New link\" on their row.", "", "", "", http.StatusUnprocessableEntity)
			return
		case errors.Is(err, directory.ErrBadOperatorAddress):
			g.opsOperatorsPage(w, r, s, "That is not an email address.", "", "", "", http.StatusUnprocessableEntity)
			return
		case err != nil:
			g.opsFailPage(w, s, "/operators", "owner", err)
			return
		}
		g.opsShowLink(w, r, s, o)
	})
}

// opsShowLink makes the owner's next link and shows it once, on the page the
// POST answers with and nowhere a URL, a history or a log could keep it.
func (g *Gateway) opsShowLink(w http.ResponseWriter, r *http.Request, s opsSession, o directory.Operator) {
	token, purpose, _, err := g.dir.IssueOperatorLink(r.Context(), o.ID, s.Op.Email, time.Now().UTC())
	if errors.Is(err, directory.ErrNoSuchOperator) {
		g.opsOperatorsPage(w, r, s, "That owner is disabled. Enable them before making a link.", "", "", "", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		g.opsFailPage(w, s, "/operators", "link", err)
		return
	}
	path := "/accept/"
	if purpose == "reset" {
		path = "/reset/"
	}
	g.opsOperatorsPage(w, r, s, "", "", g.consoleBaseOf(r)+path+token, o.Email, http.StatusOK)
}

// opsOwnerAct is the shared shape of the per-owner buttons.
func (g *Gateway) opsOwnerAct(self bool, do func(r *http.Request, s opsSession, o directory.Operator) error, notice string) http.Handler {
	return g.opsPost("/operators", func(w http.ResponseWriter, r *http.Request, s opsSession) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			g.opsOperatorsPage(w, r, s, "No owner has that number.", "", "", "", http.StatusNotFound)
			return
		}
		o, err := g.dir.OperatorByID(r.Context(), id)
		if errors.Is(err, directory.ErrNoSuchOperator) {
			g.opsOperatorsPage(w, r, s, "No owner has that number.", "", "", "", http.StatusNotFound)
			return
		}
		if err != nil {
			g.opsFailPage(w, s, "/operators", "owner", err)
			return
		}
		if o.ID == s.Op.ID && !self {
			g.opsOperatorsPage(w, r, s, "Not on your own account. Ask another owner, or use the command line.", "", "", "", http.StatusUnprocessableEntity)
			return
		}
		switch err := do(r, s, o); {
		case errors.Is(err, directory.ErrLastOperator):
			g.opsOperatorsPage(w, r, s, "That is the last active owner. Add another before disabling this one.", "", "", "", http.StatusUnprocessableEntity)
			return
		case errors.Is(err, directory.ErrNoSuchOperator):
			g.opsOperatorsPage(w, r, s, "That owner is disabled, so that cannot be done. Enable them first.", "", "", "", http.StatusUnprocessableEntity)
			return
		case err != nil:
			g.opsFailPage(w, s, "/operators", "owner", err)
			return
		}
		if notice == "" { // a link: shown once
			g.opsShowLink(w, r, s, o)
			return
		}
		http.Redirect(w, r, "/operators?notice="+notice, http.StatusSeeOther)
	})
}
