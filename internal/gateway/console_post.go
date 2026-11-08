package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/command"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/enrol"
	"platform/internal/notify"
	"platform/internal/policy"
)

// formPost is guard for console forms. Same two checks as the API, answered
// as a redirect with a message rather than as JSON, because the thing on the
// other end is a browser and a person.
func (g *Gateway) formPost(action authz.Action,
	h func(http.ResponseWriter, *http.Request, Resolution)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := ResolutionFrom(r.Context())
		// A multipart form (an upload) has to be parsed as one, or its
		// fields, the form token among them, are not seen at all.
		var err error
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			err = r.ParseMultipartForm(1 << 20)
		} else {
			err = r.ParseForm()
		}
		if err != nil {
			back(w, r, "/", "That form could not be read.")
			return
		}
		if res.FromCookie && !g.csrfOK(r, res) {
			back(w, r, "/", "That form has expired. Open the page again and retry.")
			return
		}
		if !authz.Can(res.Role, action) {
			g.log.Warn("not permitted", "role", res.Role, "action", action)
			back(w, r, "/", "Your role may not do that.")
			return
		}
		h(w, r, res)
	})
}

// back sends the person where they came from with something to read. A form
// that silently returns to an unchanged page teaches people to press it twice.
func back(w http.ResponseWriter, r *http.Request, fallback, msg string) {
	// The same rule as the sign-in's "where was I going": a plain path
	// on this site, or the fallback. A protocol-relative //host, or a
	// backslash a browser would read as one, would leave the site.
	to := localPath(r.FormValue("return"))
	if to == "" {
		to = fallback
	}
	http.Redirect(w, r, to+"?said="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (g *Gateway) consoleLock(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/devices", "No such device.")
		return
	}
	reason := r.FormValue("reason")
	if reason == "" {
		back(w, r, "/devices/"+id.String(), "A reason is needed. It is shown to whoever reviews this.")
		return
	}

	var out command.Command
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			c, e := g.pipe.Request(ctx, tx, command.RequestInput{
				DeviceID: id, Type: command.Lock, Reason: reason})
			if e != nil {
				return e
			}
			out, e = g.pipe.Dispatch(ctx, tx, c.ID)
			return e
		})
	if err != nil {
		_, msg := statusFor(err)
		back(w, r, "/devices/"+id.String(), msg)
		return
	}
	back(w, r, "/devices/"+id.String(), saidAbout(out))
}

// consoleSimple is the console form for a reversible command that needs a
// reason and no second person: lost mode and its end.
func (g *Gateway) consoleSimple(t command.Type) func(http.ResponseWriter, *http.Request, Resolution) {
	return func(w http.ResponseWriter, r *http.Request, res Resolution) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			back(w, r, "/devices", "No such device.")
			return
		}
		reason := r.FormValue("reason")
		if reason == "" {
			back(w, r, "/devices/"+id.String(), "A reason is needed. It is shown to whoever reviews this.")
			return
		}
		var out command.Command
		err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error {
				c, e := g.pipe.Request(ctx, tx, command.RequestInput{DeviceID: id, Type: t, Reason: reason})
				if e != nil {
					return e
				}
				out, e = g.pipe.Dispatch(ctx, tx, c.ID)
				return e
			})
		if err != nil {
			_, msg := statusFor(err)
			back(w, r, "/devices/"+id.String(), msg)
			return
		}
		back(w, r, "/devices/"+id.String(), saidAbout(out))
	}
}

func (g *Gateway) consoleWipe(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/devices", "No such device.")
		return
	}
	reason := r.FormValue("reason")
	if reason == "" {
		back(w, r, "/devices/"+id.String(), "A reason is needed. It is shown to whoever approves this.")
		return
	}

	// "work" unless someone deliberately asked for everything. The design
	// rule: the default is never the one that cannot be undone.
	t := command.WipeSelective
	if r.FormValue("scope") == "all" {
		t = command.WipeFull
	}

	var out command.Command
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			c, e := g.pipe.Request(ctx, tx, command.RequestInput{
				DeviceID: id, Type: t, Reason: reason})
			if e != nil {
				return e
			}
			out = c
			if c.State == command.Approved {
				out, e = g.pipe.Dispatch(ctx, tx, c.ID)
			}
			return e
		})
	if err != nil {
		_, msg := statusFor(err)
		back(w, r, "/devices/"+id.String(), msg)
		return
	}
	back(w, r, "/devices/"+id.String(), saidAbout(out))
}

func (g *Gateway) consoleDecide(approve bool) func(http.ResponseWriter, *http.Request, Resolution) {
	return func(w http.ResponseWriter, r *http.Request, res Resolution) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			back(w, r, "/approvals", "No such request.")
			return
		}

		var out command.Command
		err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error {
				c, e := g.pipe.Decide(ctx, tx, id, command.DecisionInput{
					Approve: approve, Note: r.FormValue("note")})
				if e != nil {
					return e
				}
				out = c
				if approve && c.State == command.Approved {
					out, e = g.pipe.Dispatch(ctx, tx, c.ID)
				}
				return e
			})
		if err != nil {
			_, msg := statusFor(err)
			back(w, r, "/approvals", msg)
			return
		}
		if !approve {
			back(w, r, "/approvals", "Refused, and recorded with your name.")
			return
		}
		back(w, r, "/approvals", saidAbout(out))
	}
}

// saidAbout turns a command's state into something true and plain. It never
// says "done" for a command that has only been pushed.
func saidAbout(c command.Command) string {
	switch c.State {
	case command.Held:
		return c.Label() + " is waiting for a second approval from a different role."
	case command.Approved, command.Queued:
		return c.Label() + " is approved and queued. It has not reached the device yet: " +
			"sending to the device needs the Apple certificate."
	case command.Pushed:
		return c.Label() + " has been sent. The device has not confirmed it yet."
	case command.Acknowledged:
		return c.Label() + " was carried out and the device confirmed it."
	case command.Refused:
		return "Refused: " + c.RefusedReason
	case command.Expired:
		return c.Label() + " expired before it reached the device. Ask again if it is still needed."
	}
	return ""
}

// consoleCreateEnrolment is the one console form that does NOT redirect.
//
// Every other form here answers with a redirect and a message, which is the
// right pattern: it stops a refresh resubmitting. This one renders the
// result directly, because the result contains the enrolment token and a
// redirect would have to carry it in a URL. Tokens in URLs end up in browser
// history, in proxy logs and in the Referer header of the next request. The
// double-submit risk is worth less than that.
func (g *Gateway) consoleCreateEnrolment(w http.ResponseWriter, r *http.Request, res Resolution) {
	if g.enrol == nil {
		back(w, r, "/enrolments", "Enrolment is not configured on this deployment.")
		return
	}
	in := readEnrolmentInput(r)

	var token string
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			_, t, cerr := g.enrol.Create(ctx, tx, enrol.CreateInput{
				Label: in.Label, Ownership: in.Ownership, OSFamily: in.OSFamily,
				AssignedTo: in.AssignedTo,
				Life:       time.Duration(in.Days) * 24 * time.Hour,
			})
			token = t
			return cerr
		})
	if err != nil {
		_, msg := enrolStatusFor(err)
		back(w, r, "/enrolments", "That enrolment could not be made. "+msg)
		return
	}

	g.log.Info("enrolment created", "tenant", res.Tenant.Slug, "by", res.Subject)
	g.console.EnrolmentCreated(w, r, console.Session{
		Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject,
		CSRF: g.csrfToken(res),
	}, token, g.enrolURL(r, token))
}

func (g *Gateway) consoleRevokeEnrolment(w http.ResponseWriter, r *http.Request, res Resolution) {
	if g.enrol == nil {
		back(w, r, "/enrolments", "Enrolment is not configured on this deployment.")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/enrolments", "No such enrolment.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return g.enrol.Revoke(ctx, tx, id, "withdrawn by "+res.Subject)
		})
	switch {
	case errors.Is(err, enrol.ErrNotPending):
		back(w, r, "/enrolments", "That link had already been used or withdrawn.")
	case err != nil:
		back(w, r, "/enrolments", "That link could not be withdrawn.")
	default:
		back(w, r, "/enrolments", "Withdrawn. That link will no longer enrol anything.")
	}
}

func (g *Gateway) consoleSavePolicy(w http.ResponseWriter, r *http.Request, res Resolution) {
	var undelivered []string
	body := []byte(r.FormValue("rules"))
	if r.FormValue("guided") == "1" {
		b, berr := guidedBody(r)
		if berr != nil {
			back(w, r, "/policies", "That policy was not saved. "+berr.Error())
			return
		}
		body = b
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			_, serr := policy.Save(ctx, tx, policy.SaveInput{
				Name: r.FormValue("name"),
				Scope: policy.Scope{
					OSFamily:  r.FormValue("os_family"),
					Ownership: r.FormValue("ownership"),
				},
				Body:      body,
				CreatedBy: res.Subject,
				Stage:     stageFromForm(r),
			})
			if serr != nil {
				return serr
			}
			undelivered, serr = g.deliverAndroidPolicy(ctx, tx)
			return serr
		})
	if err != nil {
		// The message is the one the person needs: which rule name was not
		// understood, or which value was the wrong shape. A generic refusal
		// here would send them to look at a JSON body with no clue what is
		// wrong with it.
		_, msg := policyStatusFor(err)
		back(w, r, "/policies", "That policy was not saved. "+msg)
		return
	}
	msg := "Saved as a new version. It applies from the next report."
	if len(undelivered) > 0 {
		msg += " On Android, judged on sync rather than enforced on the device: " +
			strings.Join(undelivered, ", ") + "."
	}
	back(w, r, "/policies", msg)
}

// consoleAddFromLibrary adds a ready-made policy in one click. It is saved
// exactly as if the person had written it, under its own title, and is theirs
// to change; if a policy of that name is already in place nothing is added.
func (g *Gateway) consoleAddFromLibrary(w http.ResponseWriter, r *http.Request, res Resolution) {
	t, ok := policy.LibraryByKey(r.PathValue("key"))
	if !ok {
		back(w, r, "/policies", "There is no ready-made policy by that name.")
		return
	}
	var undelivered []string
	already := false
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			live, lerr := policy.Active(ctx, tx)
			if lerr != nil {
				return lerr
			}
			for _, p := range live {
				if p.Name == t.Title {
					already = true
					return nil
				}
			}
			if _, serr := policy.Save(ctx, tx, policy.SaveInput{
				Name: t.Title, Scope: t.Scope, Body: []byte(t.Body), CreatedBy: res.Subject,
			}); serr != nil {
				return serr
			}
			var derr error
			undelivered, derr = g.deliverAndroidPolicy(ctx, tx)
			return derr
		})
	switch {
	case already:
		back(w, r, "/policies", "That policy is already added. Change it from the list.")
	case err != nil:
		_, msg := policyStatusFor(err)
		back(w, r, "/policies", "That policy was not added. "+msg)
	default:
		msg := "Added \"" + t.Title + "\". It applies from the next report, and you can change it any time."
		if len(undelivered) > 0 {
			msg += " On Android, judged on sync rather than enforced on the device: " + strings.Join(undelivered, ", ") + "."
		}
		back(w, r, "/policies", msg)
	}
}

func (g *Gateway) consoleRetirePolicy(w http.ResponseWriter, r *http.Request, res Resolution) {
	name := r.PathValue("name")
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return policy.Retire(ctx, tx, name)
		})
	switch {
	case errors.Is(err, policy.ErrNoSuchPolicy):
		back(w, r, "/policies", "That policy was already retired.")
	case err != nil:
		back(w, r, "/policies", "That policy could not be retired.")
	default:
		back(w, r, "/policies", "Retired. It stops applying at the next report.")
	}
}

func stageFromForm(r *http.Request) *policy.Stage {
	pct, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("rollout_percent")))
	tag := strings.TrimSpace(r.FormValue("rollout_tag"))
	if pct <= 0 && tag == "" {
		return nil
	}
	return &policy.Stage{Percent: pct, Tag: tag}
}

func (g *Gateway) consoleStage(promote bool) func(http.ResponseWriter, *http.Request, Resolution) {
	return func(w http.ResponseWriter, r *http.Request, res Resolution) {
		name := r.PathValue("name")
		var out policy.Policy
		err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error {
				var serr error
				if promote {
					out, serr = policy.Promote(ctx, tx, name, res.Subject)
				} else {
					out, serr = policy.Halt(ctx, tx, name, res.Subject)
				}
				if serr != nil {
					return serr
				}
				_, serr = g.deliverAndroidPolicy(ctx, tx)
				return serr
			})
		switch {
		case errors.Is(err, policy.ErrNoSuchPolicy):
			back(w, r, "/policies", "There is no rolling version of that policy.")
		case err != nil:
			back(w, r, "/policies", "The stage could not be changed.")
		case promote:
			back(w, r, "/policies", out.Label()+" is now live for every device it covers, from their next report.")
		default:
			back(w, r, "/policies", out.Label()+" withdrawn. The live version stands.")
		}
	}
}

func (g *Gateway) consoleSetTags(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/devices", "No such device.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			_, terr := data.SetTags(ctx, tx, id, strings.Split(r.FormValue("tags"), ","))
			return terr
		})
	if err != nil {
		back(w, r, "/devices/"+id.String(), "Tags not saved. "+strings.TrimPrefix(err.Error(), "data: ")+".")
		return
	}
	back(w, r, "/devices/"+id.String(), "Tags saved. A rollout staged by tag applies from the next report.")
}

func (g *Gateway) consoleRollbackPolicy(w http.ResponseWriter, r *http.Request, res Resolution) {
	name := r.PathValue("name")
	version, err := strconv.Atoi(r.FormValue("version"))
	if err != nil || version <= 0 {
		back(w, r, "/policies", "Say which version to restore.")
		return
	}
	var out policy.Policy
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var rerr error
			out, rerr = policy.Rollback(ctx, tx, name, version, res.Subject)
			if rerr != nil {
				return rerr
			}
			_, rerr = g.deliverAndroidPolicy(ctx, tx)
			return rerr
		})
	switch {
	case errors.Is(err, policy.ErrNoSuchPolicy):
		back(w, r, "/policies", "There is no such version to restore.")
	case err != nil:
		back(w, r, "/policies", "That version could not be restored.")
	default:
		back(w, r, "/policies", "Restored as "+out.Label()+". It applies from the next report.")
	}
}

// consoleReportLost is the one write an employee can make.
//
// It records a flag and does nothing else: no lock, no wipe, no wake-up. The
// decision belongs to an administrator through the command pipeline, with
// its reason, its permitted role and, for anything irreversible, a second
// person. A button on the most junior page in the product must not reach
// past all of that.
func (g *Gateway) consoleReportLost(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/me", "No such device.")
		return
	}
	note := r.FormValue("note")
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			d, rerr := data.ReportMyDeviceLost(ctx, tx, id, note)
			if rerr != nil {
				return rerr
			}
			// The whole reason this feature exists is the eleven o'clock at
			// night case. A flag nobody is told about does not serve it: an
			// administrator has to happen to be looking at that device.
			body := res.Subject + " reported " + d.Name + " lost."
			if note != "" {
				body += " They said: " + note
			}
			return g.tell(ctx, tx, notify.Message{
				Topic:     notify.DeviceLost,
				Subject:   d.Name + " was reported lost",
				Body:      body,
				ObjectRef: "device:" + d.ID.String(),
			})
		})
	switch {
	case errors.Is(err, data.ErrNotYours):
		// The same answer a device that does not exist would give.
		back(w, r, "/me", "No such device.")
	case err != nil:
		g.log.Error("lost report", "device", id, "err", err)
		back(w, r, "/me", "That could not be recorded. Please call your IT team.")
	default:
		g.log.Warn("device reported lost", "tenant", res.Tenant.Slug,
			"device", id, "by", res.Subject)
		back(w, r, "/me", "Reported. Your IT team can see it now. Nothing has been erased.")
	}
}

// consoleFoundDevice stands the report down. It is an administrator's to
// make, not the holder's: someone phished into reporting a laptop lost
// should not also be the one who can quietly clear it.
func (g *Gateway) consoleFoundDevice(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/devices", "No such device.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return data.ClearLostReport(ctx, tx, id)
		})
	if err != nil {
		back(w, r, "/devices/"+id.String(), "There was no lost report to clear.")
		return
	}
	back(w, r, "/devices/"+id.String(), "Lost report cleared.")
}

func (g *Gateway) consoleReleaseDevice(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/devices", "No such device.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return policy.Release(ctx, tx, id, res.Subject)
		})
	if err != nil {
		back(w, r, "/devices/"+id.String(), "That device is not quarantined.")
		return
	}
	back(w, r, "/devices/"+id.String(), "Released. It is unknown until its next report.")
}
