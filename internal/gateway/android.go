package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/android"
	"platform/internal/authz"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/notify"
	"platform/internal/tenantclaim"
)

// Android Enterprise, the tenant's side of it.
//
// Binding is a round trip through Google: we ask the API for a sign-up URL
// with our callback on it, send the administrator there, and Google sends
// them back with an enterprise token. The sign-up URL's name has to be
// presented with that token to finish, and it has to be the one THIS
// person started: a token arriving on a callback nobody here began is a
// token somebody else began, and binding on it would bind their enterprise
// to this tenant. So the name travels in a signed cookie keyed to the
// person, and the callback refuses without it.

const androidBindCookie = "android_bind"

func (g *Gateway) androidReady() bool { return android.Configured(g.android) }

func (g *Gateway) bindState(subject, signupName string) string {
	m := hmac.New(sha256.New, g.csrfKey)
	m.Write([]byte("android-bind|" + subject + "|" + signupName))
	return signupName + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (g *Gateway) openBindState(subject, state string) (string, bool) {
	i := strings.LastIndex(state, ".")
	if i <= 0 {
		return "", false
	}
	name := state[:i]
	if !hmac.Equal([]byte(state), []byte(g.bindState(subject, name))) {
		return "", false
	}
	return name, true
}

// ---------------------------------------------------------------- the page

func (g *Gateway) loadAndroid(ctx context.Context, tx *data.Tx, tenant directory.Tenant, out *console.Android) error {
	out.CanMail = g.mail != nil
	out.Configured = g.androidReady()
	out.InPlan = tenant.Feature(directory.FeatureAndroid)
	b, bound, err := android.Bound(ctx, tx)
	if err != nil {
		return err
	}
	out.Bound = bound
	if bound {
		out.Enterprise, out.DisplayName, out.BoundBy, out.BoundAt = b.Name, b.DisplayName, b.BoundBy, b.BoundAt
		out.LastSyncedAt, out.LastSyncError = b.LastSyncedAt, b.LastSyncError
		ts, err := android.Tokens(ctx, tx)
		if err != nil {
			return err
		}
		out.Tokens = ts
	}
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM devices WHERE os_family = 'android' AND android_name IS NOT NULL`).Scan(&out.Devices); err != nil {
		return err
	}
	return nil
}

func (g *Gateway) consoleAndroid(w http.ResponseWriter, r *http.Request, s console.Session) {
	res := ResolutionFrom(r.Context())
	g.console.AndroidPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Android) error {
		return g.loadAndroid(ctx, tx, res.Tenant, out)
	})
}

// ---------------------------------------------------------------- binding

func (g *Gateway) androidCallbackURL(r *http.Request) string {
	if g.androidCallback != "" {
		return strings.TrimSuffix(g.androidCallback, "/") + "/android/callback"
	}
	return g.signupSchemeFor(r) + "://" + r.Host + "/android/callback"
}

// signupSchemeFor is the console's own scheme for links back to itself.
func (g *Gateway) signupSchemeFor(r *http.Request) string {
	if r.TLS == nil && g.insecureCookies && onThisMachine(r.Host) {
		return "http"
	}
	return "https"
}

func (g *Gateway) consoleAndroidBind(w http.ResponseWriter, r *http.Request, res Resolution) {
	if !res.Tenant.Feature(directory.FeatureAndroid) {
		back(w, r, "/android", "Android Enterprise is not part of this tenant's plan. Ask the operator to move you to a plan that includes it.")
		return
	}
	if !g.androidReady() {
		back(w, r, "/android", "Android Enterprise is not available: the operator has not connected Google's Android Management API.")
		return
	}
	var already bool
	_ = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			_, already, _ = android.Bound(ctx, tx)
			return nil
		})
	if already {
		back(w, r, "/android", "This tenant already has an Android Enterprise.")
		return
	}
	su, err := g.android.CreateSignupURL(r.Context(), g.androidCallbackURL(r))
	if err != nil {
		g.log.Error("android signup url", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/android", "Google could not start the sign-up: "+err.Error())
		return
	}
	g.setCookie(w, androidBindCookie, g.bindState(res.Subject, su.Name), 600)
	g.log.Info("android binding started", "tenant", res.Tenant.Slug, "by", res.Subject)
	http.Redirect(w, r, su.URL, http.StatusFound)
}

func (g *Gateway) consoleAndroidCallback(w http.ResponseWriter, r *http.Request, s console.Session) {
	res := ResolutionFrom(r.Context())
	token := strings.TrimSpace(r.URL.Query().Get("enterpriseToken"))
	ck, err := r.Cookie(androidBindCookie)
	if err != nil || token == "" {
		g.log.Warn("android callback without a binding in progress", "tenant", res.Tenant.Slug)
		back(w, r, "/android", "That sign-up was not started from here. Start it again from this page.")
		return
	}
	signupName, ok := g.openBindState(res.Subject, ck.Value)
	if !ok {
		g.log.Warn("android callback with a state that is not this person's", "tenant", res.Tenant.Slug)
		back(w, r, "/android", "That sign-up was started by somebody else, or has expired. Start it again.")
		return
	}
	g.clearCookie(w, androidBindCookie)

	e, err := g.android.CreateEnterprise(r.Context(), signupName, token, res.Tenant.Name)
	if err != nil {
		g.log.Error("android create enterprise", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/android", "Google refused to finish the sign-up: "+err.Error())
		return
	}
	var undelivered []string
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if err := android.Bind(ctx, tx, e, res.Subject); err != nil {
				return err
			}
			// The policy goes out at binding, so the first device that
			// enrols is held to something from its first minute.
			var derr error
			undelivered, derr = android.DeliverPolicy(ctx, tx, g.android)
			return derr
		})
	if errors.Is(err, android.ErrAlreadyBound) {
		back(w, r, "/android", "This tenant already has an Android Enterprise.")
		return
	}
	if err != nil {
		g.log.Error("android bind", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/android", "The enterprise was created at Google but could not be recorded here. Tell the operator; it may need to be deleted there.")
		return
	}
	g.log.Info("android enterprise bound", "tenant", res.Tenant.Slug, "enterprise", e.Name, "by", res.Subject)
	msg := "Bound to " + e.Name + ". Your Android policy has been delivered."
	if len(undelivered) > 0 {
		msg += " Judged on sync rather than enforced on the device: " + strings.Join(undelivered, ", ") + "."
	}
	back(w, r, "/android", msg)
}

func (g *Gateway) consoleAndroidUnbind(w http.ResponseWriter, r *http.Request, res Resolution) {
	var b android.Binding
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var uerr error
			b, uerr = android.Unbind(ctx, tx, res.Subject)
			return uerr
		})
	if err != nil {
		back(w, r, "/android", "There was no Android Enterprise to unbind.")
		return
	}
	// Google's side second: if this fails the record here is already gone
	// and the enterprise at Google is orphaned, which the log says. The
	// other order would leave a binding here to an enterprise that is gone,
	// and every sync would fail against it.
	if err := g.android.DeleteEnterprise(r.Context(), b.Name); err != nil {
		g.log.Error("android enterprise not deleted at Google", "tenant", res.Tenant.Slug,
			"enterprise", b.Name, "err", err)
		back(w, r, "/android", "Unbound here, but Google refused to delete "+b.Name+". Tell the operator.")
		return
	}
	g.log.Info("android enterprise unbound", "tenant", res.Tenant.Slug, "enterprise", b.Name, "by", res.Subject)
	back(w, r, "/android", "Unbound. Devices already enrolled stay listed until retired; nothing new can enrol.")
}

// ---------------------------------------------------------------- tokens

func (g *Gateway) consoleAndroidToken(w http.ResponseWriter, r *http.Request, res Resolution) {
	label := strings.TrimSpace(r.FormValue("label"))
	// "Email the link": the address is checked here, before Google is
	// asked for anything, so a bad address costs nothing at Google and a
	// line break in it never reaches a mail header.
	wantMail := r.FormValue("send") != ""
	var mailTo string
	var invite notify.Message
	if wantMail {
		if g.mail == nil {
			back(w, r, "/android", "This deployment has no mail server, so the link cannot be emailed from here. Make the token without that box ticked and pass the link on yourself.")
			return
		}
		addrs, err := notify.ParseRecipients(strings.TrimSpace(r.FormValue("assigned_to")))
		if err != nil || len(addrs) != 1 {
			back(w, r, "/android", "To email the link, \"Who it is for\" has to be one email address.")
			return
		}
		mailTo = addrs[0]
	}
	assignedTo := strings.TrimSpace(r.FormValue("assigned_to"))
	ownership := strings.TrimSpace(r.FormValue("ownership"))
	if label == "" {
		back(w, r, "/android", "Say what the device is.")
		return
	}
	var tok android.EnrollmentToken
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			b, bound, err := android.Bound(ctx, tx)
			if err != nil {
				return err
			}
			if !bound {
				return android.ErrNotBound
			}
			var terr error
			tok, terr = g.android.CreateEnrollmentToken(ctx, b.Name, android.TokenInput{
				PolicyName: b.PolicyName(), User: assignedTo, Lifetime: 7 * 24 * time.Hour, OneTime: true,
				PersonalUsage: ownership == "personal",
			})
			if terr != nil {
				return terr
			}
			if err := android.RecordToken(ctx, tx, tok, label, assignedTo, ownership, res.Subject); err != nil {
				return err
			}
			if !wantMail {
				return nil
			}
			// The invitation is composed and stamped inside the
			// transaction, where the brand and the sender identity are,
			// and sent after it: a token Google has issued is recorded
			// whether or not the mail server is in a good mood.
			invite = inviteMessage(label, ownership, android.EnrolLink(tok.Value), tok.ExpiresAt)
			if err := g.notify.Stamp(ctx, tx, &invite); err != nil {
				return err
			}
			return data.AppendAudit(ctx, tx, "android.invite_sent", mailTo)
		})
	if errors.Is(err, android.ErrNotBound) {
		back(w, r, "/android", "Bind an Android Enterprise first.")
		return
	}
	if err != nil {
		g.log.Error("android token", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/android", "Google did not issue a token: "+err.Error())
		return
	}
	g.log.Info("android enrolment token created", "tenant", res.Tenant.Slug, "by", res.Subject)
	var mailErr string
	if wantMail {
		if err := g.mail.Deliver(r.Context(), mailTo, invite); err != nil {
			g.log.Error("android invitation", "tenant", res.Tenant.Slug, "to", mailTo, "err", err)
			mailErr = err.Error()
		}
	}
	// Shown once, on the page, never through a redirect.
	s := console.Session{Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject, CSRF: g.csrfToken(res)}
	g.console.AndroidPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Android) error {
		if err := g.loadAndroid(ctx, tx, res.Tenant, out); err != nil {
			return err
		}
		out.NewToken, out.NewTokenQR, out.NewTokenFor = tok.Value, tok.QRCode, label
		out.NewTokenLink, out.NewTokenOwnership = android.EnrolLink(tok.Value), ownership
		if wantMail && mailErr == "" {
			out.NewTokenMailed = mailTo
		}
		out.NewTokenMailError = mailErr
		return nil
	})
}

// inviteMessage is the email a person gets with their enrolment link. It
// is written for the person holding the phone, not for an administrator:
// what to tap, what will happen, how long the link is good for. It names
// no product but the tenant's, which Stamp puts on the From line.
func inviteMessage(label, ownership, link string, expires time.Time) notify.Message {
	var steps string
	if ownership == "personal" {
		steps = "Open this link on the phone itself. It installs a small app from Google Play and sets up " +
			"a separate work profile for your work apps and data. Your own apps, photos and messages stay " +
			"yours and are not visible to your employer.\n\n" + link
	} else {
		steps = "This phone is set up as a company device, which works on a new or freshly reset phone " +
			"only: on the first Google sign-in screen, type afw#setup as the email address, then enter this " +
			"link when asked. A phone already in use will refuse it; if that is your phone, ask whoever sent " +
			"this for a personal-device invitation instead.\n\n" + link
	}
	return notify.Message{
		Topic:   notify.Topic("device.invite"),
		Subject: "Set up your work phone: " + label,
		Body: "Hello,\n\nYour organisation manages work apps and data on phones with a work profile, and " +
			"this message is your invitation for " + label + ".\n\n" + steps + "\n\nThe link works once and " +
			"expires on " + expires.UTC().Format("2 January 2006") + ". If it has expired, ask whoever sent " +
			"this for a new one.\n",
	}
}

// ---------------------------------------------------------------- sync

func (g *Gateway) syncAndroid(ctx context.Context, tx *data.Tx) (android.SyncResult, error) {
	return android.Sync(ctx, tx, g.android, time.Now().UTC())
}

func (g *Gateway) consoleAndroidSync(w http.ResponseWriter, r *http.Request, res Resolution) {
	var out android.SyncResult
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var serr error
			out, serr = g.syncAndroid(ctx, tx)
			return serr
		})
	if err != nil {
		back(w, r, "/android", "Sync failed: "+err.Error())
		return
	}
	back(w, r, "/android", syncWords(out))
}

func syncWords(out android.SyncResult) string {
	msg := "Synced: " + itoa(out.Listed) + " listed, " + itoa(out.Created) + " new, " +
		itoa(out.Judged) + " judged"
	if out.Skipped > 0 {
		msg += ", " + itoa(out.Skipped) + " skipped (" + strings.Join(out.SkipReason, "; ") + ")"
	}
	return msg + "."
}

func itoa(n int) string { return strconv.Itoa(n) }

func (g *Gateway) apiAndroidSync(w http.ResponseWriter, r *http.Request) {
	var out android.SyncResult
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var serr error
			out, serr = g.syncAndroid(ctx, tx)
			return serr
		})
	if errors.Is(err, android.ErrNotBound) {
		writeError(w, http.StatusConflict, "this tenant has not bound an Android Enterprise")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "sync failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"listed": out.Listed, "created": out.Created, "judged": out.Judged,
		"skipped": out.Skipped, "skip_reasons": out.SkipReason,
	})
}

// RunAndroidSync is F8's "compliance evaluation every 15 minutes" for the
// devices Google reports on: every bound tenant is synced on the interval.
func (g *Gateway) RunAndroidSync(ctx context.Context, tenants func(context.Context) ([]uuid.UUID, error), every time.Duration) {
	if !g.androidReady() {
		return
	}
	if every <= 0 {
		every = 15 * time.Minute
	}
	g.log.Info("android sync running", "every", every)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		ids, err := tenants(ctx)
		if err != nil {
			g.log.Error("android sync: could not list tenants", "err", err)
			continue
		}
		for _, id := range ids {
			claim, err := g.signer.Mint(tenantclaim.Claim{
				TenantID: id, Subject: "system:android-sync",
				Role: string(authz.Operator), RequestID: uuid.NewString(),
			}, 2*time.Minute)
			if err != nil {
				continue
			}
			var out android.SyncResult
			err = g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
				var serr error
				out, serr = g.syncAndroid(ctx, tx)
				return serr
			})
			switch {
			case errors.Is(err, android.ErrNotBound):
			case err != nil:
				g.log.Error("android sync", "tenant", id, "err", err)
			default:
				g.log.Info("android synced", "tenant", id, "listed", out.Listed,
					"created", out.Created, "judged", out.Judged, "skipped", out.Skipped)
			}
		}
	}
}

// deliverAndroidPolicy runs after a policy changes. It is inside the same
// transaction, so a policy that Google refuses is a policy that was not
// saved: the console never shows a version Android devices are not held to.
func (g *Gateway) deliverAndroidPolicy(ctx context.Context, tx *data.Tx) ([]string, error) {
	if !g.androidReady() {
		return nil, nil
	}
	return android.DeliverPolicy(ctx, tx, g.android)
}
