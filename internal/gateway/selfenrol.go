package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"platform/internal/android"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/directory"
)

// Self-service enrolment (0045): one link for everybody. A person signs in,
// asks for a code, and gets a QR code (or, on the phone itself, a button)
// for THEIR phone, tied to THEIR address.
//
// The rules that make that safe, each of which has a test and a control:
//
//   - the address on the code is the signed-in person's, taken from the
//     session. The form has no such field, so there is nothing to tamper with
//     (--break-selfwho takes it from the form instead);
//   - nothing happens until an administrator has turned it on
//     (--break-selfoff ignores the setting);
//   - a person may ask for five codes a day (--break-selfcap removes it);
//   - in "personal" mode a person cannot ask for a company phone
//     (--break-selfowner lets them);
//   - someone the platform has been told has left is refused
//     (--break-selfleaver);
//   - Google is asked for nothing until every one of those has passed.

const selfEnrolIntro = "Your organisation has not turned this on. Ask your IT team."

// consoleSelfEnrol is the page itself.
func (g *Gateway) consoleSelfEnrol(w http.ResponseWriter, r *http.Request, s console.Session) {
	g.console.SelfEnrolPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.SelfEnrol) error {
		mode, err := android.SelfMode(ctx, tx)
		out.Mode = mode
		return err
	})
}

// consoleSelfEnrolStart makes the code.
func (g *Gateway) consoleSelfEnrolStart(w http.ResponseWriter, r *http.Request, res Resolution) {
	// Who it is for comes from the session and from nowhere else. A bearer
	// token or a device certificate has no address, and only a person can
	// own a device.
	email := strings.ToLower(strings.TrimSpace(res.Email))
	if email == "" {
		back(w, r, "/enrol", "We cannot tell which address is yours, so we cannot set a phone up for you. Ask your IT team.")
		return
	}
	label := tidyLabel(r.FormValue("label"))
	wanted := strings.TrimSpace(r.FormValue("ownership"))

	var (
		tok       android.EnrollmentToken
		mode      string
		ownership string
		problem   string
	)
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var err error
			if mode, err = android.SelfMode(ctx, tx); err != nil {
				return err
			}
			if mode == android.SelfOff {
				problem = selfEnrolIntro
				return nil
			}
			ownership = "personal"
			if mode == android.SelfAny && wanted == "company" {
				ownership = "company"
			}
			if !res.Tenant.Feature(directory.FeatureAndroid) || !g.androidReady() {
				problem = "Android phones cannot be set up here yet. Ask your IT team."
				return nil
			}
			left, err := android.HasLeft(ctx, tx, res.Subject, email)
			if err != nil {
				return err
			}
			if left {
				problem = "This account has been closed, so a phone cannot be set up. Ask your IT team."
				return nil
			}
			b, bound, err := android.Bound(ctx, tx)
			if err != nil {
				return err
			}
			if !bound {
				problem = "Android phones cannot be set up here yet. Ask your IT team."
				return nil
			}
			n, err := android.SelfAsked(ctx, tx, res.Subject, time.Now().Add(-android.SelfWindow))
			if err != nil {
				return err
			}
			if n >= android.SelfLimit {
				problem = "You have asked for several codes today already. Use the last one, or try again tomorrow."
				return nil
			}
			tok, err = g.android.CreateEnrollmentToken(ctx, b.Name, android.TokenInput{
				PolicyName: b.PolicyName(), User: email, Lifetime: android.SelfLifetime, OneTime: true,
				PersonalUsage: ownership == "personal",
			})
			if err != nil {
				return err
			}
			if err := android.RecordToken(ctx, tx, tok, label, email, ownership, res.Subject, "self"); err != nil {
				return err
			}
			return data.AppendAudit(ctx, tx, "android.self_enrol_started", "own phone, "+ownership)
		})
	if err != nil {
		g.log.Error("self-service enrolment", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/enrol", "Something went wrong on our side, and no code was made. Try again in a minute.")
		return
	}
	if problem != "" {
		back(w, r, "/enrol", problem)
		return
	}
	g.log.Info("self-service enrolment code made", "tenant", res.Tenant.Slug, "ownership", ownership)

	img, kind := enrolQR(ownership, tok, g.log)
	s := console.Session{Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject, CSRF: g.csrfToken(res)}
	// Shown once, on the page, never through a redirect.
	g.console.SelfEnrolPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.SelfEnrol) error {
		out.Mode, out.Started, out.Label = mode, true, label
		out.Link, out.QRImage, out.QRKind = android.EnrolLink(tok.Value), img, kind
		out.Ownership, out.Expires = ownership, tok.ExpiresAt.Local()
		out.OnPhone = strings.Contains(r.UserAgent(), "Android")
		return nil
	})
}

// consoleSelfEnrolMode is the administrator's switch.
func (g *Gateway) consoleSelfEnrolMode(w http.ResponseWriter, r *http.Request, res Resolution) {
	mode := strings.TrimSpace(r.FormValue("mode"))
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if mode != android.SelfOff {
				// Turning it on for an organisation that cannot enrol an
				// Android phone yet would hand everyone a link to a dead end.
				if _, bound, err := android.Bound(ctx, tx); err != nil {
					return err
				} else if !bound {
					return android.ErrNotBound
				}
			}
			return android.SetSelfMode(ctx, tx, mode, res.Subject)
		})
	switch {
	case errors.Is(err, android.ErrNotBound):
		back(w, r, "/android", "Bind an Android Enterprise first. People cannot enrol a phone until there is one.")
	case errors.Is(err, android.ErrBadSelfMode):
		back(w, r, "/android", "That is not one of the choices.")
	case err != nil:
		g.log.Error("self-enrolment setting", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/android", "The setting could not be saved. Try again.")
	default:
		g.log.Info("self-service enrolment setting changed", "tenant", res.Tenant.Slug, "mode", mode, "by", res.Subject)
		msg := "Saved. People can no longer enrol themselves."
		if mode == android.SelfPersonal {
			msg = "Saved. Everyone can now enrol their own phone. Send them the link below."
		} else if mode == android.SelfAny {
			msg = "Saved. Everyone can now enrol their own phone or a new company phone. Send them the link below."
		}
		back(w, r, "/android", msg)
	}
}

// tidyLabel keeps what a person typed as the name of their phone, minus
// anything that is not a visible character. It goes into a table and an
// audit line, and a line break has no business in either.
func tidyLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
		if b.Len() >= 60 {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "My phone"
	}
	return out
}
