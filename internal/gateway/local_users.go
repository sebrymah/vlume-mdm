package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/authz"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/identity"
	"platform/internal/localauth"
	"platform/internal/notify"
)

// The Users page (0044): where a Super Admin keeps the people of a tenant
// that has no identity provider. Everything on it is a Super Admin's, because
// the person who can add somebody and choose what they may do is the person
// who controls access.

var errNotLocal = errors.New("this organisation signs in through an identity provider")

// validEmail is a bare, plausible address. Not the sign-up's WorkEmail: a
// tenant's own people may use any mailbox, a small co-operative's among
// them, and the address is an identifier here, not a proof of a company.
func validEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 || strings.ContainsAny(s, "\r\n\t ") {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return "", false
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 || !strings.Contains(s[at+1:], ".") {
		return "", false
	}
	return data.NormaliseEmail(s), true
}

func (g *Gateway) loadUsers(ctx context.Context, tx *data.Tx, out *console.Users) error {
	accounts, err := data.ListLocalAccounts(ctx, tx)
	if err != nil {
		return err
	}
	policy, err := data.LocalMFAPolicy(ctx, tx)
	if err != nil {
		return err
	}
	out.Accounts, out.Roles, out.MFAPolicy = accounts, data.LocalRoles, policy
	out.CanMail = g.mail != nil && g.notify != nil
	return nil
}

func (g *Gateway) consoleUsers(w http.ResponseWriter, r *http.Request, s console.Session) {
	g.console.UsersPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Users) error {
		return g.loadUsers(ctx, tx, out)
	})
}

// usersAgain shows the page again with a link on it, once.
func (g *Gateway) usersAgain(w http.ResponseWriter, r *http.Request, res Resolution, show func(*console.Users)) {
	s := console.Session{Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject, CSRF: g.csrfToken(res)}
	g.console.UsersPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Users) error {
		if err := g.loadUsers(ctx, tx, out); err != nil {
			return err
		}
		show(out)
		return nil
	})
}

// mailLink sends a link to a person, branded as the tenant, after the
// transaction that made it. It says whether it was sent and, if not, why.
func (g *Gateway) mailLink(ctx context.Context, to string, msg notify.Message) (bool, string) {
	if g.mail == nil || g.notify == nil {
		return false, ""
	}
	if err := g.mail.Deliver(ctx, to, msg); err != nil {
		g.log.Error("local account email", "err", err)
		return false, err.Error()
	}
	return true, ""
}

func (g *Gateway) inviteMessage(host, org, email, link string, reset bool) notify.Message {
	if reset {
		return notify.Message{
			Subject: "Reset your password for " + org,
			Body: "An administrator at " + org + " has made a password reset link for " + email + ". " +
				"Choose a new password here; the link works once, for an hour:\n\n  " + link + "\n\n" +
				"If you did not expect this, tell your administrator.\n",
		}
	}
	return notify.Message{
		Subject: "You have been invited to " + org,
		Body: "You have been invited to " + org + " as " + email + ".\n\n" +
			"Choose a password here. The link works once, for seven days:\n\n  " + link + "\n\n" +
			"You will sign in with your email address and that password" +
			", and administrators are asked to set up an authenticator app the first time.\n",
	}
}

func (g *Gateway) consoleUserInvite(w http.ResponseWriter, r *http.Request, res Resolution) {
	email, ok := validEmail(r.FormValue("email"))
	if !ok {
		back(w, r, "/users", "That is not an email address.")
		return
	}
	role := strings.TrimSpace(r.FormValue("role"))
	name := strings.TrimSpace(r.FormValue("name"))
	if len(name) > 120 || strings.ContainsAny(name, "\r\n") {
		back(w, r, "/users", "That name is too long, or has a line break in it.")
		return
	}
	token, hash, err := newLocalToken()
	if err != nil {
		back(w, r, "/users", "Something went wrong making the link.")
		return
	}
	link := g.consoleBaseOf(r) + "/signin/local/accept/" + token
	wantMail := r.FormValue("send") == "1"
	now := time.Now().UTC()
	var msg notify.Message
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()), func(ctx context.Context, tx *data.Tx) error {
		if local, e := data.LocalModeOn(ctx, tx); e != nil || !local {
			if e != nil {
				return e
			}
			return errNotLocal
		}
		id, e := data.CreateLocalAccount(ctx, tx, email, name, role, res.Subject)
		if e != nil {
			return e
		}
		if e := data.IssueLocalToken(ctx, tx, id, "invite", hash, now.Add(data.InviteLife), now); e != nil {
			return e
		}
		if wantMail && g.notify != nil {
			msg = g.inviteMessage("", res.Tenant.Name, email, link, false)
			return g.notify.Stamp(ctx, tx, &msg)
		}
		return nil
	})
	switch {
	case errors.Is(err, data.ErrAccountExists):
		back(w, r, "/users", email+" already has an account here. Use \"New link\" or \"Reset password\" on their row.")
		return
	case errors.Is(err, data.ErrBadRole):
		back(w, r, "/users", "That is not a role.")
		return
	case errors.Is(err, errNotLocal):
		back(w, r, "/identity", err.Error()+".")
		return
	case err != nil:
		g.log.Error("invite", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/users", "Not invited.")
		return
	}
	emailed, mailErr := false, ""
	if msg.Subject != "" {
		emailed, mailErr = g.mailLink(r.Context(), email, msg)
	}
	g.log.Info("local account invited", "tenant", res.Tenant.Slug, "by", res.Subject)
	g.usersAgain(w, r, res, func(u *console.Users) {
		u.NewLink, u.NewLinkFor, u.NewLinkKind = link, email, "Invitation"
		u.Emailed, u.MailError = emailed, mailErr
	})
}

func (g *Gateway) consoleUserMFAPolicy(w http.ResponseWriter, r *http.Request, res Resolution) {
	policy := strings.TrimSpace(r.FormValue("policy"))
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()), func(ctx context.Context, tx *data.Tx) error {
		return data.SetLocalMFAPolicy(ctx, tx, policy)
	})
	if err != nil {
		back(w, r, "/users", "That is not a choice.")
		return
	}
	back(w, r, "/users", "Saved. It applies from each person's next sign-in.")
}

// consoleUserAct is every button on a row of the Users page.
func (g *Gateway) consoleUserAct(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		back(w, r, "/users", "No such account.")
		return
	}
	action := r.PathValue("action")
	now := time.Now().UTC()
	var link, linkKind, linkFor string
	var msg notify.Message
	var token string
	var hash []byte
	if action == "reset-link" || action == "invite-again" {
		if token, hash, err = newLocalToken(); err != nil {
			back(w, r, "/users", "Something went wrong making the link.")
			return
		}
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()), func(ctx context.Context, tx *data.Tx) error {
		if local, e := data.LocalModeOn(ctx, tx); e != nil || !local {
			if e != nil {
				return e
			}
			return errNotLocal
		}
		acct, e := data.LocalAccountByID(ctx, tx, id)
		if e != nil {
			return e
		}
		switch action {
		case "role":
			if e := data.ChangeLocalRole(ctx, tx, id, strings.TrimSpace(r.FormValue("role"))); e != nil {
				return e
			}
			// The role is in the session, so a session made under the old
			// one is ended rather than left to keep it.
			return g.endSessions(ctx, tx, res.Tenant, acct.Subject(), now)
		case "disable":
			if e := data.SetLocalStatus(ctx, tx, id, true); e != nil {
				return e
			}
			// Signed out everywhere, and the seat is freed: an
			// administrator who has gone should not be holding one.
			if _, e := tx.Exec(ctx, `UPDATE tenant_admins SET last_seen_at = to_timestamp(0) WHERE subject = $1`, acct.Subject()); e != nil {
				return e
			}
			return g.endSessions(ctx, tx, res.Tenant, acct.Subject(), now)
		case "enable":
			return data.SetLocalStatus(ctx, tx, id, false)
		case "unlock":
			return data.UnlockLocalAccount(ctx, tx, id)
		case "mfa-reset":
			if e := data.ResetMFA(ctx, tx, id); e != nil {
				return e
			}
			return g.endSessions(ctx, tx, res.Tenant, acct.Subject(), now)
		case "reset-link", "invite-again":
			if acct.Status == "disabled" {
				return data.ErrNoSuchAccount
			}
			purpose, life, kind := "reset", data.ResetLife, "Reset link"
			if action == "invite-again" {
				purpose, life, kind = "invite", data.InviteLife, "New invitation"
			}
			if acct.Status == "invited" && action == "reset-link" {
				return data.ErrNoSuchAccount // an invitation is what they need
			}
			if acct.Status == "active" && action == "invite-again" {
				return data.ErrNoSuchAccount
			}
			if e := data.IssueLocalToken(ctx, tx, id, purpose, hash, now.Add(life), now); e != nil {
				return e
			}
			link = g.consoleBaseOf(r) + "/signin/local/" + map[string]string{"reset": "reset", "invite": "accept"}[purpose] + "/" + token
			linkKind, linkFor = kind, acct.Email
			if g.notify != nil && g.mail != nil {
				msg = g.inviteMessage("", res.Tenant.Name, acct.Email, link, purpose == "reset")
				if e := g.notify.Stamp(ctx, tx, &msg); e != nil {
					return e
				}
			}
			return data.AppendAudit(ctx, tx, "local.link_made", "account:"+id.String()+" kind:"+purpose)
		}
		return errors.New("no such action")
	})
	switch {
	case errors.Is(err, data.ErrLastSuperAdmin):
		back(w, r, "/users", "That would leave nobody who can manage access. Make someone else a super admin first.")
		return
	case errors.Is(err, data.ErrNoSuchAccount):
		back(w, r, "/users", "That does not apply to this account as it is now.")
		return
	case errors.Is(err, data.ErrBadRole):
		back(w, r, "/users", "That is not a role.")
		return
	case errors.Is(err, errNotLocal):
		back(w, r, "/identity", err.Error()+".")
		return
	case err != nil:
		g.log.Error("account action", "tenant", res.Tenant.Slug, "action", action, "err", err)
		back(w, r, "/users", "That did not work.")
		return
	}
	g.log.Info("local account changed", "tenant", res.Tenant.Slug, "action", action, "by", res.Subject)
	if link != "" {
		emailed, mailErr := false, ""
		if msg.Subject != "" {
			emailed, mailErr = g.mailLink(r.Context(), linkFor, msg)
		}
		g.usersAgain(w, r, res, func(u *console.Users) {
			u.NewLink, u.NewLinkFor, u.NewLinkKind = link, linkFor, linkKind
			u.Emailed, u.MailError = emailed, mailErr
		})
		return
	}
	back(w, r, "/users", "Done.")
}

// ---------------------------------------------------------------- account

func accountIDOf(subject string) (uuid.UUID, bool) {
	if !data.IsLocalSubject(subject) {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(strings.TrimPrefix(subject, "local:"))
	return id, err == nil
}

func (g *Gateway) consoleAccount(w http.ResponseWriter, r *http.Request, s console.Session) {
	id, ok := accountIDOf(s.Subject)
	if !ok {
		http.NotFound(w, r)
		return
	}
	g.console.AccountPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Account) error {
		a, err := data.LocalAccountByID(ctx, tx, id)
		if err != nil {
			return err
		}
		policy, err := data.LocalMFAPolicy(ctx, tx)
		if err != nil {
			return err
		}
		out.Email, out.Name, out.Role = a.Email, a.Name, a.Role
		out.MFAOn, out.RecoveryLeft = a.TOTPEnabled, a.RecoveryLeft
		out.MFARequired = data.MFARequired(policy, a.Role)
		return nil
	})
}

func (g *Gateway) consoleAccountPassword(w http.ResponseWriter, r *http.Request, res Resolution) {
	id, ok := accountIDOf(res.Subject)
	if !ok {
		back(w, r, "/", "Only an account kept here has a password to change.")
		return
	}
	pw := r.FormValue("password")
	if pw != r.FormValue("confirm") {
		back(w, r, "/account", "The two new passwords are not the same.")
		return
	}
	var acct data.LocalAccount
	if err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()), func(ctx context.Context, tx *data.Tx) error {
		var e error
		acct, e = data.LocalAccountByID(ctx, tx, id)
		return e
	}); err != nil {
		back(w, r, "/account", "That did not work.")
		return
	}
	// The current password again, so a session left open on a borrowed
	// laptop is not a way to take the account over.
	if g.limiter.allowKey("local:account-pw:"+res.Subject, 5) == false {
		back(w, r, "/account", "Too many tries. Wait a minute.")
		return
	}
	if err := localauth.Verify(r.FormValue("current"), acct.PasswordHash); err != nil {
		back(w, r, "/account", "The current password is not right.")
		return
	}
	if err := localauth.CheckPassword(pw, acct.Email, acct.Name, res.Tenant.Name); err != nil {
		back(w, r, "/account", "That password will not do: "+err.Error()+".")
		return
	}
	encoded, err := localauth.Hash(pw)
	if err != nil {
		back(w, r, "/account", "That password could not be used.")
		return
	}
	now := time.Now().UTC()
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()), func(ctx context.Context, tx *data.Tx) error {
		if e := data.SetLocalPassword(ctx, tx, id, encoded, now); e != nil {
			return e
		}
		return g.endSessions(ctx, tx, res.Tenant, acct.Subject(), now)
	})
	if err != nil {
		g.log.Error("account password", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/account", "That did not work.")
		return
	}
	// Every session that person had is gone, this one among them. They
	// have just proved who they are, so they get a fresh one.
	claims := identity.Claims{Subject: acct.Subject(), Email: acct.Email, Name: acct.Name}
	if !g.startSession(w, r, res.Tenant, claims, authz.Role(acct.Role)) {
		return
	}
	back(w, r, "/account", "Password changed. You have been signed out everywhere else.")
}

var (
	errMapAdminFirst = errors.New("Not saved. This organisation signs in with accounts kept here. Map a group to Super Admin under \"Who gets which role\" first, or nobody will be able to sign in after the switch.")
	errNeedSecret    = errors.New("Not saved. Replacing local sign-in with an identity provider needs the provider's client secret.")
)

// guardLeavingLocal is the check made when a tenant that keeps its own
// accounts connects an identity provider instead: after the switch its
// accounts stop signing in, so there must already be a group that becomes
// Super Admin, or the tenant locks itself out of the one page that could
// fix it. haveSecret says the form carried the provider's secret, which a
// tenant that never had one cannot keep.
func (g *Gateway) guardLeavingLocal(ctx context.Context, tx *data.Tx, haveSecret bool) error {
	local, err := data.LocalModeOn(ctx, tx)
	if err != nil || !local {
		return err
	}
	if !haveSecret {
		return errNeedSecret
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_role_map WHERE role = 'super_admin'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errMapAdminFirst
	}
	return nil
}
