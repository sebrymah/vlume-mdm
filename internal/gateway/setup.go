package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"platform/internal/notify"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"platform/internal/android"
	"platform/internal/authz"
	"platform/internal/branding"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/enrol"
	"platform/internal/identity"
)

// Setup is the wizard T1 asks for, built as a checklist rather than a
// sequence of modal steps. A checklist can be left and come back to, shows
// what is done and what is not, and does not trap somebody on step three
// because step two is waiting for a colleague's DNS change.
//
// It also carries the PRD's first success metric, time from sign-up to first
// enrolled device, because a metric that is not shown is one nobody is held
// to.

// readiness reads every setting the checklist cares about in one tenant
// transaction, so the page cannot show one setting's state beside another
// tenant's.
func (g *Gateway) readiness(ctx context.Context, tx *data.Tx, t directory.Tenant,
	host string) (console.Setup, error) {

	s := console.Setup{CreatedAt: t.CreatedAt, Host: host}
	add := func(st console.SetupStep) { s.Steps = append(s.Steps, st) }

	// 1. The name on the door.
	b, err := branding.Load(ctx, tx)
	if err != nil {
		return s, err
	}
	add(console.SetupStep{
		Key: "brand", Title: "Give it your name",
		Detail: "The product name, colour and legal footer your staff see.",
		Href:   "/branding", Done: !b.IsPlaceholder(),
	})

	// 2. Where it lives. Set by the operator, shown so the checklist is
	// complete, not editable here: a tenant choosing its own hostname would
	// be a tenant choosing to answer on somebody else's.
	add(console.SetupStep{
		Key: "host", Title: "Where it lives",
		Detail: "This console answers at " + host + ". Changing that is your operator's job.",
		Done:   true,
	})

	// 3. Sign-in. Somebody is reading this page, so the provider works; what
	// can still be missing is anyone beyond the first group.
	var identities, mappings int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_identity`).Scan(&identities); err != nil {
		return s, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_role_map`).Scan(&mappings); err != nil {
		return s, err
	}
	add(console.SetupStep{
		Key: "signin", Title: "Decide who gets in",
		Detail: fmt.Sprintf("Your identity provider is connected and %d of its groups "+
			"map to a role here. Map the groups for IT, security and the help desk.",
			mappings),
		Href: "/identity", Done: identities > 0 && mappings >= 2,
	})

	// 4. Being told.
	var targets int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_targets`).Scan(&targets); err != nil {
		return s, err
	}
	add(console.SetupStep{
		Key: "notify", Title: "Decide who is told",
		Detail: "Point a lost-device report, or a wipe waiting for approval, at a " +
			"channel or an inbox somebody watches.",
		Href: "/notifications", Done: targets > 0,
	})

	// 5. Sending as themselves.
	var verified int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM sending_domains WHERE verified_at IS NOT NULL`).Scan(&verified); err != nil {
		return s, err
	}
	add(console.SetupStep{
		Key: "region", Title: "Where your data is kept",
		Detail: "This tenant's records, keys and reports are kept in " + t.Region + ". " +
			"Chosen at sign-up; moving a tenant between regions is an operator's job.",
		Done: true,
	})
	add(console.SetupStep{
		Key: "domain", Title: "Send mail as your own domain",
		Detail: "Signed, so notifications reach inboxes rather than spam folders.",
		Href:   "/notifications", Done: verified > 0, Optional: true,
	})

	// 5b. The network. Done only when the network has actually asked: a
	// token minted and never used is an integration somebody meant to
	// finish, and the platform cannot see the network's side any other way.
	var tokens int
	var lastName string
	var lastAsked *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT count(*),
		       coalesce((SELECT name FROM integration_tokens
		                  WHERE revoked_at IS NULL AND last_used_at IS NOT NULL
		                  ORDER BY last_used_at DESC LIMIT 1), ''),
		       (SELECT max(last_used_at) FROM integration_tokens WHERE revoked_at IS NULL)
		  FROM integration_tokens WHERE revoked_at IS NULL`).Scan(&tokens, &lastName, &lastAsked); err != nil {
		return s, err
	}
	network := console.SetupStep{
		Key: "network", Title: "Connect your network", Href: "/identity", Optional: true,
		Detail: "Point your Wi-Fi controller, VPN or NAC at the access feed with a token " +
			"from the Sign-in page. It denies quarantined devices and ones that have not " +
			"reported clean.",
	}
	switch {
	case lastAsked != nil:
		network.Done = true
		network.Detail = fmt.Sprintf("%s last asked at %s.", lastName,
			lastAsked.UTC().Format("2 Jan 2006 15:04 UTC"))
	case tokens > 0:
		network.Detail = fmt.Sprintf("%d token(s) minted, but nothing has asked yet. "+
			"The network is not connected until it does.", tokens)
	}
	add(network)

	// 6 and 7. Honest about what cannot be done yet. A step that cannot be
	// completed and does not say why is a step somebody opens a ticket about.
	add(console.SetupStep{
		Key: "abm", Title: "Apple Business Manager",
		Detail: "Zero-touch enrolment for company-owned Apple devices.",
		Blocked: "Waiting on the Apple MDM vendor certificate, which has been applied for. " +
			"Devices can be enrolled by link in the meantime.",
	})
	androidStep := console.SetupStep{
		Key: "android", Title: "Android Enterprise",
		Detail: "Managed Google Play and work profiles. Bind this tenant to its own " +
			"enterprise by signing in with a Google account.",
		Href: "/android", Optional: true,
	}
	if !t.Feature(directory.FeatureAndroid) {
		androidStep.Blocked = "Not part of this tenant's plan."
		androidStep.Href = ""
	} else if !g.androidReady() {
		androidStep.Blocked = "The operator has not connected Google's Android Management API " +
			"(a service account). Android devices cannot be managed until that is done."
		androidStep.Href = ""
	} else if _, bound, err := android.Bound(ctx, tx); err != nil {
		return s, err
	} else if bound {
		androidStep.Done = true
	}
	add(androidStep)

	// 8. The one that proves the rest worked.
	var devices int
	var first *time.Time
	if err := tx.QueryRow(ctx,
		`SELECT count(*), min(created_at) FROM devices`).Scan(&devices, &first); err != nil {
		return s, err
	}
	add(console.SetupStep{
		Key: "device", Title: "Enrol your first device",
		Detail: "Invite one, run the agent on it, and watch it appear.",
		Href:   "/enrolments", Done: devices > 0,
	})
	s.FirstDeviceAt = first
	if first != nil {
		d := first.Sub(t.CreatedAt)
		switch {
		case d < 0:
			// A device older than its tenant: seeded data. Say nothing
			// rather than something false.
		case d < time.Hour:
			s.TimeToFirst = fmt.Sprintf("%d minutes", int(d.Minutes()))
		case d < 48*time.Hour:
			s.TimeToFirst = fmt.Sprintf("%d hours", int(d.Hours()))
		default:
			s.TimeToFirst = fmt.Sprintf("%d days", int(d.Hours()/24))
		}
	}

	// Ready means the required steps are done. Optional and blocked ones
	// do not count against it, or a tenant could never be ready.
	s.Ready = true
	for _, st := range s.Steps {
		if !st.Done && !st.Optional && st.Blocked == "" {
			s.Ready = false
		}
	}
	return s, nil
}

func (g *Gateway) consoleSetup(w http.ResponseWriter, r *http.Request, s console.Session) {
	res := ResolutionFrom(r.Context())
	g.console.SetupPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Setup) error {
		rd, err := g.readiness(ctx, tx, res.Tenant, r.Host)
		if err != nil {
			return err
		}
		*out = rd
		return nil
	})
}

func (g *Gateway) apiSetup(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	var out console.Setup
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			rd, err := g.readiness(ctx, tx, res.Tenant, r.Host)
			out = rd
			return err
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the setup state")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- branding

func (g *Gateway) consoleBranding(w http.ResponseWriter, r *http.Request, s console.Session) {
	g.console.BrandingPage(w, r, s)
}

func (g *Gateway) consoleSaveBranding(w http.ResponseWriter, r *http.Request, res Resolution) {
	b := branding.Brand{
		ProductName: strings.TrimSpace(r.FormValue("product_name")),
		LegalFooter: strings.TrimSpace(r.FormValue("legal_footer")),
		LostPhone:   strings.TrimSpace(r.FormValue("lost_phone")),
		LostEmail:   strings.TrimSpace(r.FormValue("lost_email")),
		Colour:      strings.TrimSpace(r.FormValue("colour")),
		MarkLetter:  strings.ToUpper(strings.TrimSpace(r.FormValue("mark_letter"))),
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return branding.Save(ctx, tx, b)
		})
	if err != nil {
		// The contrast guard's message says which colour and why, and that
		// is the message the person needs.
		back(w, r, "/branding", "Not saved. "+err.Error())
		return
	}
	g.log.Info("branding saved", "tenant", res.Tenant.Slug, "by", res.Subject)
	back(w, r, "/branding", "Saved. Your staff see it from their next page.")
}

// ---------------------------------------------------------------- identity
//
// Guarded by access.manage, which only a Super Admin holds. Anybody who can
// edit the role map can map their own group to super_admin, so editing it
// has to be gated to people who already are. That is the whole reason the
// action exists.

func (g *Gateway) consoleIdentity(w http.ResponseWriter, r *http.Request, s console.Session) {
	seats := ResolutionFrom(r.Context()).Tenant.AdminSeats
	g.console.IdentityPage(w, r, s, func(ctx context.Context, tx *data.Tx, out *console.Identity) error {
		if err := g.loadIdentity(ctx, tx, out); err != nil {
			return err
		}
		// ?protocol=saml shows the other form without changing anything:
		// the stored protocol changes only on save. The stored values are
		// not shown on the other form, since they mean different things.
		if want := r.URL.Query().Get("protocol"); (want == identity.ProtocolSAML || want == identity.ProtocolOIDC) && want != out.Protocol {
			out.Protocol, out.Issuer, out.ClientID, out.RedirectURL = want, "", "", ""
			out.SAMLSSOURL, out.HasCertificate, out.HasSecret = "", false, false
		}
		return loadSeats(ctx, tx, out, seats)
	})
}

// loadSeats lists who holds a seat. The window is the same one takeSeat
// uses, so the page and the refusal never disagree about the count.
func loadSeats(ctx context.Context, tx *data.Tx, out *console.Identity, cap int) error {
	out.SeatCap = cap
	rows, err := tx.Query(ctx, `
		SELECT subject, email, name, role, last_seen_at FROM tenant_admins
		 WHERE last_seen_at > now() - $1::interval ORDER BY last_seen_at DESC`, seatWindow.String())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var s console.Seat
		if err := rows.Scan(&s.Subject, &s.Email, &s.Name, &s.Role, &s.LastSeenAt); err != nil {
			return err
		}
		out.Seats = append(out.Seats, s)
	}
	out.SeatsUsed = len(out.Seats)
	return rows.Err()
}

// consoleReleaseSeat frees a seat. The person can sign in again when one
// is free; nothing about their role changes, because the role is the
// identity provider's to give and this page only counts.
func (g *Gateway) consoleReleaseSeat(w http.ResponseWriter, r *http.Request, res Resolution) {
	subject := strings.TrimSpace(r.FormValue("subject"))
	if subject == "" {
		back(w, r, "/identity", "Nothing named.")
		return
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			// The row stays, lapsed, so the seat is free and the sign-out
			// stamp holds: a released person keeps no session either.
			tag, err := tx.Exec(ctx, `
				UPDATE tenant_admins SET last_seen_at = to_timestamp(0), sessions_invalid_before = now()
				 WHERE subject = $1 AND last_seen_at > now() - $2::interval`, subject, seatWindow.String())
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return pgx.ErrNoRows
			}
			return data.AppendAudit(ctx, tx, "seat.released", subject)
		})
	if errors.Is(err, pgx.ErrNoRows) {
		back(w, r, "/identity", "That seat was already free.")
		return
	}
	if err != nil {
		g.log.Error("release seat", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/identity", "The seat could not be released.")
		return
	}
	g.revoked.forget(res.Tenant.ID, subject)
	back(w, r, "/identity", "Seat released and their sessions ended. The next administrator to sign in takes the seat.")
}

func (g *Gateway) loadIdentity(ctx context.Context, tx *data.Tx, out *console.Identity) error {
	var sealedLen int
	var certPEM string
	err := tx.QueryRow(ctx, `
		SELECT issuer, client_id, role_claim, redirect_url, length(client_secret_sealed),
		       protocol, saml_sso_url, saml_certificate, saml_slo_url, saml_sp_cert <> ''
		  FROM tenant_identity`).Scan(
		&out.Issuer, &out.ClientID, &out.RoleClaim, &out.RedirectURL, &sealedLen,
		&out.Protocol, &out.SAMLSSOURL, &certPEM, &out.SAMLSLOURL, &out.HasSigningKey)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		out.Configured = false
		out.Protocol = identity.ProtocolOIDC
	case err != nil:
		return err
	default:
		out.Configured = true
		out.HasSecret = sealedLen > 0
		if cert, _, cerr := identity.ParseCertificate(certPEM); cerr == nil {
			out.HasCertificate = true
			out.CertSubject = cert.Subject.String()
			na := cert.NotAfter
			out.CertNotAfter = &na
		}
	}

	rows, err := tx.Query(ctx,
		`SELECT claim_value, role FROM tenant_role_map ORDER BY claim_value`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var m console.RoleMapping
		if err := rows.Scan(&m.ClaimValue, &m.Role); err != nil {
			return err
		}
		out.Roles = append(out.Roles, m)
	}
	for _, role := range authz.Roles() {
		if authz.FromTenantIdentity(role) {
			out.RoleChoices = append(out.RoleChoices, string(role))
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_ = tx.QueryRow(ctx, `SELECT version, created_at FROM tenant_keys WHERE retired_at IS NULL`).Scan(&out.KeyVersion, &out.KeyCreatedAt)
	return g.loadTokens(ctx, tx, out)
}

func (g *Gateway) consoleSaveIdentity(w http.ResponseWriter, r *http.Request, res Resolution) {
	if strings.TrimSpace(r.FormValue("protocol")) == identity.ProtocolSAML {
		g.consoleSaveSAML(w, r, res)
		return
	}
	issuer := strings.TrimSpace(r.FormValue("issuer"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	secret := strings.TrimSpace(r.FormValue("client_secret"))
	roleClaim := strings.TrimSpace(r.FormValue("role_claim"))
	if roleClaim == "" {
		roleClaim = "groups"
	}
	if issuer == "" || clientID == "" {
		back(w, r, "/identity", "Not saved. An issuer and a client id are both needed.")
		return
	}
	if !strings.HasPrefix(issuer, "https://") && !strings.HasPrefix(issuer, "http://127.0.0.1") {
		back(w, r, "/identity", "Not saved. The issuer is an https:// address.")
		return
	}

	// The redirect URL is derived from where this request arrived, never
	// typed, so it cannot disagree with where the console actually is.
	scheme := "https"
	if r.TLS == nil && g.insecureCookies {
		scheme = "http"
	}
	redirect := scheme + "://" + r.Host + "/signin/callback"

	// An empty secret on the form means "keep the one you have". A page
	// that made somebody re-enter the secret to change the role claim would
	// be a page where the secret gets pasted into chat to be found later.
	if secret != "" && g.sealer == nil {
		back(w, r, "/identity", "Not saved. This deployment has no sealing key.")
		return
	}

	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			// A tenant that keeps its own accounts must not switch itself
			// into a state nobody can sign in from (0044).
			if e := g.guardLeavingLocal(ctx, tx, secret != ""); e != nil {
				return e
			}
			var sealed []byte
			if secret != "" {
				var serr error
				if sealed, serr = g.sealer.Seal(ctx, tx, []byte(secret)); serr != nil {
					return serr
				}
			}
			_, err := tx.Exec(ctx, `
				INSERT INTO tenant_identity
				  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim,
				   protocol, saml_sso_url, saml_certificate)
				VALUES (app.current_tenant(), $1, $2, coalesce($3, ''::bytea), $4, $5, 'oidc', '', '')
				ON CONFLICT (tenant_id) DO UPDATE SET
				  issuer = excluded.issuer, client_id = excluded.client_id,
				  client_secret_sealed = CASE WHEN $3 IS NULL
				                              THEN tenant_identity.client_secret_sealed
				                              ELSE excluded.client_secret_sealed END,
				  redirect_url = excluded.redirect_url, role_claim = excluded.role_claim,
				  protocol = 'oidc', saml_sso_url = '', saml_certificate = ''`,
				issuer, clientID, sealed, redirect, roleClaim)
			if err != nil {
				return err
			}
			return data.AppendAudit(ctx, tx, "identity.saved", issuer)
		})
	if errors.Is(err, errMapAdminFirst) || errors.Is(err, errNeedSecret) {
		back(w, r, "/identity", err.Error())
		return
	}
	if err != nil {
		g.log.Error("identity save", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/identity", "Not saved.")
		return
	}
	back(w, r, "/identity", "Saved. Register "+redirect+" at the identity provider if you have not.")
}

// consoleSaveSAML is the SAML half of the provider form. Our entity id and
// assertion consumer service are derived from where this request arrived,
// as the OIDC redirect is, so they cannot disagree with where the console
// is. The certificate is parsed before it is stored: a certificate that
// does not parse would lock everyone out at the next sign-in, and the
// person who could fix it is the one who just got locked out.
func (g *Gateway) consoleSaveSAML(w http.ResponseWriter, r *http.Request, res Resolution) {
	entityID := strings.TrimSpace(r.FormValue("issuer"))
	ssoURL := strings.TrimSpace(r.FormValue("saml_sso_url"))
	sloURL := strings.TrimSpace(r.FormValue("saml_slo_url"))
	certText := strings.TrimSpace(r.FormValue("saml_certificate"))
	roleClaim := strings.TrimSpace(r.FormValue("role_claim"))
	if roleClaim == "" {
		roleClaim = "groups"
	}
	if entityID == "" || ssoURL == "" {
		back(w, r, "/identity", "Not saved. The provider's entity id and sign-in URL are both needed.")
		return
	}
	if !strings.HasPrefix(ssoURL, "https://") && !strings.HasPrefix(ssoURL, "http://127.0.0.1") {
		back(w, r, "/identity", "Not saved. The sign-in URL is an https:// address.")
		return
	}
	if sloURL != "" && !strings.HasPrefix(sloURL, "https://") && !strings.HasPrefix(sloURL, "http://127.0.0.1") {
		back(w, r, "/identity", "Not saved. The logout URL is an https:// address, or blank for no single logout.")
		return
	}
	var certPEM *string
	if certText != "" {
		_, norm, err := identity.ParseCertificate(certText)
		if err != nil {
			back(w, r, "/identity", "Not saved. That is not a certificate: paste the provider's signing certificate, PEM or base64.")
			return
		}
		certPEM = &norm
	}

	scheme := "https"
	if r.TLS == nil && g.insecureCookies {
		scheme = "http"
	}
	base := scheme + "://" + r.Host
	ours := base + "/saml/metadata"
	acs := base + "/signin/saml"

	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if e := g.guardLeavingLocal(ctx, tx, true); e != nil {
				return e
			}
			// An empty certificate on the form keeps the one held, as an
			// empty client secret does for OIDC. The first save needs one,
			// which the table's own check enforces.
			tag, err := tx.Exec(ctx, `
				INSERT INTO tenant_identity
				  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim,
				   protocol, saml_sso_url, saml_certificate, saml_slo_url)
				VALUES (app.current_tenant(), $1, $2, ''::bytea, $3, $4, 'saml', $5, coalesce($6, ''), $7)
				ON CONFLICT (tenant_id) DO UPDATE SET
				  issuer = excluded.issuer, client_id = excluded.client_id,
				  client_secret_sealed = ''::bytea,
				  redirect_url = excluded.redirect_url, role_claim = excluded.role_claim,
				  protocol = 'saml', saml_sso_url = excluded.saml_sso_url,
				  saml_slo_url = excluded.saml_slo_url,
				  saml_certificate = CASE WHEN $6 IS NULL
				                          THEN tenant_identity.saml_certificate
				                          ELSE excluded.saml_certificate END`,
				entityID, ours, acs, roleClaim, ssoURL, certPEM, sloURL)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return errors.New("nothing written")
			}
			return data.AppendAudit(ctx, tx, "identity.saved", "saml:"+entityID)
		})
	if errors.Is(err, errMapAdminFirst) {
		back(w, r, "/identity", err.Error())
		return
	}
	if err != nil {
		if certPEM == nil {
			back(w, r, "/identity", "Not saved. The first SAML save needs the provider's signing certificate.")
			return
		}
		g.log.Error("saml identity save", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/identity", "Not saved.")
		return
	}
	back(w, r, "/identity", "Saved. Give your provider our metadata at "+ours+" (or the entity id and the reply URL "+acs+") if you have not.")
}

func (g *Gateway) consoleAddRole(w http.ResponseWriter, r *http.Request, res Resolution) {
	value := strings.TrimSpace(r.FormValue("claim_value"))
	role, err := authz.Parse(strings.TrimSpace(r.FormValue("role")))
	if value == "" || err != nil || !authz.FromTenantIdentity(role) {
		back(w, r, "/identity", "Not saved. Name a group and pick one of the six roles.")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			if _, err := tx.Exec(ctx, `
				INSERT INTO tenant_role_map (tenant_id, claim_value, role)
				VALUES (app.current_tenant(), $1, $2)
				ON CONFLICT (tenant_id, claim_value) DO UPDATE SET role = excluded.role`,
				value, string(role)); err != nil {
				return err
			}
			return data.AppendAudit(ctx, tx, "role_map.set", value+" -> "+string(role))
		})
	if err != nil {
		back(w, r, "/identity", "Not saved.")
		return
	}
	g.log.Info("role mapping set", "tenant", res.Tenant.Slug, "group", value,
		"role", role, "by", res.Subject)
	back(w, r, "/identity", "Saved. It applies from each person's next sign-in.")
}

func (g *Gateway) consoleRemoveRole(w http.ResponseWriter, r *http.Request, res Resolution) {
	value := strings.TrimSpace(r.FormValue("claim_value"))
	if value == "" {
		back(w, r, "/identity", "Nothing named.")
		return
	}
	var lastAdmin bool
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			// The lock-out guard. Removing the only mapping to super_admin
			// leaves a tenant nobody can administer, and the people who
			// could fix it are exactly the people it has just locked out.
			var role string
			var admins int
			if err := tx.QueryRow(ctx,
				`SELECT role FROM tenant_role_map WHERE claim_value = $1`, value).Scan(&role); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM tenant_role_map WHERE role = 'super_admin'`).Scan(&admins); err != nil {
				return err
			}
			if role == "super_admin" && admins <= 1 {
				lastAdmin = true
				return errors.New("last admin")
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM tenant_role_map WHERE claim_value = $1`, value); err != nil {
				return err
			}
			return data.AppendAudit(ctx, tx, "role_map.removed", value)
		})
	switch {
	case lastAdmin:
		back(w, r, "/identity", "Not removed. That is the only group mapped to Super Admin, "+
			"and removing it would leave nobody able to administer this console. "+
			"Map another group to Super Admin first.")
	case errors.Is(err, pgx.ErrNoRows):
		back(w, r, "/identity", "That group was not mapped to anything.")
	case err != nil:
		back(w, r, "/identity", "Not removed.")
	default:
		g.log.Info("role mapping removed", "tenant", res.Tenant.Slug, "group", value,
			"by", res.Subject)
		back(w, r, "/identity", "Removed. Members of that group lose their role at their next sign-in.")
	}
}

var _ = enrol.DefaultLife

// brandingEmailPreview shows what an email from this tenant looks like:
// the same renderer, the same stamp, a sample message. What the person
// sees here is what their staff get, which is the only honest preview.
func (g *Gateway) brandingEmailPreview(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	m := notify.Message{
		Topic:   notify.DeviceLost,
		Subject: "HQ-MBP-002 was reported lost",
		Body: "O. Martins reported HQ-MBP-002 (serial C02XK4YTQ71W) lost: left it in a taxi.\n\n" +
			"The device has been locked. When it is found, release it from the console.\n\n" +
			"https://" + r.Host + "/devices",
		ObjectRef: "device:C02XK4YTQ71W",
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error { return g.notify.Stamp(ctx, tx, &m) })
	if err != nil {
		g.log.Error("email preview", "tenant", res.Tenant.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, "the preview could not be made")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	_, _ = w.Write([]byte(notify.RenderHTML(m)))
}
