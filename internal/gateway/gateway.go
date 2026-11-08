// Package gateway is the front door. It resolves the tenant exactly once,
// mints the signed internal claim, enforces the role matrix and the plan's
// rate limit, and then hands off. Nothing behind it ever resolves a tenant
// again.
//
// The rule that matters: the hostname decides the tenant. A session or a
// device certificate must agree with it. Where they disagree the request is
// refused rather than resolved in anyone's favour, because a gateway that
// picks a winner between two tenant claims is a cross-tenant vulnerability
// with a preference.
package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"platform/internal/android"
	"platform/internal/authz"
	"platform/internal/command"
	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/enrol"
	"platform/internal/identity"
	"platform/internal/notify"
	"platform/internal/secrets"
	"platform/internal/session"
	"platform/internal/tenantclaim"
)

// Identity is what an identity provider tells us about a console user.
type Identity struct {
	Subject  string
	TenantID uuid.UUID
	Role     authz.Role
}

// IdentityVerifier turns a bearer token that is NOT one of our own sessions
// into an identity.
//
// It used to be the port for the identity provider itself. It is not any
// more: a person signing in goes through internal/identity, which speaks
// OpenID Connect to the tenant's own provider, and comes out the other side
// holding a session. What is left for this interface is the other kind of
// caller, a program with a long-lived API token, which is not built. Until
// it is, the only implementation is the development stand-in, and a
// deployment leaves it nil.
type IdentityVerifier interface {
	Verify(ctx context.Context, bearer string) (Identity, error)
}

var ErrNoIdentity = errors.New("gateway: no usable identity")

// Resolution is the answer the gateway reaches before any handler runs.
type Resolution struct {
	Tenant  directory.Tenant
	Subject string
	// Email is empty for a device certificate and for a bearer token: only
	// a signed-in person has one, and only a person can own a device.
	Email    string
	Role     authz.Role
	Source   string
	DeviceID uuid.UUID
	// FromCookie records that the credential was ambient. Cross-site request
	// protection is only needed when a browser will attach the credential by
	// itself; a caller who set an Authorization header cannot be made to do
	// so by another site.
	FromCookie bool
	// RenewCookie carries a freshly minted session token when the one that
	// arrived is old enough to be worth replacing. entry sets it on the
	// response; nothing else looks at it.
	RenewCookie string
}

type ctxKey int

const (
	ctxClaim ctxKey = iota
	ctxResolution
)

func ClaimFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxClaim).(string)
	return v
}

func ResolutionFrom(ctx context.Context) Resolution {
	v, _ := ctx.Value(ctxResolution).(Resolution)
	return v
}

type Config struct {
	Directory *directory.Directory
	Store     *data.Store
	Signer    *tenantclaim.Signer
	Identity  IdentityVerifier
	Pipeline  *command.Pipeline
	// Sessions signs the console's sign-in cookies. Without it the sign-in
	// routes answer "not available" rather than half working.
	Sessions *session.Signer
	// OIDC speaks to each tenant's own identity provider; SAML is the
	// second adapter for the tenants whose provider is not OpenID Connect.
	OIDC *identity.OIDC
	SAML *identity.SAML
	// Sealer opens the stored client secrets.
	Sealer secrets.Sealer
	// Enrol admits devices and issues their identity certificates. Without
	// it the enrolment routes answer "not configured" and, more to the
	// point, no device certificate verifies, because there is nothing that
	// could have issued one.
	Enrol *enrol.Service
	// Notify is the outbox. Without it the platform still works and tells
	// nobody, which is what it did before this sprint; the difference is
	// that it no longer claims otherwise.
	Notify *notify.Service
	// InsecureCookies drops the Secure attribute so a sign-in works over
	// plain HTTP. It is named to be uncomfortable because it should be: it
	// is for local development and for tests, and main.go warns when it is
	// on.
	InsecureCookies bool
	// AllowPrivateBuckets lets the export-to-bucket sender reach a
	// loopback or private address, for a test's fake bucket. Never set
	// in a deployment.
	AllowPrivateBuckets bool
	// CSRFKey signs the console's form tokens. A restart with a new key
	// invalidates open forms, which is why it is configuration rather than
	// something generated at startup.
	CSRFKey []byte
	// Signup, when set, serves self-service sign-up on its own hostname.
	// Nil means there is no sign-up: the routes are absent, not refused.
	Signup *SignupConfig
	// Mail carries one-off mail to a person: an enrolment invitation. The
	// email channel in production, the log in the demonstration, nil where
	// there is no mail server, in which case the console says so and shows
	// the link to be passed on by hand.
	Mail notify.Channel
	// AndroidCallbackBase, when set, is where Google sends the administrator
	// back after the enterprise sign-up, instead of the console's own
	// address. Google insists on https for that one URL; a console served
	// over plain http on a laptop sets this to an https listener of its own.
	AndroidCallbackBase string
	// TrustedProxies are the peers whose X-Forwarded-For is believed. Empty
	// means the header is ignored from everyone, which is right with no
	// proxy in front and wrong behind one (proxy.go).
	TrustedProxies []netip.Prefix
	// Android is the Android Management API adapter. NotConfigured, the
	// default, makes every Android page say what is missing.
	Android android.Provider
	// Region is the one this deployment serves (T11). A tenant whose row
	// names another region is refused here, whatever hostname it uses:
	// its data lives on the deployment of its own region. Empty means
	// the check is off, for a single-region installation.
	Region string
	Log    *slog.Logger
}

type Gateway struct {
	console *console.Console
	dir     *directory.Directory
	store   *data.Store
	signer  *tenantclaim.Signer
	idp     IdentityVerifier
	pipe    *command.Pipeline
	csrfKey []byte
	// csrfPrevious is the key before the last rotation (0044).
	csrfPrevious []byte
	csrfMu       sync.RWMutex
	limiter      *limiter
	log          *slog.Logger
	claimTTL     time.Duration

	sessions            *session.Signer
	oidc                *identity.OIDC
	saml                *identity.SAML
	sealer              secrets.Sealer
	enrol               *enrol.Service
	notify              *notify.Service
	insecureCookies     bool
	allowPrivateBuckets bool
	signup              *SignupConfig
	androidCallback     string
	mail                notify.Channel
	trustedProxies      []netip.Prefix
	android             android.Provider
	region              string
	// keys is the sealer as a keyring, for the one place that needs to
	// make a tenant key before a tenant exists: sign-up.
	keys *secrets.Keyring
	// waiters are the devices long-polling their queues (wake.go).
	waiters *waiters
	// revoked remembers per-person revocation stamps (signout.go).
	revoked *revocationCache
}

func New(cfg Config) *Gateway {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Android == nil {
		cfg.Android = android.NotConfigured{}
	}
	return (&Gateway{
		console: console.New(cfg.Store),
		dir:     cfg.Directory, store: cfg.Store, signer: cfg.Signer,
		idp: cfg.Identity, pipe: cfg.Pipeline, csrfKey: cfg.CSRFKey,
		limiter: newLimiter(cfg.Store, cfg.Log), log: cfg.Log, claimTTL: 2 * time.Minute,
		sessions: cfg.Sessions, oidc: cfg.OIDC, saml: cfg.SAML, sealer: cfg.Sealer, enrol: cfg.Enrol, notify: cfg.Notify,
		insecureCookies:     cfg.InsecureCookies,
		allowPrivateBuckets: cfg.AllowPrivateBuckets,
		signup:              cfg.Signup,
		androidCallback:     strings.TrimSuffix(cfg.AndroidCallbackBase, "/"),
		mail:                cfg.Mail,
		trustedProxies:      cfg.TrustedProxies,
		android:             cfg.Android,
		region:              cfg.Region,
	}).wire().wireKeys(cfg)
}

func (g *Gateway) wireKeys(cfg Config) *Gateway {
	if kr, ok := cfg.Sealer.(*secrets.Keyring); ok {
		g.keys = kr
	}
	return g
}

// Hooks the pipeline needs from the gateway's side of the seam.
func (g *Gateway) wire() *Gateway {
	g.waiters = newWaiters()
	g.revoked = newRevocationCache()
	if g.pipe != nil {
		g.pipe.OnWiped = g.retireIfOffboarding
		g.pipe.OnPushed = g.pushed
	}
	return g
}

// ---------------------------------------------------------------- resolution

// resolve decides the tenant. Order matters and is deliberate.
func (g *Gateway) resolve(r *http.Request) (Resolution, int, string) {
	host, err := g.dir.ResolveHost(r.Context(), r.Host)
	if errors.Is(err, directory.ErrUnknownHost) {
		// No tenant owns this hostname. There is nothing to serve and nothing
		// to say about which tenants exist.
		return Resolution{}, http.StatusNotFound, "unknown host"
	}
	if err != nil {
		return Resolution{}, http.StatusInternalServerError, "host lookup failed"
	}
	if !host.Active() && !(host.Exporting() && (r.URL.Path == "/api/export" || r.URL.Path == "/export" ||
		r.URL.Path == "/api/export/move" || r.URL.Path == "/export/move" || r.URL.Path == "/export/bucket" || strings.HasPrefix(r.URL.Path, "/signin"))) {
		return Resolution{}, http.StatusForbidden, "tenant is not active"
	}
	if g.region != "" && host.Region != "" && host.Region != g.region {
		// Not a tenant of this deployment. Its data is kept elsewhere,
		// and nothing of it is served from here, whatever DNS says.
		return Resolution{}, http.StatusForbidden, "this tenant's data is kept in another region"
	}

	// A device identity certificate is authoritative when present. It cannot
	// be forged by a header because it comes from the TLS handshake.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		if len(cert.Subject.OrganizationalUnit) == 0 {
			return Resolution{}, http.StatusForbidden, "device certificate carries no tenant"
		}
		certTenant, err := uuid.Parse(cert.Subject.OrganizationalUnit[0])
		if err != nil {
			return Resolution{}, http.StatusForbidden, "device certificate tenant is malformed"
		}
		if certTenant != host.ID {
			// A device presenting tenant A's certificate to tenant B's
			// hostname. Refuse; never choose.
			return Resolution{}, http.StatusForbidden, "device certificate and hostname name different tenants"
		}
		deviceID, err := uuid.Parse(cert.Subject.CommonName)
		if err != nil {
			return Resolution{}, http.StatusForbidden, "device certificate subject is malformed"
		}
		// Until the enrolment sprint this was the end of it: a certificate
		// of the right SHAPE was trusted. Shape is not provenance. The
		// check below is what makes a device certificate mean anything.
		if err := g.deviceCertTrusted(r.Context(), host, cert, deviceID); err != nil {
			g.log.Warn("device certificate refused", "tenant", host.Slug,
				"device", deviceID, "reason", err)
			return Resolution{}, http.StatusForbidden, "device certificate is not accepted"
		}
		return Resolution{
			Tenant: host, Subject: "device:" + deviceID.String(),
			// A device, not an administrator. This line used to say
			// ITAdmin, which handed every managed machine the right to
			// lock, wipe, re-policy and enumerate the whole fleet.
			Role: authz.Device, Source: "device_certificate", DeviceID: deviceID,
		}, 0, ""
	}

	fromCookie := false
	bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	// Network equipment that can only speak HTTP Basic (Cisco ISE's MDM
	// integration is one) sends the integration token as the password.
	// Only the token is read from it: a Basic header carrying anything
	// else is not credentials here, and the username is ignored.
	if _, pass, ok := r.BasicAuth(); ok {
		bearer = ""
		if strings.HasPrefix(pass, tokenPrefix) {
			bearer = pass
		}
	}
	if bearer == "" {
		// A browser sends a cookie, not an Authorization header. It is a
		// transport difference, not a second trust path: the same signed
		// session is verified the same way either way.
		if ck, err := r.Cookie(sessionCookie); err == nil {
			bearer = strings.TrimSpace(ck.Value)
			fromCookie = bearer != ""
		}
	}
	if bearer == "" {
		return Resolution{}, http.StatusUnauthorized, "no credentials"
	}

	var (
		id    Identity
		renew string
		email string
	)
	switch sess, serr := g.verifySession(bearer); {
	case serr == nil:
		role, perr := authz.Parse(sess.Role)
		if perr != nil {
			// The role matrix changed under a live session. Make them sign
			// in again rather than guessing what the old name meant.
			return Resolution{}, http.StatusUnauthorized, "your session is no longer valid"
		}
		// Tenant-wide revocation, checked against StartedAt, which renewal
		// never moves. A tenant that has just revoked cannot be outrun by a
		// session refreshing itself.
		if sess.StartedAt.Before(host.SessionsInvalidBefore) {
			return Resolution{}, http.StatusUnauthorized, "your session was ended by an administrator"
		}
		// One person's revocation, the same comparison against a stamp on
		// their own row. Read under a bootstrap claim and remembered for
		// a short while, so the cost is one lookup every half minute per
		// person rather than one per request.
		if sess.StartedAt.Before(g.subjectInvalidBefore(r.Context(), host, sess.Subject)) {
			return Resolution{}, http.StatusUnauthorized, "your session was ended by an administrator"
		}
		id = Identity{Subject: sess.Subject, TenantID: sess.TenantID, Role: role}
		email = sess.Email
		if sess.ShouldRenew() {
			if tok, _, rerr := g.sessions.Renew(sess); rerr == nil {
				renew = tok
			}
		}

	case fromCookie:
		// A cookie that does not verify is a dead or tampered session, not
		// an API token. Say so plainly so the browser is sent to sign in.
		return Resolution{}, http.StatusUnauthorized, "your session has ended"

	case strings.HasPrefix(bearer, tokenPrefix):
		// A tenant's network equipment. Looked up in the hostname's
		// tenant, under row-level security; revoked is the same as never
		// issued. This is the "revocation of their own" the note below
		// promised real API tokens would need.
		var ierr error
		id, ierr = g.resolveIntegration(r.Context(), host, bearer)
		if ierr != nil {
			return Resolution{}, http.StatusUnauthorized, "integration token not accepted"
		}

	default:
		// An Authorization header that is not one of our sessions. The only
		// thing left that could accept it is the bearer verifier.
		//
		// Note what does NOT apply on this path: tenant-wide session
		// revocation, because this is not a session. A session token sent
		// as a bearer header still goes through the case above and is still
		// revocable. When real API tokens exist they will need a revocation
		// of their own, and that belongs with them rather than bolted on
		// here.
		if g.idp == nil {
			return Resolution{}, http.StatusUnauthorized, "identity not accepted"
		}
		var verr error
		id, verr = g.idp.Verify(r.Context(), bearer)
		if verr != nil {
			return Resolution{}, http.StatusUnauthorized, "identity not accepted"
		}
	}

	if id.TenantID != host.ID {
		// A valid session for tenant A, used against tenant B's hostname.
		return Resolution{}, http.StatusForbidden, "session and hostname name different tenants"
	}
	if _, err := authz.Parse(string(id.Role)); err != nil {
		return Resolution{}, http.StatusForbidden, "unknown role"
	}

	return Resolution{
		Tenant: host, Subject: id.Subject, Email: email, Role: id.Role,
		Source: "session", FromCookie: fromCookie, RenewCookie: renew,
	}, 0, ""
}

// verifySession is split out so the one nil check lives in one place. A
// deployment without a session signer has no console sign-in, which is a
// configuration to refuse rather than to work around.
func (g *Gateway) verifySession(token string) (session.Session, error) {
	if g.sessions == nil {
		return session.Session{}, session.ErrInvalid
	}
	return g.sessions.Verify(token)
}

// ---------------------------------------------------------------- middleware

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()

	// The console. Same front door, same claim, same matrix. It renders HTML
	// where the API returns JSON, and that is the only difference.
	if g.console != nil {
		mux.Handle("GET /{$}", http.HandlerFunc(g.home))
		mux.Handle("GET /devices", g.page(authz.ViewDevices, g.console.Devices))
		mux.Handle("GET /devices/{id}", g.page(authz.ViewDevices, g.console.Device))
		mux.Handle("GET /audit", g.page(authz.ViewAudit, g.console.Audit))
		mux.Handle("GET /reports", g.page(authz.ViewDevices, g.consoleReports))
		mux.Handle("GET /apps", g.page(authz.ViewDevices, g.consoleApps))
		mux.Handle("GET /people", g.page(authz.ViewDevices, g.consolePeople))
		// The tenant's own accounts (0044), and a person's own page.
		mux.Handle("GET /users", g.page(authz.ManageAccess, g.consoleUsers))
		mux.Handle("POST /users/invite", g.formPost(authz.ManageAccess, g.consoleUserInvite))
		mux.Handle("POST /users/mfa-policy", g.formPost(authz.ManageAccess, g.consoleUserMFAPolicy))
		mux.Handle("POST /users/{id}/{action}", g.formPost(authz.ManageAccess, g.consoleUserAct))
		mux.Handle("GET /account", g.page(authz.ViewOwnDevices, g.consoleAccount))
		mux.Handle("POST /account/password", g.formPost(authz.ViewOwnDevices, g.consoleAccountPassword))
		mux.Handle("GET /people/{id}", g.page(authz.ViewDevices, g.consolePerson))
		mux.Handle("POST /devices/{id}/recovery-key/reveal", g.formPost(authz.RetrieveKey, g.consoleRevealKey))
		mux.Handle("GET /reports/compliance.pdf", g.guard(authz.ViewDevices, g.reportPDF))
		mux.Handle("GET /reports/compliance.csv", g.guard(authz.ViewDevices, g.reportCSV))
		mux.Handle("GET /approvals", g.page(authz.ApproveWipe, g.console.Approvals))
		mux.Handle("POST /devices/{id}/lock", g.formPost(authz.LockDevice, g.consoleLock))
		mux.Handle("POST /devices/{id}/lost-mode", g.formPost(authz.LockDevice, g.consoleSimple(command.LostMode)))
		mux.Handle("POST /devices/{id}/lost-mode/end", g.formPost(authz.LockDevice, g.consoleSimple(command.LostModeEnd)))
		mux.Handle("POST /devices/{id}/wipe", g.formPost(authz.RequestWipe, g.consoleWipe))
		mux.Handle("POST /commands/{id}/approve", g.formPost(authz.ApproveWipe, g.consoleDecide(true)))
		mux.Handle("POST /commands/{id}/refuse", g.formPost(authz.ApproveWipe, g.consoleDecide(false)))
		mux.Handle("GET /enrolments", g.page(authz.ViewDevices, g.console.Enrolments))
		mux.Handle("POST /enrolments", g.formPost(authz.EnrolDevice, g.consoleCreateEnrolment))
		mux.Handle("POST /enrolments/{id}/revoke", g.formPost(authz.EnrolDevice, g.consoleRevokeEnrolment))
		mux.Handle("GET /policies", g.page(authz.ViewDevices, g.console.Policies))
		mux.Handle("POST /policies", g.formPost(authz.ChangePolicy, g.consoleSavePolicy))
		mux.Handle("POST /policies/{name}/retire", g.formPost(authz.ChangePolicy, g.consoleRetirePolicy))
		mux.Handle("POST /policies/{name}/rollback", g.formPost(authz.ChangePolicy, g.consoleRollbackPolicy))
		mux.Handle("POST /policies/{name}/promote", g.formPost(authz.ChangePolicy, g.consoleStage(true)))
		mux.Handle("POST /policies/{name}/halt", g.formPost(authz.ChangePolicy, g.consoleStage(false)))
		mux.Handle("POST /devices/{id}/tags", g.formPost(authz.ChangePolicy, g.consoleSetTags))
		mux.Handle("POST /devices/{id}/offboard", g.formPost(authz.RequestWipe, g.consoleOffboardDevice))
		mux.Handle("POST /people/offboard", g.formPost(authz.OffboardEmployee, g.consoleOffboardPerson))

		// The employee surface. ViewOwnDevices is held by every tenant
		// role, so an administrator sees their own laptop here too; what
		// scopes the page is the claim, not the route.
		mux.Handle("GET /me", g.page(authz.ViewOwnDevices, g.console.Me))
		mux.Handle("POST /me/devices/{id}/lost", g.formPost(authz.ViewOwnDevices, g.consoleReportLost))
		// Self-service enrolment (0045): one link for everybody, a code for
		// their own phone. The setting is an administrator's; the page and
		// the code are for anyone who signs in.
		mux.Handle("GET /enrol", g.page(authz.EnrolOwn, g.consoleSelfEnrol))
		mux.Handle("POST /enrol/start", g.formPost(authz.EnrolOwn, g.consoleSelfEnrolStart))
		mux.Handle("POST /android/self-enrol", g.formPost(authz.EnrolDevice, g.consoleSelfEnrolMode))
		// Standing a lost report down is the same role set that would act
		// on it. Reusing device.lock rather than adding an action: the
		// people who may lock a device in an emergency are the people who
		// may say the emergency is over.
		mux.Handle("POST /devices/{id}/found", g.formPost(authz.LockDevice, g.consoleFoundDevice))
		// Letting a quarantined device back in is the same role set, for
		// the same reason.
		mux.Handle("POST /devices/{id}/release", g.formPost(authz.LockDevice, g.consoleReleaseDevice))

		// Where notifications go. Changing it is policy.change: deciding
		// which channel hears about a wipe is the same kind of decision as
		// deciding what a device must do.
		// Setup. The checklist is for anyone who runs the console; the
		// branding form is policy.change like the rest of the settings;
		// deciding who gets in is access.manage, held by Super Admin alone.
		mux.Handle("GET /setup", g.page(authz.ViewDevices, g.consoleSetup))
		mux.Handle("GET /branding", g.page(authz.ChangePolicy, g.consoleBranding))
		mux.Handle("GET /branding/email", g.guard(authz.ChangePolicy, g.brandingEmailPreview))
		mux.Handle("POST /branding", g.formPost(authz.ChangePolicy, g.consoleSaveBranding))
		mux.Handle("POST /branding/image", g.formPost(authz.ChangePolicy, g.consoleUploadImage))
		mux.Handle("GET /identity", g.page(authz.ManageAccess, g.consoleIdentity))
		mux.Handle("POST /identity", g.formPost(authz.ManageAccess, g.consoleSaveIdentity))
		mux.Handle("POST /identity/roles", g.formPost(authz.ManageAccess, g.consoleAddRole))
		mux.Handle("POST /identity/roles/remove", g.formPost(authz.ManageAccess, g.consoleRemoveRole))
		mux.Handle("POST /identity/seats/release", g.formPost(authz.ManageAccess, g.consoleReleaseSeat))
		mux.Handle("POST /identity/seats/signout", g.formPost(authz.ManageAccess, g.consoleSignOutPerson))
		mux.Handle("POST /identity/tokens", g.formPost(authz.ManageAccess, g.consoleCreateToken))
		mux.Handle("POST /identity/tokens/{id}/revoke", g.formPost(authz.ManageAccess, g.consoleRevokeToken))
		mux.Handle("POST /identity/keys/rotate", g.formPost(authz.ManageAccess, g.consoleRotateKey))
		// Android Enterprise. Seeing the page and syncing is for anyone
		// who may admit devices; binding the tenant to a Google
		// enterprise, and cutting it loose, is deciding who gets in.
		mux.Handle("GET /android", g.page(authz.EnrolDevice, g.consoleAndroid))
		mux.Handle("GET /android/callback", g.page(authz.ManageAccess, g.consoleAndroidCallback))
		mux.Handle("POST /android/bind", g.formPost(authz.ManageAccess, g.consoleAndroidBind))
		mux.Handle("POST /android/unbind", g.formPost(authz.ManageAccess, g.consoleAndroidUnbind))
		mux.Handle("POST /android/tokens", g.formPost(authz.EnrolDevice, g.consoleAndroidToken))
		mux.Handle("POST /android/sync", g.formPost(authz.EnrolDevice, g.consoleAndroidSync))

		mux.Handle("GET /notifications", g.page(authz.ChangePolicy, g.consoleNotifications))
		mux.Handle("POST /notifications", g.formPost(authz.ChangePolicy, g.consoleSetTarget))
		mux.Handle("POST /notifications/{topic}/clear", g.formPost(authz.ChangePolicy, g.consoleClearTarget))
		mux.Handle("POST /sending-domains", g.formPost(authz.ChangePolicy, g.consoleRegisterDomain))
		mux.Handle("POST /sending-domains/{domain}/verify",
			g.formPost(authz.ChangePolicy, g.consoleVerifyDomain))
		mux.Handle("POST /sending-domains/{domain}/remove",
			g.formPost(authz.ChangePolicy, g.consoleRemoveDomain))
	}

	mux.Handle("GET /api/devices", g.guard(authz.ViewDevices, g.listDevices))
	mux.Handle("GET /api/me/devices", g.guard(authz.ViewOwnDevices, g.myDevices))
	mux.Handle("GET /api/devices/{id}", g.guard(authz.ViewDevices, g.getDevice))
	// Over time (0041): a device's verdict changes, the fleet's days.
	mux.Handle("GET /api/devices/{id}/compliance/history", g.guard(authz.ViewDevices, g.deviceHistory))
	mux.Handle("GET /api/compliance/trend", g.guard(authz.ViewDevices, g.complianceTrend))
	mux.Handle("GET /api/audit", g.guard(authz.ViewAudit, g.listAudit))
	mux.Handle("GET /api/reports/compliance", g.guard(authz.ViewDevices, g.apiReport))
	mux.Handle("POST /api/siem/export", g.guard(authz.ChangePolicy, g.apiSIEMExport))
	// T10: everything, as a zip, for the Super Admin. Also answered while
	// the tenant is marked exporting, when nothing else is.
	mux.Handle("GET /api/export", g.guard(authz.ManageAccess, g.apiExport))
	// T11: the move bundle. POST, because the transport key is in the
	// body and a key does not belong in a URL or a browser's history.
	mux.Handle("POST /api/export/move", g.guard(authz.ManageAccess, g.apiMoveExport))
	mux.Handle("POST /api/keys/rotate", g.guard(authz.ManageAccess, g.apiRotateKey))
	mux.Handle("GET /export", g.guard(authz.ManageAccess, g.apiExport))
	mux.Handle("POST /export/bucket", g.formPost(authz.ManageAccess, g.consoleExportBucket))
	mux.Handle("POST /export/move", g.formPost(authz.ManageAccess, func(w http.ResponseWriter, r *http.Request, res Resolution) {
		g.apiMoveExport(w, r)
	}))
	mux.Handle("GET /api/siem/status", g.guard(authz.ViewAudit, g.apiSIEMStatus))

	// The command pipeline, reachable at last.
	mux.Handle("POST /api/devices/{id}/lock", g.guard(authz.LockDevice, g.lockDeviceCmd))
	mux.Handle("POST /api/devices/{id}/lost-mode", g.guard(authz.LockDevice, g.lostModeCmd))
	mux.Handle("POST /api/devices/{id}/lost-mode/end", g.guard(authz.LockDevice, g.lostModeEndCmd))
	mux.Handle("POST /api/devices/{id}/release", g.guard(authz.LockDevice, g.releaseDevice))
	// The network's one question, and its bulk form.
	mux.Handle("GET /api/network/access/{serial}", g.guard(authz.NetworkRead, g.networkAccess))
	mux.Handle("GET /api/network/denied", g.guard(authz.NetworkRead, g.networkDenied))
	// By the address the device authenticated to the network with, which
	// is what a NAC has. And the same answer in the shape Cisco ISE asks
	// for it (ise.go).
	mux.Handle("GET /api/network/access/mac/{mac}", g.guard(authz.NetworkRead, g.networkAccessByMAC))
	mux.Handle("GET /ciscoise/mdminfo", g.guard(authz.NetworkRead, g.iseInfo))
	mux.Handle("GET /ciscoise/mdmapi", g.guard(authz.NetworkRead, g.iseQuery))
	mux.Handle("POST /api/android/sync", g.guard(authz.EnrolDevice, g.apiAndroidSync))
	mux.Handle("POST /api/devices/{id}/wipe", g.guard(authz.RequestWipe, g.wipeDevice))
	mux.Handle("GET /api/commands", g.guard(authz.ViewDevices, g.listCommands))
	mux.Handle("POST /api/commands/{id}/approve", g.guard(authz.ApproveWipe, g.decideCommand(true)))
	mux.Handle("POST /api/commands/{id}/refuse", g.guard(authz.ApproveWipe, g.decideCommand(false)))
	// The three routes a managed device reaches. They are guarded by
	// ViewOwnDevices, which every tenant role also holds, so the guard is
	// not what keeps a person out: each handler refuses anything that is
	// not a device certificate, and refuses a device that is not the one
	// named. The role matrix stops a device reaching anything else.
	mux.Handle("POST /api/commands/{id}/ack", g.guard(authz.ViewOwnDevices, g.acknowledgeCommand))
	mux.Handle("GET /api/my/commands", g.guard(authz.ViewOwnDevices, g.myCommands))
	mux.Handle("GET /api/my/signing-keys", g.guard(authz.ViewOwnDevices, g.mySigningKeys))
	mux.Handle("POST /api/signing-keys/rotate", g.guard(authz.ManageAccess, g.apiRotateSigningKey))
	mux.Handle("POST /api/my/certificate", g.guard(authz.ViewOwnDevices, g.renewCertificate))

	// Enrolment. Admitting a device is its own action in the matrix;
	// reading the list is not, because anyone who may see devices may see
	// which ones are on their way.
	mux.Handle("GET /api/enrolments", g.guard(authz.ViewDevices, g.listEnrolments))
	mux.Handle("POST /api/enrolments", g.guard(authz.EnrolDevice, g.createEnrolment))
	mux.Handle("POST /api/enrolments/{id}/revoke", g.guard(authz.EnrolDevice, g.revokeEnrolment))

	// Policy. Reading what is required is part of seeing a device; changing
	// it is policy.change, which is the action that has existed in the
	// matrix since the first sprint and has until now had nothing to guard.
	mux.Handle("GET /api/setup", g.guard(authz.ViewDevices, g.apiSetup))
	mux.Handle("GET /api/notifications", g.guard(authz.ChangePolicy, g.listNotifications))
	mux.Handle("POST /api/notifications", g.guard(authz.ChangePolicy, g.setNotificationTarget))
	mux.Handle("GET /api/sending-domains", g.guard(authz.ChangePolicy, g.listSendingDomains))
	mux.Handle("POST /api/sending-domains", g.guard(authz.ChangePolicy, g.registerSendingDomain))
	mux.Handle("POST /api/sending-domains/{domain}/verify",
		g.guard(authz.ChangePolicy, g.verifySendingDomain))
	mux.Handle("POST /api/sending-domains/{domain}/remove",
		g.guard(authz.ChangePolicy, g.removeSendingDomain))
	mux.Handle("GET /api/policies", g.guard(authz.ViewDevices, g.listPolicies))
	mux.Handle("POST /api/policies", g.guard(authz.ChangePolicy, g.savePolicy))
	mux.Handle("POST /api/policies/{name}/retire", g.guard(authz.ChangePolicy, g.retirePolicy))
	mux.Handle("POST /api/policies/{name}/rollback", g.guard(authz.ChangePolicy, g.rollbackPolicy))
	mux.Handle("POST /api/policies/{name}/promote", g.guard(authz.ChangePolicy, g.stageChange(true)))
	mux.Handle("POST /api/policies/{name}/halt", g.guard(authz.ChangePolicy, g.stageChange(false)))
	mux.Handle("POST /api/devices/{id}/tags", g.guard(authz.ChangePolicy, g.setTags))
	mux.Handle("POST /api/devices/{id}/offboard", g.guard(authz.RequestWipe, g.apiOffboardDevice))
	mux.Handle("POST /api/people/offboard", g.guard(authz.OffboardEmployee, g.apiOffboardPerson))
	// The HR system's one sentence, through a token scoped to say it.
	mux.Handle("POST /api/hr/leavers", g.guard(authz.OffboardEmployee, g.apiOffboardPerson))
	mux.Handle("GET /api/policies/templates", g.guard(authz.ViewDevices, g.listTemplates))
	mux.Handle("GET /api/devices/{id}/policy", g.guard(authz.ViewDevices, g.effectivePolicy))
	mux.Handle("GET /api/devices/{id}/compliance", g.guard(authz.ViewDevices, g.getCompliance))
	mux.Handle("GET /api/devices/{id}/apps", g.guard(authz.ViewDevices, g.deviceApps))
	mux.Handle("GET /api/apps", g.guard(authz.ViewDevices, g.findApp))
	// F11: the device hands its key up; the roles that hold key.retrieve
	// ask for it back, with a reason, on the record.
	mux.Handle("POST /api/my/recovery-key", g.guard(authz.ViewOwnDevices, g.escrowKey))
	mux.Handle("POST /api/devices/{id}/recovery-key/reveal", g.guard(authz.RetrieveKey, g.apiRevealKey))
	// The device reporting on itself. Guarded by ViewDevices only so the
	// route is registered with an action like every other; the real check is
	// in the handler, which refuses anything that is not the named device on
	// its own certificate.
	mux.Handle("POST /api/devices/{id}/report", g.guard(authz.ViewOwnDevices, g.reportDevice))

	// Everything above is behind entry and needs a credential. The three
	// routes below exist to get one, so they sit outside it. That makes them
	// the whole unauthenticated surface of this platform, and keeping that
	// list short and visible in one place is the point of writing it this
	// way rather than special-casing paths inside entry.
	outer := http.NewServeMux()
	outer.Handle("GET /signin", http.HandlerFunc(g.signIn))
	outer.Handle("GET /signin/callback", http.HandlerFunc(g.callback))
	// The tenant with no identity provider (0044): the password, the
	// second factor, an invitation, and a forgotten password. Each is
	// refused for a tenant that signs in some other way.
	outer.Handle("POST /signin/local", http.HandlerFunc(g.localSignIn))
	outer.Handle("GET /signin/local/mfa", http.HandlerFunc(g.localMFA))
	outer.Handle("POST /signin/local/mfa", http.HandlerFunc(g.localMFA))
	outer.Handle("GET /signin/local/enrol", http.HandlerFunc(g.localEnrol))
	outer.Handle("POST /signin/local/enrol", http.HandlerFunc(g.localEnrol))
	outer.Handle("GET /signin/local/accept/{token}", g.linkPage("invite"))
	outer.Handle("POST /signin/local/accept/{token}", g.setPassword("invite"))
	outer.Handle("GET /signin/local/reset/{token}", g.linkPage("reset"))
	outer.Handle("POST /signin/local/reset/{token}", g.setPassword("reset"))
	outer.Handle("GET /signin/local/forgot", http.HandlerFunc(g.localForgot))
	outer.Handle("POST /signin/local/forgot", http.HandlerFunc(g.localForgot))
	// The SAML half: the provider posts the assertion back (so this one
	// is a POST from another site, which is why the flow cookie it reads
	// is set the way it is), and the metadata is what the tenant's
	// administrator hands to the provider.
	outer.Handle("POST /signin/saml", http.HandlerFunc(g.samlCallback))
	outer.Handle("GET /saml/metadata", http.HandlerFunc(g.samlMetadata))
	outer.Handle("GET /signout/saml", http.HandlerFunc(g.samlLogout))
	outer.Handle("POST /signout", http.HandlerFunc(g.signOut))
	// The brand's images, per hostname, before anyone has signed in.
	outer.Handle("GET /brand/logo", g.brandImage("logo"))
	outer.Handle("GET /brand/favicon.ico", g.brandImage("favicon"))
	// A device redeeming its enrolment token has no session and no
	// certificate yet: the token in the body is its whole credential. That
	// is why this one is out here with the sign-in routes rather than
	// behind entry.
	outer.Handle("POST /api/enrol", http.HandlerFunc(g.redeemEnrolment))
	outer.Handle("/", g.entry(mux))

	// Sign-up lives on the one hostname that belongs to no tenant, and is
	// decided by hostname before anything else looks at the request. A
	// tenant's hostname never serves /signup and the sign-up hostname never
	// serves a tenant: the two surfaces share a process and nothing else.
	if g.signup == nil {
		return outer
	}
	signup := g.signupHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.signup.servesHost(r.Host) {
			signup.ServeHTTP(w, r)
			return
		}
		outer.ServeHTTP(w, r)
	})
}

// page is guard for console routes. A console route cannot be mounted without
// naming the action it needs, exactly as an API route cannot.
func (g *Gateway) page(action authz.Action,
	h func(http.ResponseWriter, *http.Request, console.Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := ResolutionFrom(r.Context())
		if !authz.Can(res.Role, action) {
			g.log.Warn("not permitted", "role", res.Role, "action", action,
				"tenant", res.Tenant.Slug)
			http.Error(w, "this role may not "+string(action), http.StatusForbidden)
			return
		}
		h(w, r, console.Session{
			Claim: ClaimFrom(r.Context()), Role: res.Role, Subject: res.Subject,
			CSRF: g.csrfToken(res),
		})
	})
}

// entry resolves the tenant, applies the plan's rate limit, mints the claim
// and puts both on the context. Every route sits behind it.
func (g *Gateway) entry(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.NewString()
		w.Header().Set("X-Request-Id", requestID)

		res, status, reason := g.resolve(r)
		if status != 0 {
			g.log.Warn("refused", "request_id", requestID, "host", r.Host,
				"path", r.URL.Path, "status", status, "reason", reason)
			// A browser with no usable session wants the sign-in page, not a
			// JSON body it will render as text. A program wants the JSON.
			// Only 401 redirects: a 403 is an answer, and bouncing someone
			// to sign in again when they are already signed in produces a
			// loop that looks like the product is broken.
			if status == http.StatusUnauthorized && r.Method == http.MethodGet && wantsHTML(r) {
				g.clearCookie(w, sessionCookie)
				next := ""
				if p := localPath(r.URL.RequestURI()); p != "" && p != "/" {
					next = "?next=" + url.QueryEscape(p)
				}
				http.Redirect(w, r, "/signin"+next, http.StatusFound)
				return
			}
			writeError(w, status, reason)
			return
		}

		if res.RenewCookie != "" {
			g.setCookie(w, sessionCookie, res.RenewCookie, int(session.Lifetime/time.Second))
		}

		if !g.limiter.allow(res.Tenant.ID, res.Tenant.APIRatePerMin) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate limit for this plan exceeded")
			return
		}

		token, err := g.signer.Mint(tenantclaim.Claim{
			TenantID: res.Tenant.ID, Subject: res.Subject, Email: res.Email,
			Role: string(res.Role), RequestID: requestID,
		}, g.claimTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not mint claim")
			return
		}

		ctx := context.WithValue(r.Context(), ctxClaim, token)
		ctx = context.WithValue(ctx, ctxResolution, res)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// guard is the only way a route is registered, so a route cannot be added
// without naming the action it requires.
func (g *Gateway) guard(action authz.Action, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := ResolutionFrom(r.Context())
		// Only a credential the browser attaches by itself needs this. A
		// caller who set an Authorization header cannot be made to by
		// another site.
		if r.Method != http.MethodGet && res.FromCookie && !g.csrfOK(r, res) {
			writeError(w, http.StatusForbidden, "missing or wrong form token")
			return
		}
		if !authz.Can(res.Role, action) {
			g.log.Warn("not permitted", "role", res.Role, "action", action,
				"tenant", res.Tenant.Slug)
			writeError(w, http.StatusForbidden, "this role may not "+string(action))
			return
		}
		h(w, r)
	})
}

// ---------------------------------------------------------------- limiter

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu sync.Mutex
	b  map[string]*bucket
	// store holds the shared buckets (0034). When it cannot be reached the
	// in-memory bucket stands in, per instance, and says so in the log:
	// a database blip should slow a tenant down a little, not shut the
	// door on every tenant.
	store *data.Store
	log   *slog.Logger
}

func newLimiter(store *data.Store, log *slog.Logger) *limiter {
	if log == nil {
		log = slog.Default()
	}
	return &limiter{b: map[string]*bucket{}, store: store, log: log}
}

// allow is a token bucket per tenant, refilled at the plan's rate.
//
// The bucket is a row in the database, shared by every instance, so a
// plan's limit is the plan's limit however many gateways stand behind the
// balancer. The in-memory bucket below is the fallback for a store that
// cannot be reached.
func (l *limiter) allow(tenant uuid.UUID, perMinute int) bool {
	return l.allowKey("tenant:"+tenant.String(), perMinute)
}

// allowKey is the same bucket for anything with a name. The sign-up page
// has no tenant to key on, so it keys on the caller's address; the prefix
// keeps the two namespaces apart.
func (l *limiter) allowKey(key string, perMinute int) bool {
	if perMinute <= 0 {
		return true
	}
	if l.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ok, err := l.store.TakeToken(ctx, key, perMinute)
		cancel()
		if err == nil {
			return ok
		}
		l.log.Warn("shared rate limit unavailable; limiting per instance meanwhile", "err", err)
	}
	return l.allowLocal(key, perMinute)
}

func (l *limiter) allowLocal(key string, perMinute int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	bk, ok := l.b[key]
	if !ok {
		bk = &bucket{tokens: float64(perMinute), last: now}
		l.b[key] = bk
	}
	rate := float64(perMinute) / 60.0
	bk.tokens += now.Sub(bk.last).Seconds() * rate
	if bk.tokens > float64(perMinute) {
		bk.tokens = float64(perMinute)
	}
	bk.last = now

	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}
