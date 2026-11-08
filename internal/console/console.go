// Package console renders the tenant console.
//
// Server-rendered rather than a single-page application, and that is a
// deliberate departure from the technical specification's "TypeScript and
// React" line. The reason is T4: the design document's own rule is that the
// theme is "resolved per request from tenant_branding into CSS custom
// properties. No build step, no per-tenant bundle." Rendering on the server
// is the shortest path to that, and it removes the flash of the wrong brand
// that a client-resolved theme produces.
//
// The seam is the handlers, not the markup. If richer interaction is wanted
// later, these routes become JSON and a React application renders them,
// without any of the resolution, role or isolation work below changing.
package console

import (
	"context"
	"embed"
	"html/template"
	"net/http"
	"time"

	"github.com/google/uuid"

	"platform/internal/android"
	"platform/internal/authz"
	"platform/internal/branding"
	"platform/internal/command"
	"platform/internal/data"
	"platform/internal/enrol"
	"platform/internal/policy"
)

//go:embed templates/*.html
var files embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"pct": func(n, total int) int {
		if total == 0 {
			return 0
		}
		return n * 100 / total
	},
}).ParseFS(files, "templates/*.html"))

type Console struct {
	store *data.Store
}

func New(store *data.Store) *Console { return &Console{store: store} }

// Session is what the gateway already worked out. The console never resolves
// a tenant, never reads a header and never parses a token: by the time a
// handler here runs, all of that is settled and carried on the claim.
type Session struct {
	Claim   string
	Role    authz.Role
	Subject string
	// CSRF is the token every form on the page carries. The gateway mints it
	// from the session; the console only puts it in the markup.
	CSRF string
}

// navItem is only ever built from authz.Can, so a section a role may not use
// is absent rather than present and disabled. The design document is explicit
// about why: a disabled control still advertises a capability and invites a
// request for it.
type navItem struct {
	Label  string
	Href   string
	Active bool
}

type page struct {
	Brand       branding.Brand
	Nav         []navItem
	Subject     string
	Role        authz.Role
	CSRF        string
	Said        string
	Path        string
	Title       string
	Commands    []command.Command
	CanLock     bool
	CanWipe     bool
	Counts      data.StateCounts
	Devices     []data.Device
	Device      *data.Device
	AuditEvents []data.AuditEvent

	CanEnrol     bool
	CanSetPolicy bool
	Enrolments   []enrol.Enrolment
	Policies     []policy.Policy
	RuleKinds    []policy.Kind
	Templates    []policy.Template
	Template     *policy.Template
	// Compliance is the device page's verdict, and Requires is what that
	// device is being held to. Both are nil for a device that has never
	// reported, which the template says in words rather than showing an
	// empty table.
	Compliance *policy.Compliance
	Requires   []string

	Notify *Notifications

	// The setup checklist, the sign-in settings, and what the branding
	// form needs to say about its colour.
	Setup           *Setup
	Identity        *Identity
	CanManageAccess bool
	Contrast        float64
	// Signup is the one page rendered with no tenant and no session.
	Signup *SignupView
	// Android is the Android Enterprise page.
	Android *Android
	Reports *Reports
	// Apps search, and what a device has installed.
	AppQuery   string
	AppHolders []data.AppHolder
	Apps       []data.App
	// MACs are the device's hardware addresses, what the network's door
	// knows it by.
	MACs []string
	// Local sign-in (0044): the tenant keeps its own accounts.
	LocalMode bool
	Users     *Users
	Account   *Account
	Local     *LocalView
	// People (0040): the listing, one person's page, and the person a
	// device is assigned to.
	PeopleQuery   string
	People        []data.Person
	Person        *data.Person
	PersonDevices []data.Device
	Holder        *data.Person
	CanOffboard   bool
	// Over time (0041): the fleet's last days on the dashboard, drawn as
	// one line of the compliant share, and a device's verdict changes.
	Trend     []data.ComplianceSnapshot
	TrendLine *TrendLine
	History   []data.VerdictChange
	// Escrow status on the device page, and a revealed key on its own page.
	RecoveryKey    *data.RecoveryKeyStatus
	CanRetrieveKey bool
	KeyDeviceID    uuid.UUID
	KeyKind        string
	KeyValue       string
	// Mine is the employee surface: this person's own devices, each with
	// its verdict and what it is held to, read in one transaction so a
	// page cannot show one device's findings beside another's rules.
	Mine []MyDevice
	Now  time.Time
	// NewToken and NewLink are set on exactly one page: the one rendered
	// straight after an enrolment is created. The token is never stored,
	// so this is the only moment it can be shown, which is also why that
	// page does not redirect. A redirect would have to carry the token in
	// a URL, and a URL is the one place a credential must never be.
	NewToken string
	NewLink  string
}

// MyDevice is one device as its holder sees it.
type MyDevice struct {
	Device     data.Device
	Compliance *policy.Compliance
	Requires   []string
}

// NeedsAttention is what decides whether the page leads with a problem or
// with reassurance. Unknown counts: a device we have not heard from is not
// a device anyone should be told is fine.
func (m MyDevice) NeedsAttention() bool {
	return m.Compliance == nil || m.Compliance.State != policy.Compliant
}

func navFor(role authz.Role, active, subject string, localMode bool) []navItem {
	var out []navItem
	add := func(label, href string, allowed bool) {
		if allowed {
			out = append(out, navItem{Label: label, Href: href, Active: href == active})
		}
	}
	// First, and for everyone who holds it, which includes administrators:
	// an IT admin with a laptop of their own should see it here like anyone
	// else rather than hunting for it in the fleet list.
	add("Your devices", "/me", authz.Can(role, authz.ViewOwnDevices))
	add("Dashboard", "/", authz.Can(role, authz.ViewDevices))
	add("Setup", "/setup", authz.Can(role, authz.ViewDevices))
	add("Devices", "/devices", authz.Can(role, authz.ViewDevices))
	add("Enrolments", "/enrolments", authz.Can(role, authz.ViewDevices))
	add("Policies", "/policies", authz.Can(role, authz.ViewDevices))
	add("Notifications", "/notifications", authz.Can(role, authz.ChangePolicy))
	add("Android", "/android", authz.Can(role, authz.EnrolDevice))
	add("Branding", "/branding", authz.Can(role, authz.ChangePolicy))
	// Only a Super Admin sees this entry at all: the control it leads to
	// is absent for everybody else rather than present and refused.
	add("Sign-in", "/identity", authz.Can(role, authz.ManageAccess))
	// A tenant with no identity provider keeps its people here (0044): the
	// Super Admin manages them, and each person has their own password.
	add("Users", "/users", localMode && authz.Can(role, authz.ManageAccess))
	add("Approvals", "/approvals", authz.Can(role, authz.ApproveWipe))
	add("Reports", "/reports", authz.Can(role, authz.ViewDevices))
	add("Apps", "/apps", authz.Can(role, authz.ViewDevices))
	add("People", "/people", authz.Can(role, authz.ViewDevices))
	add("Audit log", "/audit", authz.Can(role, authz.ViewAudit))
	add("Account", "/account", localMode && data.IsLocalSubject(subject))
	return out
}

// render loads the brand and the page's own data in one tenant-scoped
// transaction, so a page cannot render with one tenant's brand and another's
// data even if something above went wrong.
func (c *Console) render(w http.ResponseWriter, r *http.Request, s Session,
	name, active, title string,
	load func(context.Context, *data.Tx, *page) error) {

	p := page{
		Subject: s.Subject, Role: s.Role, Title: title,
		CSRF: s.CSRF, Said: r.URL.Query().Get("said"), Path: r.URL.Path,
		CanLock:         authz.Can(s.Role, authz.LockDevice),
		CanWipe:         authz.Can(s.Role, authz.RequestWipe),
		CanEnrol:        authz.Can(s.Role, authz.EnrolDevice),
		CanSetPolicy:    authz.Can(s.Role, authz.ChangePolicy),
		CanManageAccess: authz.Can(s.Role, authz.ManageAccess),
		CanRetrieveKey:  authz.Can(s.Role, authz.RetrieveKey),
		Now:             time.Now().UTC(),
	}

	err := c.store.WithTenant(r.Context(), s.Claim, func(ctx context.Context, tx *data.Tx) error {
		b, err := branding.Load(ctx, tx)
		if err != nil {
			return err
		}
		p.Brand = b
		// Which sign-in the tenant uses decides two menu entries, so it is
		// read in the same transaction as everything else on the page.
		local, err := data.LocalModeOn(ctx, tx)
		if err != nil {
			return err
		}
		p.LocalMode = local
		if load == nil {
			return nil
		}
		return load(ctx, tx, &p)
	})
	if err != nil {
		http.Error(w, "could not render the page", http.StatusInternalServerError)
		return
	}
	p.Nav = navFor(s.Role, active, s.Subject, p.LocalMode)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, p); err != nil {
		http.Error(w, "could not render the page", http.StatusInternalServerError)
	}
}

func (c *Console) Dashboard(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "dashboard.html", "/", "Dashboard",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			counts, err := data.CountByState(ctx, tx)
			if err != nil {
				return err
			}
			p.Counts = counts
			trend, err := data.ComplianceTrend(ctx, tx, 30)
			if err != nil {
				return err
			}
			p.Trend = trend
			p.TrendLine = DrawTrend(trend, 600, 120)
			return nil
		})
}

func (c *Console) Devices(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "devices.html", "/devices", "Devices",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			ds, err := data.ListDevices(ctx, tx)
			if err != nil {
				return err
			}
			p.Devices = ds
			return nil
		})
}

func (c *Console) Device(w http.ResponseWriter, r *http.Request, s Session) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c.render(w, r, s, "device.html", "/devices", "Device",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			d, err := data.GetDevice(ctx, tx, id)
			if err != nil {
				// Another tenant's device is indistinguishable from one that
				// does not exist, which is the correct amount to know.
				return nil
			}
			p.Device = &d
			p.Title = d.Name
			cs, cerr := command.List(ctx, tx, command.Filter{DeviceID: id, Limit: 20})
			if cerr != nil {
				return cerr
			}
			p.Commands = cs

			// What this device is held to, and how it did. Both read in
			// the same transaction as the device itself, so the page
			// cannot show one device's verdict beside another's rules.
			rules, applied, perr := policy.EffectiveForDevice(ctx, tx, d.ID, d.OSFamily, d.Ownership, d.Tags)
			if perr != nil {
				return perr
			}
			p.Requires = rules.Describe()
			_ = applied
			c, found, cerr := policy.Of(ctx, tx, id, time.Now().UTC())
			if cerr != nil {
				return cerr
			}
			if found {
				p.Compliance = &c
			}
			apps, aerr := data.AppsOf(ctx, tx, id)
			if aerr != nil {
				return aerr
			}
			p.Apps = apps
			history, herr := data.VerdictHistory(ctx, tx, id, 20)
			if herr != nil {
				return herr
			}
			p.History = history
			if d.PersonID != nil {
				if h, herr := data.GetPerson(ctx, tx, *d.PersonID); herr == nil {
					p.Holder = &h
				}
			}
			if macs, merr := data.MACsOf(ctx, tx, id); merr != nil {
				return merr
			} else if len(macs) > 0 {
				p.MACs = macs
			}
			if rk, ok, kerr := data.RecoveryKeyStatusOf(ctx, tx, id); kerr != nil {
				return kerr
			} else if ok {
				p.RecoveryKey = &rk
			}
			return nil
		})
}

// Approvals is the queue of things waiting on a person. Only roles that may
// approve can reach it, so it is absent from everyone else's navigation.
func (c *Console) Approvals(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "approvals.html", "/approvals", "Approvals",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			cs, err := command.List(ctx, tx, command.Filter{OnlyHeld: true, Limit: 50})
			if err != nil {
				return err
			}
			p.Commands = cs
			return nil
		})
}

func (c *Console) Audit(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "audit.html", "/audit", "Audit log",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			ev, err := data.RecentAudit(ctx, tx, 100)
			if err != nil {
				return err
			}
			p.AuditEvents = ev
			return nil
		})
}

// Problem renders a page for the things that go wrong before anyone is
// signed in: a tenant whose identity provider is not set up, a provider that
// refused, a person whose groups map to no role.
//
// It takes a claim like every other page, because it still renders a
// tenant's own branding and that still has to come through row-level
// security. The claim the gateway mints for it carries no identity: the
// subject is anonymous and the role is the lowest there is. If branding
// cannot be read at all, the page degrades to plain text rather than
// failing, since an error page that errors tells the person nothing.
func (c *Console) Problem(w http.ResponseWriter, r *http.Request, claim string,
	status int, title, detail string) {

	p := page{Title: title, Said: detail, Brand: branding.Default()}
	_ = c.store.WithTenant(r.Context(), claim, func(ctx context.Context, tx *data.Tx) error {
		b, err := branding.Load(ctx, tx)
		if err != nil {
			return err
		}
		p.Brand = b
		return nil
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "problem.html", p); err != nil {
		http.Error(w, title+"\n\n"+detail, status)
	}
}

// Enrolments is the list of devices on their way in.
//
// Everyone who may see devices may see this: knowing a laptop has been
// invited is not a privilege beyond knowing the laptop exists. Creating one
// is, and the form is absent rather than disabled for a role that may not,
// which is the design rule for every control in this console.
func (c *Console) Enrolments(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "enrolments.html", "/enrolments", "Enrolments",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			es, err := enrol.List(ctx, tx, 100)
			if err != nil {
				return err
			}
			p.Enrolments = es
			return nil
		})
}

// EnrolmentCreated is the one page that shows a token, once.
func (c *Console) EnrolmentCreated(w http.ResponseWriter, r *http.Request, s Session,
	token, link string) {

	c.render(w, r, s, "enrolment_created.html", "/enrolments", "Enrolment created",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			p.NewToken = token
			p.NewLink = link
			es, err := enrol.List(ctx, tx, 100)
			if err != nil {
				return err
			}
			p.Enrolments = es
			return nil
		})
}

// Policies lists what the tenant requires, live versions and superseded
// ones together. The old versions are the answer to "what did we require in
// March", so they are on the page rather than in a backup.
func (c *Console) Policies(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "policies.html", "/policies", "Policies",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			ps, err := policy.List(ctx, tx)
			if err != nil {
				return err
			}
			p.Policies = ps
			p.RuleKinds = policy.Kinds()
			p.Templates = policy.Templates()
			// A template chosen from the list fills the form; nothing is
			// saved until the person presses save under their own name.
			if t, ok := policy.TemplateByKey(r.URL.Query().Get("template")); ok {
				p.Template = &t
			}
			return nil
		})
}

// Me is the employee surface.
//
// It has existed as a hole since the console sprint: the employee role holds
// devices.view_own and there was nothing to view, because nothing linked a
// person to a device. Everything on this page is scoped by data.MyDevices,
// which takes the person from the claim rather than from the request, so
// there is no identifier on this route that could be changed to someone
// else's.
func (c *Console) Me(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "me.html", "/me", "Your devices",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			ds, err := data.MyDevices(ctx, tx)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			for _, d := range ds {
				m := MyDevice{Device: d}
				rules, _, rerr := policy.EffectiveForDevice(ctx, tx, d.ID, d.OSFamily, d.Ownership, d.Tags)
				if rerr != nil {
					return rerr
				}
				m.Requires = rules.Describe()
				cmp, found, cerr := policy.Of(ctx, tx, d.ID, now)
				if cerr != nil {
					return cerr
				}
				if found {
					m.Compliance = &cmp
				}
				p.Mine = append(p.Mine, m)
			}
			return nil
		})
}

// ------------------------------------------------------- notifications
//
// The console renders these; it does not hold a notify.Service. The gateway
// passes a loader, for the same reason every other page takes its data from
// a transaction the gateway opened: this package renders and does not decide
// what anyone may read.

type NotificationTarget struct {
	Topic     string
	Means     string
	Kind      string
	Endpoint  string
	CreatedBy string
}

type NotificationTopic struct {
	Topic      string
	Means      string
	Configured bool
}

type NotificationRecord struct {
	Topic     string
	Subject   string
	State     string
	Attempts  int
	LastError string
	CreatedAt time.Time
	Delivered bool
}

type SendingDomain struct {
	Domain      string
	From        string
	Verified    bool
	RecordName  string
	RecordValue []string
	LastError   string
}

type Notifications struct {
	Targets  []NotificationTarget
	Topics   []NotificationTopic
	Recent   []NotificationRecord
	Domains  []SendingDomain
	WhyNoSPF string
}

func (c *Console) NotificationsPage(w http.ResponseWriter, r *http.Request, s Session,
	load func(context.Context, *data.Tx, *Notifications) error) {

	c.render(w, r, s, "notifications.html", "/notifications", "Notifications",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			var n Notifications
			if err := load(ctx, tx, &n); err != nil {
				return err
			}
			p.Notify = &n
			return nil
		})
}

// ------------------------------------------------------------- setup

type SetupStep struct {
	Key, Title, Detail, Href string
	// Blocked says why a step cannot be done yet. A step that cannot be
	// completed and does not say why is a step somebody opens a ticket
	// about.
	Blocked  string
	Done     bool
	Optional bool
}

type Setup struct {
	Steps         []SetupStep
	Ready         bool
	Host          string
	CreatedAt     time.Time
	FirstDeviceAt *time.Time
	// TimeToFirst is the PRD's first success metric, in words, or empty
	// when it cannot honestly be stated.
	TimeToFirst string
}

func (c *Console) SetupPage(w http.ResponseWriter, r *http.Request, s Session,
	load func(context.Context, *data.Tx, *Setup) error) {

	c.render(w, r, s, "setup.html", "/setup", "Setup",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			var st Setup
			if err := load(ctx, tx, &st); err != nil {
				return err
			}
			p.Setup = &st
			return nil
		})
}

// ------------------------------------------------------------- identity

type RoleMapping struct {
	ClaimValue string
	Role       string
}

// Seat is one administrator who has signed in within the seat window.
type Seat struct {
	Subject, Email, Name, Role string
	LastSeenAt                 time.Time
}

type Identity struct {
	Configured  bool
	Issuer      string
	ClientID    string
	RoleClaim   string
	RedirectURL string
	// Protocol is "oidc" or "saml". Under SAML, ClientID is our entity
	// id (also the metadata address) and RedirectURL is the assertion
	// consumer service; the certificate is described, never shown.
	Protocol   string
	SAMLSSOURL string
	// Single logout (0043): the provider's logout URL, and whether we
	// hold a signing key of our own yet (made on first need).
	SAMLSLOURL     string
	HasSigningKey  bool
	HasCertificate bool
	CertSubject    string
	CertNotAfter   *time.Time
	// HasSecret says one is held without ever saying what it is.
	HasSecret   bool
	Roles       []RoleMapping
	RoleChoices []string
	// Seats: who holds one, how many there are.
	Seats     []Seat
	SeatsUsed int
	SeatCap   int
	// The tenant's key: which version is current, since when.
	KeyVersion   int
	KeyCreatedAt *time.Time
	// The network integrations, and a token just minted, shown once.
	Tokens       []data.IntegrationToken
	NewToken     string
	NewTokenName string
}

// Users is the page where a Super Admin keeps a local tenant's people.
type Users struct {
	Accounts  []data.LocalAccount
	Roles     []string
	MFAPolicy string
	// CanMail says an invitation can be emailed; without it the link is
	// shown once for the administrator to hand over.
	CanMail bool
	// NewLink is shown once, on the page that made it, never through a
	// redirect: a link in a query string is a link in the browser history.
	NewLink, NewLinkFor, NewLinkKind string
	Emailed                          bool
	MailError                        string
}

// Account is a person's own page: who they are here and their password.
type Account struct {
	Email, Name, Role string
	MFAOn             bool
	MFARequired       bool
	RecoveryLeft      int
}

// LocalView is every page a person sees before they have a session on a
// local tenant: sign in, the second factor, enrolling it, choosing a
// password from a link, asking for a reset, and the recovery codes.
type LocalView struct {
	Mode  string
	Title string
	Said  string
	// Notice is good news, said plainly, above a form.
	Notice string
	Email  string
	Name   string
	Token  string
	Next   string
	// CanReset says the "forgot it" link goes somewhere: there is a way to
	// send mail.
	CanReset bool
	// Enrolment: the secret as an app types it, and the QR code as a data
	// URL, which html/template would otherwise rewrite.
	Secret string
	QR     template.URL
	Codes  []string
	// Continue is where the recovery-codes page goes next.
	Continue string
}

// UsersPage renders the Users page.
func (c *Console) UsersPage(w http.ResponseWriter, r *http.Request, s Session,
	load func(context.Context, *data.Tx, *Users) error) {

	c.render(w, r, s, "users.html", "/users", "Users",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			var u Users
			if err := load(ctx, tx, &u); err != nil {
				return err
			}
			p.Users = &u
			return nil
		})
}

// AccountPage renders a person's own page.
func (c *Console) AccountPage(w http.ResponseWriter, r *http.Request, s Session,
	load func(context.Context, *data.Tx, *Account) error) {

	c.render(w, r, s, "account.html", "/account", "Your account",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			var a Account
			if err := load(ctx, tx, &a); err != nil {
				return err
			}
			p.Account = &a
			return nil
		})
}

// LocalPage renders a sign-in page with the tenant's own brand, before
// anyone has a session.
func (c *Console) LocalPage(w http.ResponseWriter, r *http.Request, claim string, status int, v LocalView) {
	p := page{Title: v.Title, Brand: branding.Default(), Local: &v}
	_ = c.store.WithTenant(r.Context(), claim, func(ctx context.Context, tx *data.Tx) error {
		b, err := branding.Load(ctx, tx)
		if err != nil {
			return err
		}
		p.Brand = b
		return nil
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "local.html", p); err != nil {
		http.Error(w, v.Title, status)
	}
}

func (c *Console) IdentityPage(w http.ResponseWriter, r *http.Request, s Session,
	load func(context.Context, *data.Tx, *Identity) error) {

	c.render(w, r, s, "identity.html", "/identity", "Sign-in",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			var id Identity
			if err := load(ctx, tx, &id); err != nil {
				return err
			}
			p.Identity = &id
			return nil
		})
}

// ------------------------------------------------------------- branding

func (c *Console) BrandingPage(w http.ResponseWriter, r *http.Request, s Session) {
	c.render(w, r, s, "branding.html", "/branding", "Branding",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			// render has already loaded the brand; the form shows the
			// number behind the guard so a refusal is not a surprise.
			if ratio, err := branding.ContrastWithWhite(p.Brand.Colour); err == nil {
				p.Contrast = ratio
			}
			return nil
		})
}

// ------------------------------------------------------------- sign-up

// SignupView is the self-service sign-up page in each of its states:
// start, sent, slug, idp, done, problem.
type SignupView struct {
	State        string
	Email        string
	Company      string
	Slug         string
	Token        string
	TenantDomain string
	ConsoleURL   string
	RedirectURL  string
	SignInURL    string
	// Detail is the page's own message; Said is one carried across a
	// redirect, the way every console form reports back.
	Detail string
	Said   string
	// Regions to choose from, when the operator runs more than one.
	Regions []string
	// Local says the tenant was made with no identity provider, which only
	// changes the wording of the last page.
	Local bool
}

// Public renders the sign-up page. It is the one render that touches no
// tenant: there is no claim, no row-level security and no tenant brand,
// because the tenant does not exist yet. The brand it carries is the
// operator's, which is allowed here and nowhere else.
func (c *Console) Public(w http.ResponseWriter, r *http.Request, status int,
	brand branding.Brand, title string, v SignupView) {

	p := page{Title: title, Brand: brand, Path: r.URL.Path, Said: v.Said, Signup: &v,
		Now: time.Now().UTC()}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "signup.html", p); err != nil {
		http.Error(w, "could not render the page", http.StatusInternalServerError)
	}
}

// ------------------------------------------------------------- android

type Android struct {
	Configured    bool
	InPlan        bool
	Bound         bool
	Enterprise    string
	DisplayName   string
	BoundBy       string
	BoundAt       time.Time
	LastSyncedAt  *time.Time
	LastSyncError string
	Devices       int
	Tokens        []android.TokenRecord
	// A token just issued, shown once.
	NewToken    string
	NewTokenQR  string
	NewTokenFor string
	// NewTokenLink is Google's enrolment link for it: the thing to send.
	NewTokenLink      string
	NewTokenOwnership string
	// NewTokenQRImage is the QR code to scan, as a data: URL, and
	// NewTokenQRKind says what it holds: "link" (a personal phone's camera
	// opens it) or "provision" (a company phone's welcome screen reads it
	// after six taps). Empty when there is nothing right to draw, which is
	// better than drawing the wrong thing.
	NewTokenQRImage template.URL
	NewTokenQRKind  string
	// NewTokenMailed is who the link was emailed to; NewTokenMailError
	// says why it was not, when it was asked for and could not go.
	NewTokenMailed    string
	NewTokenMailError string
	CanMail           bool
}

func (c *Console) AndroidPage(w http.ResponseWriter, r *http.Request, s Session,
	load func(context.Context, *data.Tx, *Android) error) {

	c.render(w, r, s, "android.html", "/android", "Android",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			var a Android
			if err := load(ctx, tx, &a); err != nil {
				return err
			}
			p.Android = &a
			return nil
		})
}

// ------------------------------------------------------------- reports

type Reports struct {
	Summary   string
	Total     int
	Scheduled string
}

func (c *Console) ReportsPage(w http.ResponseWriter, r *http.Request, s Session,
	load func(context.Context, *data.Tx, *Reports) error) {

	c.render(w, r, s, "reports.html", "/reports", "Reports",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			var rp Reports
			if err := load(ctx, tx, &rp); err != nil {
				return err
			}
			p.Reports = &rp
			return nil
		})
}

// ------------------------------------------------------------------ people

func (c *Console) PeoplePage(w http.ResponseWriter, r *http.Request, s Session, query string) {
	c.render(w, r, s, "people.html", "/people", "People",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			p.PeopleQuery = query
			people, err := data.ListPeople(ctx, tx, query)
			if err != nil {
				return err
			}
			p.People = people
			return nil
		})
}

func (c *Console) PersonPage(w http.ResponseWriter, r *http.Request, s Session, id uuid.UUID) {
	c.render(w, r, s, "person.html", "/people", "Person",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			person, err := data.GetPerson(ctx, tx, id)
			if err != nil {
				// Another tenant's person is indistinguishable from one who
				// does not exist.
				return nil
			}
			p.Person = &person
			p.Title = person.Label()
			devs, err := data.DevicesOfPerson(ctx, tx, id)
			if err != nil {
				return err
			}
			p.PersonDevices = devs
			p.CanOffboard = authz.Can(s.Role, authz.OffboardEmployee)
			return nil
		})
}

// ------------------------------------------------------------- apps, keys

func (c *Console) AppsPage(w http.ResponseWriter, r *http.Request, s Session, query string,
	find func(context.Context, *data.Tx) ([]data.AppHolder, error)) {
	c.render(w, r, s, "apps.html", "/apps", "Apps",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			p.AppQuery = query
			found, err := find(ctx, tx)
			if err != nil {
				return err
			}
			p.AppHolders = found
			return nil
		})
}

// RevealedKeyPage shows a recovery key once. It is rendered directly from
// the handler that revealed it, so the key is never in a URL.
func (c *Console) RevealedKeyPage(w http.ResponseWriter, r *http.Request, s Session, device uuid.UUID, kind, key string) {
	c.render(w, r, s, "key.html", "/devices", "Recovery key",
		func(ctx context.Context, tx *data.Tx, p *page) error {
			p.KeyDeviceID, p.KeyKind, p.KeyValue = device, kind, key
			return nil
		})
}
