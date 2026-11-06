package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"platform/internal/branding"
	"platform/internal/console"
	"platform/internal/directory"
	"platform/internal/notify"
	"platform/internal/secrets"
)

// Self-service sign-up, the public side of it.
//
// This is the only surface in the platform that a stranger can reach and
// cause a write from, so the whole file is about bounding what a stranger
// can cause. The sequence:
//
//   1. POST /signup            a company name and a work email. We write one
//                              row and send one email. Nothing else exists.
//   2. GET  /signup/{token}    the link from that email. Opening it proves
//                              the address. The token is the credential for
//                              every step after this, which is why there is
//                              no session and no CSRF token here: a request
//                              that does not carry the secret is not a
//                              request from the person we emailed.
//   3. POST .../slug           choose the console's address.
//   4. POST .../finish         the identity provider and the admin group:
//                              the tenant is created and the link is spent,
//                              in one transaction.
//
// Bounds on step 1: a per-address bucket in memory (bursts), a per-address
// and per-domain cap in the database (days), and the free-mail refusal
// (who). Bounds on 2 to 4: the token is 256 bits, stored hashed, usable for
// a day and spent on use.
//
// What this page is NOT: a tenant surface. It carries the operator's own
// brand, which the build gate on operator branding allows exactly here,
// because there is no tenant yet whose brand it could carry instead.

type SignupConfig struct {
	// Host is the hostname that serves sign-up and nothing else.
	Host string
	// TenantDomain is where new tenants answer: <slug>.<TenantDomain>. A
	// tenant moves to its own domain later through the operator (AddHost).
	TenantDomain string
	// Brand is the operator's, shown on this page only.
	Brand branding.Brand
	// Mail sends the verification link. The email channel in production;
	// the log channel in the demonstration, which prints the link.
	Mail notify.Channel
	// BurstPerMinute bounds step 1 per caller address, in memory. Zero
	// means the default.
	BurstPerMinute int
	// Regions a new tenant may choose (T11), the first being the default.
	// Empty means the deployment's own and no choice offered.
	Regions []string
}

func (c *SignupConfig) servesHost(reqHost string) bool {
	h := strings.ToLower(reqHost)
	if i := strings.LastIndex(h, ":"); i != -1 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	return h == strings.ToLower(c.Host)
}

func (c *SignupConfig) brand() branding.Brand {
	b := c.Brand
	if b.ProductName == "" {
		b.ProductName = "Device management"
	}
	if b.Colour == "" {
		b.Colour = branding.Default().Colour
	}
	if b.MarkLetter == "" {
		b.MarkLetter = strings.ToUpper(b.ProductName[:1])
	}
	return b
}

const signupTokenBytes = 32

// A token is random bytes; the link carries them base64url; the row holds
// the SHA-256. Decoding is strict so that a token with a stray character is
// "not valid" rather than silently something else.
func newSignupToken() (token string, hash []byte, err error) {
	raw := make([]byte, signupTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	return token, sum[:], nil
}

func signupHash(token string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != signupTokenBytes {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

func (g *Gateway) signupHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/signup", http.StatusFound)
	}))
	mux.Handle("GET /signup", http.HandlerFunc(g.signupStart))
	mux.Handle("POST /signup", http.HandlerFunc(g.signupRequest))
	mux.Handle("GET /signup/{token}", http.HandlerFunc(g.signupOpen))
	mux.Handle("POST /signup/{token}/slug", http.HandlerFunc(g.signupSlug))
	mux.Handle("POST /signup/{token}/finish", http.HandlerFunc(g.signupFinish))
	mux.Handle("GET /signup/{token}/done", http.HandlerFunc(g.signupDone))
	// The partner API lives on the operator's hostname too (T7).
	g.partnerRoutes(mux)
	// Everything else on this hostname is nothing. Not a tenant's console,
	// not an API, not a sign-in page: there is no tenant here.
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	return mux
}

// signupScheme is what links should start with: https, unless this is the
// plain-HTTP development setup AND the request is to this machine. The
// second condition is what keeps a misconfigured production gateway from
// writing http:// redirect URLs into real tenants: the directory refuses
// a plain-HTTP console anywhere but localhost, and this agrees with it.
func (g *Gateway) signupScheme(r *http.Request) string {
	if r.TLS == nil && g.insecureCookies && onThisMachine(r.Host) {
		return "http"
	}
	return "https"
}

func onThisMachine(reqHost string) bool {
	h := strings.ToLower(reqHost)
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "127.0.0.1"
}

// consoleURL is where a tenant with this slug will answer. In production
// that is https on the tenant domain; in the demonstration the port the
// sign-up page itself arrived on is carried across, because <slug>.localhost
// resolves to the same machine.
func (g *Gateway) signupConsoleURL(r *http.Request, slug string) string {
	host := slug + "." + g.signup.TenantDomain
	if _, port, err := net.SplitHostPort(r.Host); err == nil && g.signupScheme(r) == "http" {
		host += ":" + port
	}
	return g.signupScheme(r) + "://" + host
}

func (g *Gateway) signupRender(w http.ResponseWriter, r *http.Request, status int,
	title string, v console.SignupView) {
	v.TenantDomain = g.signup.TenantDomain
	g.console.Public(w, r, status, g.signup.brand(), title, v)
}

func (g *Gateway) signupStart(w http.ResponseWriter, r *http.Request) {
	g.signupRender(w, r, http.StatusOK, "Sign up", console.SignupView{State: "start"})
}

func (g *Gateway) signupRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		g.signupRender(w, r, http.StatusBadRequest, "Sign up",
			console.SignupView{State: "start", Detail: "That form could not be read."})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	company := strings.TrimSpace(r.FormValue("company"))
	v := console.SignupView{State: "start", Email: email, Company: company}

	ip := g.callerIP(r)
	burst := g.signup.BurstPerMinute
	if burst == 0 {
		burst = 6
	}
	if !g.limiter.allowKey("signup:"+ip, burst) {
		w.Header().Set("Retry-After", "60")
		v.Detail = "Too many attempts. Wait a minute and try again."
		g.signupRender(w, r, http.StatusTooManyRequests, "Sign up", v)
		return
	}

	token, hash, err := newSignupToken()
	if err != nil {
		g.log.Error("sign-up token", "err", err)
		v.Detail = "Something went wrong on our side. Try again in a moment."
		g.signupRender(w, r, http.StatusInternalServerError, "Sign up", v)
		return
	}
	// The address as the directory tidies it is the address the email goes
	// to, so the two never differ by case.
	addr, _, err := directory.WorkEmail(email)
	if err == nil {
		_, err = g.dir.StartSignup(r.Context(), addr, company, ip, hash)
	}
	switch {
	case errors.Is(err, directory.ErrNotWorkEmail):
		v.Detail = "Use your work email address. A tenant belongs to a company, " +
			"so the address that creates it has to be one the company controls."
		g.signupRender(w, r, http.StatusUnprocessableEntity, "Sign up", v)
		return
	case errors.Is(err, directory.ErrTooManySignups):
		v.Detail = "Too many sign-ups from this address or company today. " +
			"If a colleague already started, ask them for the link."
		g.signupRender(w, r, http.StatusTooManyRequests, "Sign up", v)
		return
	case err != nil:
		if strings.Contains(err.Error(), "company") {
			v.Detail = "Name the company."
			g.signupRender(w, r, http.StatusUnprocessableEntity, "Sign up", v)
			return
		}
		g.log.Error("sign-up start", "err", err)
		v.Detail = "Something went wrong on our side. Try again in a moment."
		g.signupRender(w, r, http.StatusInternalServerError, "Sign up", v)
		return
	}

	link := g.signupScheme(r) + "://" + r.Host + "/signup/" + token
	brand := g.signup.brand()
	msg := notify.Message{
		Subject: "Confirm your address to set up " + brand.ProductName,
		Body: "Someone asked to set up " + brand.ProductName + " for " + company +
			" using this address.\n\nIf that was you, open this link within 24 hours:\n\n" +
			link + "\n\nIf it was not, ignore this message and nothing will happen.\n",
		Tenant: brand.ProductName, Colour: brand.Colour, Footer: brand.LegalFooter,
	}
	if err := g.signup.Mail.Deliver(r.Context(), addr, msg); err != nil {
		// The row exists; asking again replaces it. Say so rather than
		// pretending the email is on its way.
		g.log.Error("sign-up email", "err", err, "domain", emailDomain(addr))
		v.Detail = "We could not send the email just now. Try again in a few minutes."
		g.signupRender(w, r, http.StatusBadGateway, "Sign up", v)
		return
	}
	g.log.Info("sign-up requested", "domain", emailDomain(addr), "ip", ip)
	g.signupRender(w, r, http.StatusOK, "Check your email",
		console.SignupView{State: "sent", Email: addr, Company: company})
}

func emailDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i != -1 {
		return addr[i+1:]
	}
	return ""
}

// signupProblem says why a link does not work. A used or expired link says
// so, because the person holding it did get it from us; a token that was
// never ours is simply not found.
func (g *Gateway) signupProblem(w http.ResponseWriter, r *http.Request, err error) {
	v := console.SignupView{State: "problem"}
	switch {
	case errors.Is(err, directory.ErrSignupExpired):
		v.Detail = "This link has expired. Links last a day. Start again and we will send a new one."
		g.signupRender(w, r, http.StatusGone, "Link expired", v)
	case errors.Is(err, directory.ErrSignupFinished):
		v.Detail = "This link has already been used, and a link works once. " +
			"If you set the tenant up, sign in at its own address. If somebody " +
			"else did, ask them."
		g.signupRender(w, r, http.StatusGone, "Link already used", v)
	case errors.Is(err, directory.ErrNoSuchSignup):
		http.NotFound(w, r)
	default:
		g.log.Error("sign-up open", "err", err)
		v.Detail = "Something went wrong on our side. Try the link again in a moment."
		g.signupRender(w, r, http.StatusInternalServerError, "Sign up", v)
	}
}

func (g *Gateway) signupToken(w http.ResponseWriter, r *http.Request) ([]byte, string, bool) {
	token := r.PathValue("token")
	hash, ok := signupHash(token)
	if !ok {
		http.NotFound(w, r)
		return nil, "", false
	}
	return hash, token, true
}

func (g *Gateway) signupView(r *http.Request, s directory.Signup, token string) console.SignupView {
	v := console.SignupView{
		Email: s.Email, Company: s.Company, Slug: s.Slug, Token: token,
		Said: r.URL.Query().Get("said"),
	}
	if s.Slug == "" {
		v.State = "slug"
		v.Slug = suggestSlug(s.Company)
		// The example address, with the real scheme and domain.
		v.ConsoleURL = g.signupConsoleURL(r, "address")
		return v
	}
	v.State = "idp"
	v.Regions = g.signup.Regions
	v.ConsoleURL = g.signupConsoleURL(r, s.Slug)
	v.RedirectURL = v.ConsoleURL + "/signin/callback"
	return v
}

// suggestSlug is a starting point from the company name, nothing more.
func suggestSlug(company string) string {
	var b strings.Builder
	lastDash := true
	for _, c := range strings.ToLower(company) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	return s
}

func (g *Gateway) signupOpen(w http.ResponseWriter, r *http.Request) {
	hash, token, ok := g.signupToken(w, r)
	if !ok {
		return
	}
	s, err := g.dir.OpenSignup(r.Context(), hash)
	if err != nil {
		g.signupProblem(w, r, err)
		return
	}
	g.signupRender(w, r, http.StatusOK, "Set up your console", g.signupView(r, s, token))
}

func (g *Gateway) signupSlug(w http.ResponseWriter, r *http.Request) {
	hash, token, ok := g.signupToken(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that form could not be read", http.StatusBadRequest)
		return
	}
	_, err := g.dir.SetSignupSlug(r.Context(), hash, r.FormValue("slug"))
	said := ""
	switch {
	case errors.Is(err, directory.ErrBadSlug):
		said = "An address is lowercase letters, digits and hyphens, up to 40 of them."
	case errors.Is(err, directory.ErrSlugTaken):
		said = "That address is taken. Choose another."
	case err != nil:
		g.signupProblem(w, r, err)
		return
	}
	to := "/signup/" + token
	if said != "" {
		to += "?said=" + url.QueryEscape(said)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (g *Gateway) signupFinish(w http.ResponseWriter, r *http.Request) {
	hash, token, ok := g.signupToken(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that form could not be read", http.StatusBadRequest)
		return
	}
	s, err := g.dir.OpenSignup(r.Context(), hash)
	if err != nil {
		g.signupProblem(w, r, err)
		return
	}
	if s.Slug == "" {
		http.Redirect(w, r, "/signup/"+token, http.StatusSeeOther)
		return
	}
	region := strings.TrimSpace(r.FormValue("region"))
	if len(g.signup.Regions) > 0 {
		ok := false
		for _, rg := range g.signup.Regions {
			if rg == region {
				ok = true
			}
		}
		if region == "" {
			region, ok = g.signup.Regions[0], true
		}
		if !ok {
			region = ""
		}
	}
	back := func(msg string) {
		http.Redirect(w, r, "/signup/"+token+"?said="+url.QueryEscape(msg), http.StatusSeeOther)
	}

	issuer := strings.TrimSpace(r.FormValue("issuer"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	secret := strings.TrimSpace(r.FormValue("client_secret"))
	roleClaim := strings.TrimSpace(r.FormValue("role_claim"))
	adminGroup := strings.TrimSpace(r.FormValue("admin_group"))
	if issuer == "" || clientID == "" || secret == "" {
		back("The issuer, client id and client secret are all needed.")
		return
	}
	if adminGroup == "" {
		back("Name the group whose members will be the first administrators, or nobody will be able to sign in.")
		return
	}
	if g.keys == nil {
		back("This deployment cannot create a tenant's keys. Tell the operator.")
		return
	}
	// The tenant's own key, made before the tenant: the first secret is
	// sealed under it, and both go into the create.
	tenantKey, keySealed, err := g.keys.NewTenantKey()
	if err != nil {
		g.log.Error("sign-up tenant key", "err", err)
		back("Something went wrong on our side. Try again in a moment.")
		return
	}
	sealed, err := secrets.SealWith(tenantKey, 1, []byte(secret))
	if err != nil {
		g.log.Error("sign-up seal", "err", err)
		back("Something went wrong on our side. Try again in a moment.")
		return
	}

	id, err := g.dir.FinishSignup(r.Context(), hash, directory.NewTenant{
		Name: s.Company, Slug: s.Slug, Plan: "starter",
		Host:       s.Slug + "." + g.signup.TenantDomain,
		ConsoleURL: g.signupConsoleURL(r, s.Slug),
		Issuer:     issuer, ClientID: clientID, ClientSecretSealed: sealed,
		RoleClaim: roleClaim, AdminGroup: adminGroup, KeySealed: keySealed, Region: region,
	})
	switch {
	case errors.Is(err, directory.ErrSlugTaken), errors.Is(err, directory.ErrHostTaken):
		// Taken between choosing and finishing. Clear the draft so the
		// first page comes back.
		back("That address was taken while you were filling this in. Choose another.")
		return
	case errors.Is(err, directory.ErrSignupFinished), errors.Is(err, directory.ErrSignupExpired):
		g.signupProblem(w, r, err)
		return
	case err != nil:
		if strings.HasPrefix(err.Error(), "directory: ") {
			back(strings.TrimPrefix(err.Error(), "directory: ") + ".")
			return
		}
		g.log.Error("sign-up finish", "err", err)
		back("Something went wrong on our side. Try again in a moment.")
		return
	}
	g.log.Info("tenant signed up", "tenant", id, "slug", s.Slug, "domain", s.Domain)

	// The welcome. Sent after the commit, to the address that proved
	// itself, so the person has the console's address somewhere other than
	// a page behind a spent link. It is not allowed to fail the sign-up:
	// the tenant exists either way, and the done page says the same thing.
	consoleURL := g.signupConsoleURL(r, s.Slug)
	brand := g.signup.brand()
	welcome := notify.Message{
		Subject: s.Company + " is set up on " + brand.ProductName,
		Body: "Your console is ready.\n\n" +
			"  Console   " + consoleURL + "\n" +
			"  Sign in   " + consoleURL + "/signin\n\n" +
			"Sign in with your company's identity provider. Members of " + adminGroup +
			" are the first administrators; they map every other group from the console.\n\n" +
			"What is left is on the Setup page inside: the product's own name and colours, " +
			"where notifications go, and the first device.\n\n" +
			"The link you used to set this up has now been spent and will not work again.\n",
		Tenant: brand.ProductName, Colour: brand.Colour, Footer: brand.LegalFooter,
	}
	if err := g.signup.Mail.Deliver(r.Context(), s.Email, welcome); err != nil {
		g.log.Error("welcome email", "err", err, "tenant", id)
	}
	http.Redirect(w, r, "/signup/"+token+"/done", http.StatusSeeOther)
}

func (g *Gateway) signupDone(w http.ResponseWriter, r *http.Request) {
	hash, token, ok := g.signupToken(w, r)
	if !ok {
		return
	}
	s, sum, err := g.dir.SignupResult(r.Context(), hash)
	if err != nil {
		g.signupProblem(w, r, err)
		return
	}
	v := console.SignupView{
		State: "done", Email: s.Email, Company: sum.Name, Slug: sum.Slug, Token: token,
		ConsoleURL: g.signupConsoleURL(r, sum.Slug),
	}
	v.SignInURL = v.ConsoleURL + "/signin"
	g.signupRender(w, r, http.StatusOK, "Your console is ready", v)
}

var _ = context.Background
