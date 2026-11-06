package gateway

import (
	"context"
	"encoding/base64"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"platform/internal/directory"
	"platform/internal/identity"
	"platform/internal/identity/idptest"
	"platform/internal/secrets"
)

// SAML sign-in, end to end, against a provider that signs real assertions
// (internal/identity/idptest). The browser is the same real client the
// OIDC tests use; the one thing it does that a real browser would not is
// send a SameSite cookie on a cross-site POST, which is the case the flow
// cookie is set SameSite=None for in production.

const samlACS = "http://mdm.kalesi.example/signin/saml"

type samlFixture struct {
	fixture
	idp     *idptest.SAMLServer
	server  *httptest.Server
	browser *browser
}

func newSAMLFixture(t *testing.T) *samlFixture {
	t.Helper()
	f := newFixture(t)
	idp, err := idptest.NewSAML(samlACS)
	if err != nil {
		t.Fatalf("idptest saml: %v", err)
	}
	t.Cleanup(idp.Close)
	sealer, _ := secrets.NewAESSealer(sealKey)
	g := New(Config{
		Directory: f.g.dir, Store: f.g.store, Signer: f.g.signer, Identity: f.g.idp,
		Pipeline: f.pipe, CSRFKey: testKey, Sessions: f.sessions,
		OIDC: identity.NewOIDC(), SAML: identity.NewSAML(), Sealer: secrets.NewKeyring(sealer), Enrol: f.enrol,
		InsecureCookies: true,
	})
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	seedSAMLIdentity(t, idp)
	return &samlFixture{
		fixture: fixture{h: g.Handler(), g: g, pipe: f.pipe, sessions: f.sessions,
			enrol: f.enrol, sealer: secrets.NewKeyring(sealer), devices: f.devices},
		idp: idp, server: srv, browser: newBrowser(t, srv.Listener.Addr().String()),
	}
}

func seedSAMLIdentity(t *testing.T, idp *idptest.SAMLServer) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("MDM_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_identity
		  (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, role_claim,
		   protocol, saml_sso_url, saml_certificate)
		VALUES ($1, $2, 'http://mdm.kalesi.example/saml/metadata', ''::bytea, $3,
		        'eduPersonAffiliation', 'saml', $4, $5)`,
		tenantA, idp.EntityID(), samlACS, idp.SSOURL(), idp.CertificatePEM()); err != nil {
		t.Fatalf("seed saml identity: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO tenant_role_map (tenant_id, claim_value, role) VALUES
		  ($1,'MDM-Owners','super_admin'),
		  ($1,'IT-Operations','it_admin'),
		  ($1,'All-Staff','employee')`, tenantA); err != nil {
		t.Fatalf("seed role map: %v", err)
	}
}

var samlResponseInput = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)

// startSAML walks to the provider and returns what it would auto-post,
// without posting it, so a test can decide what to do with it.
func (f *samlFixture) startSAML(t *testing.T) string {
	t.Helper()
	resp, body := f.browser.get("http://mdm.kalesi.example/signin")
	m := samlResponseInput.FindStringSubmatch(body)
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("the provider did not answer with a response form (%d): %.400s", resp.StatusCode, body)
	}
	return html.UnescapeString(m[1])
}

func (b *browser) postForm(to string, form url.Values) (*http.Response, string) {
	b.t.Helper()
	req, _ := http.NewRequest("POST", to, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("POST %s: %v", to, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp, string(body)
}

func (f *samlFixture) post(t *testing.T, encoded string) (*http.Response, string) {
	t.Helper()
	return f.browser.postForm(samlACS, url.Values{"SAMLResponse": {encoded}})
}

func TestSAMLPersonSignsInAndReachesTheConsole(t *testing.T) {
	f := newSAMLFixture(t)
	f.idp.SignInAs(idptest.Person{Subject: "o.martins", Email: "o.martins@kalesi.example",
		Name: "O. Martins", Groups: []string{"All-Staff", "IT-Operations"}})

	resp, body := f.post(t, f.startSAML(t))
	if resp.StatusCode != 200 || !strings.Contains(body, "Dashboard") {
		t.Fatalf("sign-in ended at %d: %.400s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "it_admin") {
		t.Fatalf("the role did not come from the groups attribute: %.400s", body)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") == "" {
		t.Fatal("no session cookie was set")
	}
	// The sign-in is in the tenant's audit log like an OIDC one.
	var n int
	f.g.store.WithTenant(context.Background(), f.claim(t, "a-super"), func(ctx context.Context, tx *dataTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'session.start'`).Scan(&n)
	})
	if n == 0 {
		t.Fatal("no audit row for the sign-in")
	}
}

func TestSAMLAssertionForAnotherFlowIsRefused(t *testing.T) {
	f := newSAMLFixture(t)
	f.idp.SignInAs(idptest.Person{Subject: "o.martins", Groups: []string{"IT-Operations"}})
	first := f.startSAML(t)
	// A second sign-in replaces the flow cookie: the first answer now
	// answers a request this browser is no longer making.
	f.startSAML(t)
	resp, body := f.post(t, first)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "could not confirm who you are") {
		t.Fatalf("an assertion for another flow was not refused: %d %.300s", resp.StatusCode, body)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatal("a session was started anyway")
	}
}

func TestSAMLTamperedAssertionIsRefused(t *testing.T) {
	f := newSAMLFixture(t)
	f.idp.SignInAs(idptest.Person{Subject: "o.martins", Groups: []string{"All-Staff"}})
	encoded := f.startSAML(t)
	raw := decodeStd(t, encoded)
	forged := encodeStd(strings.Replace(raw, "All-Staff", "MDM-Owners", 1))
	resp, _ := f.post(t, forged)
	if resp.StatusCode != http.StatusForbidden || f.browser.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatalf("a tampered assertion signed somebody in: %d", resp.StatusCode)
	}
}

func TestSAMLResponseWithoutAFlowIsExpired(t *testing.T) {
	f := newSAMLFixture(t)
	f.idp.SignInAs(idptest.Person{Subject: "o.martins", Groups: []string{"All-Staff"}})
	encoded := f.startSAML(t)
	// A different browser, holding no flow cookie, posts the same answer.
	other := newBrowser(t, f.server.Listener.Addr().String())
	resp, body := other.postForm(samlACS, url.Values{"SAMLResponse": {encoded}})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "expired") {
		t.Fatalf("a response with no flow was not refused: %d %.300s", resp.StatusCode, body)
	}
}

func TestSAMLFlowFromAnotherHostnameIsRefused(t *testing.T) {
	f := newSAMLFixture(t)
	f.idp.SignInAs(idptest.Person{Subject: "o.martins", Groups: []string{"All-Staff"}})
	encoded := f.startSAML(t)
	// Kalesi's flow cookie, carried by hand to Arbor's hostname.
	u, _ := url.Parse("http://mdm.kalesi.example/")
	var flow string
	for _, c := range f.browser.client.Jar.Cookies(u) {
		if c.Name == flowCookie {
			flow = c.Value
		}
	}
	if flow == "" {
		t.Fatal("no flow cookie after starting a sign-in")
	}
	req, _ := http.NewRequest("POST", "http://devices.arbor.example/signin/saml",
		strings.NewReader(url.Values{"SAMLResponse": {encoded}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: flowCookie, Value: flow})
	resp, err := f.browser.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "different tenants") {
		t.Fatalf("a flow begun on another hostname was not refused as such: %d %s", resp.StatusCode, body)
	}
}

func TestSAMLMetadataIsServedForSAMLTenantsOnly(t *testing.T) {
	f := newSAMLFixture(t)
	resp, body := f.browser.get("http://mdm.kalesi.example/saml/metadata")
	if resp.StatusCode != 200 || !strings.Contains(body, `entityID="http://mdm.kalesi.example/saml/metadata"`) ||
		!strings.Contains(body, samlACS) {
		t.Fatalf("metadata: %d %.300s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/samlmetadata+xml") {
		t.Fatalf("content type %q", ct)
	}
	// Arbor has no SAML; there is no metadata to serve and nothing to
	// learn from asking.
	resp, _ = f.browser.get("http://devices.arbor.example/saml/metadata")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("metadata for a non-SAML tenant answered %d", resp.StatusCode)
	}
}

func TestSAMLProviderCanBeChangedFromTheConsole(t *testing.T) {
	f := newSAMLFixture(t)
	f.idp.SignInAs(idptest.Person{Subject: "f.okonkwo", Groups: []string{"MDM-Owners"}})
	if resp, _ := f.post(t, f.startSAML(t)); resp.StatusCode != 200 {
		t.Fatalf("super admin could not sign in: %d", resp.StatusCode)
	}
	sess, err := f.sessions.Verify(f.browser.sessionCookie("mdm.kalesi.example"))
	if err != nil {
		t.Fatal(err)
	}
	csrf := f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)

	// Junk for a certificate is refused before it is stored.
	resp, body := f.browser.postForm("http://mdm.kalesi.example/identity", url.Values{
		"csrf": {csrf}, "return": {"/identity"}, "protocol": {"saml"},
		"issuer": {"https://sts.windows.net/x/"}, "saml_sso_url": {"https://login.microsoftonline.com/x/saml2"},
		"saml_certificate": {"not a certificate"},
	})
	if !strings.Contains(body, "not a certificate") {
		t.Fatalf("junk certificate was not refused: %d %.300s", resp.StatusCode, body)
	}

	// A new provider, with its certificate: from now on only it can sign
	// people in.
	next, err := idptest.NewSAML(samlACS)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	resp, body = f.browser.postForm("http://mdm.kalesi.example/identity", url.Values{
		"csrf": {csrf}, "return": {"/identity"}, "protocol": {"saml"},
		"issuer": {next.EntityID()}, "saml_sso_url": {next.SSOURL()},
		"saml_certificate": {next.CertificatePEM()}, "role_claim": {"eduPersonAffiliation"},
	})
	if !strings.Contains(body, "Saved") || !strings.Contains(body, "one is held") {
		t.Fatalf("saml provider not saved: %d %.400s", resp.StatusCode, body)
	}

	fresh := newBrowser(t, f.server.Listener.Addr().String())
	next.SignInAs(idptest.Person{Subject: "o.martins", Groups: []string{"IT-Operations"}})
	r2, b2 := fresh.get("http://mdm.kalesi.example/signin")
	m := samlResponseInput.FindStringSubmatch(b2)
	if r2.StatusCode != 200 || m == nil {
		t.Fatalf("the new provider was not used: %d %.300s", r2.StatusCode, b2)
	}
	r3, b3 := fresh.postForm(samlACS, url.Values{"SAMLResponse": {html.UnescapeString(m[1])}})
	if r3.StatusCode != 200 || !strings.Contains(b3, "it_admin") {
		t.Fatalf("sign-in through the new provider failed: %d %.300s", r3.StatusCode, b3)
	}
	if next.Served != 1 {
		t.Fatalf("the new provider served %d assertions", next.Served)
	}
}

func TestSAMLTenantCanBeOnboarded(t *testing.T) {
	f := newSAMLFixture(t)
	id, err := f.g.dir.CreateTenant(context.Background(), directory.NewTenant{
		Name: "Zuri Logistics", Slug: "zuri", Host: "mdm.zuri.example", AdminGroup: "Zuri-IT",
		Protocol: "saml", Issuer: f.idp.EntityID(), SAMLSSOURL: f.idp.SSOURL(),
		SAMLCertificate: f.idp.CertificatePEM(),
	})
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	cfg, err := f.g.dir.Identity(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "saml" || cfg.ClientID != "https://mdm.zuri.example/saml/metadata" ||
		cfg.RedirectURL != "https://mdm.zuri.example/signin/saml" || len(cfg.SecretSealed) != 0 {
		t.Fatalf("stored: %+v", cfg)
	}
	// And the sign-in route sends the browser to the provider.
	resp := f.browser.once("GET", "http://mdm.zuri.example/signin")
	if loc := resp.Header.Get("Location"); resp.StatusCode != 302 || !strings.HasPrefix(loc, f.idp.SSOURL()+"?") {
		t.Fatalf("sign-in did not go to the provider: %d %s", resp.StatusCode, loc)
	}
	// Without a certificate the row is refused, not half-written.
	if _, err := f.g.dir.CreateTenant(context.Background(), directory.NewTenant{
		Name: "Half", Slug: "half", Host: "mdm.half.example", AdminGroup: "x",
		Protocol: "saml", Issuer: "urn:half", SAMLSSOURL: "https://half.example/sso",
	}); err == nil {
		t.Fatal("a SAML tenant without a certificate was created")
	}
}

func decodeStd(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func encodeStd(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestOIDCCallbackRefusesASAMLTenant(t *testing.T) {
	f := newSAMLFixture(t)
	f.idp.SignInAs(idptest.Person{Subject: "o.martins", Groups: []string{"All-Staff"}})
	f.startSAML(t)
	// The flow is live; its state is the SAML request id. Somebody sends
	// the browser to the OIDC callback with it.
	u, _ := url.Parse("http://mdm.kalesi.example/")
	var state string
	for _, c := range f.browser.client.Jar.Cookies(u) {
		if c.Name == flowCookie {
			fl, err := f.sessions.VerifyFlow(c.Value)
			if err != nil {
				t.Fatal(err)
			}
			state = fl.State
		}
	}
	resp := f.browser.once("GET", "http://mdm.kalesi.example/signin/callback?code=x&state="+url.QueryEscape(state))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the OIDC callback took a SAML tenant's flow: %d", resp.StatusCode)
	}
}
