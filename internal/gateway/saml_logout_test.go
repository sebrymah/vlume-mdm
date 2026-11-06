package gateway

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"platform/internal/identity/idptest"
)

// SAML single logout (0043), both ways.

var x509InMetadata = regexp.MustCompile(`<X509Certificate[^>]*>([^<]+)</X509Certificate>`)

// samlLogoutFixture is the SAML fixture with a logout URL at the provider
// and our signing certificate pinned there, as a real provider pins it
// from our metadata.
func samlLogoutFixture(t *testing.T) *samlFixture {
	t.Helper()
	f := newSAMLFixture(t)
	adminExec(t, `UPDATE tenant_identity SET saml_slo_url = $1 WHERE tenant_id = $2`, f.idp.SLOURL(), tenantA)
	f.idp.SetServiceProviderSLO("http://mdm.kalesi.example/signout/saml")
	resp, md := f.browser.get("http://mdm.kalesi.example/saml/metadata")
	if resp.StatusCode != 200 {
		t.Fatalf("metadata: %d", resp.StatusCode)
	}
	if !strings.Contains(md, "SingleLogoutService") || !strings.Contains(md, "/signout/saml") {
		t.Fatalf("our metadata does not offer single logout:\n%s", md)
	}
	m := x509InMetadata.FindStringSubmatch(md)
	if m == nil {
		t.Fatalf("our metadata carries no signing certificate:\n%s", md)
	}
	pem := "-----BEGIN CERTIFICATE-----\n" + strings.TrimSpace(m[1]) + "\n-----END CERTIFICATE-----\n"
	if err := f.idp.TrustServiceProvider(pem); err != nil {
		t.Fatalf("pin our certificate at the provider: %v", err)
	}
	// Made once, sealed, and the same on the next read.
	if n := adminCount(t, `SELECT count(*) FROM tenant_identity WHERE tenant_id = $1 AND saml_sp_key_sealed IS NOT NULL AND saml_sp_cert <> ''`, tenantA); n != 1 {
		t.Fatal("the signing key was not kept")
	}
	if n := adminCount(t, `SELECT count(*) FROM tenant_identity WHERE tenant_id = $1 AND position('PRIVATE KEY' in encode(saml_sp_key_sealed, 'escape')) > 0`, tenantA); n != 0 {
		t.Fatal("the signing key is stored in the clear")
	}
	_, md2 := f.browser.get("http://mdm.kalesi.example/saml/metadata")
	if x509InMetadata.FindStringSubmatch(md2)[1] != m[1] {
		t.Fatal("a second read made a second certificate")
	}
	return f
}

func samlSignIn(t *testing.T, f *samlFixture) string {
	t.Helper()
	f.idp.SignInAs(idptest.Person{Subject: "o.martins", Email: "o.martins@kalesi.example",
		Name: "O. Martins", Groups: []string{"All-Staff", "IT-Operations"}})
	resp, body := f.post(t, f.startSAML(t))
	if resp.StatusCode != 200 || !strings.Contains(body, "Dashboard") {
		t.Fatalf("sign-in ended at %d: %.300s", resp.StatusCode, body)
	}
	cookie := f.browser.sessionCookie("mdm.kalesi.example")
	if cookie == "" {
		t.Fatal("no session after sign-in")
	}
	return cookie
}

func TestSAMLSignOutEndsTheProvidersSessionToo(t *testing.T) {
	f := samlLogoutFixture(t)
	cookie := samlSignIn(t, f)
	sess, err := f.sessions.Verify(cookie)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := f.browser.postForm("http://mdm.kalesi.example/signout",
		url.Values{"csrf": {f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)}})
	// Through the provider and back: it saw a signed request naming the
	// person, answered, and the browser came back to our sign-in page
	// with no session (which, for a configured tenant, starts the next
	// sign-in at the provider; the chain ends there, 200).
	if resp.StatusCode != 200 {
		t.Fatalf("sign-out ended at %s (%d): %.300s", resp.Request.URL, resp.StatusCode, body)
	}
	if len(f.idp.LoggedOut) != 1 || f.idp.LoggedOut[0] != "o.martins" {
		t.Fatalf("the provider was asked to sign out %v", f.idp.LoggedOut)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatal("the session cookie survived sign-out")
	}
	// A browser with no session is sent to sign in, which for a
	// configured tenant ends at the provider: the request must not end
	// on our API with the device list.
	if resp, body := f.browser.get("http://mdm.kalesi.example/api/devices"); resp.Request.URL.Path == "/api/devices" && strings.Contains(body, "HQ-MBP-001") {
		t.Fatal("the browser is still signed in")
	}
}

func TestSAMLProviderCanSignThePersonOutHere(t *testing.T) {
	f := samlLogoutFixture(t)
	samlSignIn(t, f)
	to, err := f.idp.LogOut("o.martins")
	if err != nil {
		t.Fatal(err)
	}
	resp, body := f.browser.get(to)
	if resp.StatusCode != 200 || !strings.Contains(body, "signed out everywhere") {
		t.Fatalf("the provider did not get our answer: %d %s %.200s", resp.StatusCode, resp.Request.URL, body)
	}
	if f.idp.Answered != 1 {
		t.Fatalf("answers at the provider: %d", f.idp.Answered)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatal("the session survived the provider's logout")
	}
}

// The control --break-slosig takes the provider's request unsigned.
func TestAnUnsignedLogoutRequestIsRefused(t *testing.T) {
	f := samlLogoutFixture(t)
	samlSignIn(t, f)
	resp, _ := f.browser.get(f.idp.UnsignedLogOut("o.martins"))
	if resp.StatusCode != 400 {
		t.Fatalf("an unsigned logout request was acted on: %d at %s", resp.StatusCode, resp.Request.URL)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") == "" {
		t.Fatal("an unsigned logout request ended the session")
	}
	// And one from another provider: our test IdP's twin with its own key.
	other, err := idptest.NewSAML(samlACS)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetServiceProviderSLO("http://mdm.kalesi.example/signout/saml")
	to, _ := other.LogOut("o.martins")
	if resp, _ := f.browser.get(to); resp.StatusCode != 400 {
		t.Fatalf("another provider's logout request was acted on: %d", resp.StatusCode)
	}
}

func TestSAMLWithoutALogoutURLSignsOutHereOnly(t *testing.T) {
	f := newSAMLFixture(t)
	cookie := samlSignIn(t, f)
	sess, _ := f.sessions.Verify(cookie)
	resp, _ := f.browser.postForm("http://mdm.kalesi.example/signout",
		url.Values{"csrf": {f.g.csrfFor(sess.TenantID, sess.Subject, sess.Role)}})
	if resp.StatusCode != 200 || len(f.idp.LoggedOut) != 0 || f.idp.Answered != 0 {
		t.Fatalf("ended at %s (%d), provider asked %v", resp.Request.URL, resp.StatusCode, f.idp.LoggedOut)
	}
	if f.browser.sessionCookie("mdm.kalesi.example") != "" {
		t.Fatal("the session survived")
	}
}
