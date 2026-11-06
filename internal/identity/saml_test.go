package identity

import (
	"context"
	"encoding/base64"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/google/uuid"

	"platform/internal/identity/idptest"
)

const acs = "https://mdm.kalesi.example/signin/saml"

func samlConfig(t *testing.T, idp *idptest.SAMLServer) Config {
	t.Helper()
	return Config{
		TenantID: uuid.New(), Protocol: ProtocolSAML,
		Issuer: idp.EntityID(), ClientID: "https://mdm.kalesi.example/saml/metadata",
		RedirectURL: acs, SAMLSSOURL: idp.SSOURL(), SAMLCertificate: idp.CertificatePEM(),
		RoleClaim: "eduPersonAffiliation",
	}
}

var responseInput = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)

// roundTrip walks the browser's path: to the provider, and back with the
// posted response, which it returns still encoded.
func roundTrip(t *testing.T, s *SAML, cfg Config) (encoded, requestID string) {
	t.Helper()
	to, id, err := s.AuthURL(cfg)
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	if !strings.HasPrefix(to, cfg.SAMLSSOURL+"?") || !strings.Contains(to, "SAMLRequest=") {
		t.Fatalf("redirect does not go to the provider with a request: %s", to)
	}
	jar, _ := cookiejar.New(nil)
	resp, err := (&http.Client{Jar: jar}).Get(to)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	defer resp.Body.Close()
	var body strings.Builder
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		body.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	m := responseInput.FindStringSubmatch(body.String())
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("provider answered %d without a SAMLResponse form: %.300s", resp.StatusCode, body.String())
	}
	return html.UnescapeString(m[1]), id
}

func TestSAMLSignsInWithGroups(t *testing.T) {
	idp, err := idptest.NewSAML(acs)
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()
	idp.SignInAs(idptest.Person{Subject: "ada@kalesi.example", Email: "ada@kalesi.example",
		Name: "Ada Okonkwo", Groups: []string{"IT-Operations", "All-Staff"}})

	s := NewSAML()
	cfg := samlConfig(t, idp)
	encoded, id := roundTrip(t, s, cfg)

	c, err := s.Consume(cfg, encoded, id)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if c.Subject != "ada@kalesi.example" || c.Email != "ada@kalesi.example" || c.Name != "Ada Okonkwo" {
		t.Fatalf("claims: %+v", c)
	}
	if len(c.Groups) != 2 || c.Groups[0] != "IT-Operations" {
		t.Fatalf("groups: %v", c.Groups)
	}
}

func TestSAMLRefusesAnswerToAnotherRequest(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	idp.SignInAs(idptest.Person{Subject: "ada", Groups: []string{"All-Staff"}})
	s := NewSAML()
	cfg := samlConfig(t, idp)
	encoded, _ := roundTrip(t, s, cfg)

	// A fresh request id: the assertion answers the first one, not this.
	_, other, _ := s.AuthURL(cfg)
	if _, err := s.Consume(cfg, encoded, other); err == nil {
		t.Fatal("an assertion for another request was accepted")
	}
	// And no request at all, which is what an identity-provider-initiated
	// sign-in looks like.
	if _, err := s.Consume(cfg, encoded, ""); err == nil {
		t.Fatal("an unsolicited assertion was accepted")
	}
}

func TestSAMLRefusesTamperedAssertion(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	idp.SignInAs(idptest.Person{Subject: "ada", Groups: []string{"All-Staff"}})
	s := NewSAML()
	cfg := samlConfig(t, idp)
	encoded, id := roundTrip(t, s, cfg)

	raw := decodeB64(t, encoded)
	if !strings.Contains(raw, "All-Staff") {
		t.Fatalf("assertion does not carry the group: %.400s", raw)
	}
	// Promote ourselves inside the signed document.
	forged := encodeB64(strings.Replace(raw, "All-Staff", "MDM-Owners", 1))
	if _, err := s.Consume(cfg, forged, id); err == nil {
		t.Fatal("a tampered assertion was accepted")
	}
}

func TestSAMLRefusesAnotherProvidersCertificate(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	other, _ := idptest.NewSAML(acs)
	defer other.Close()
	idp.SignInAs(idptest.Person{Subject: "ada", Groups: []string{"All-Staff"}})
	s := NewSAML()
	cfg := samlConfig(t, idp)
	encoded, id := roundTrip(t, s, cfg)

	// The tenant pinned a different certificate: the right provider's
	// signature is now the wrong signature.
	pinned := cfg
	pinned.SAMLCertificate = other.CertificatePEM()
	if _, err := s.Consume(pinned, encoded, id); err == nil {
		t.Fatal("an assertion signed by an unpinned key was accepted")
	}
}

func TestSAMLRefusesAssertionForAnotherAudience(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	idp.SignInAs(idptest.Person{Subject: "ada", Groups: []string{"All-Staff"}})
	s := NewSAML()
	cfg := samlConfig(t, idp)
	encoded, id := roundTrip(t, s, cfg)

	// The same provider, the same key, but we are a different service
	// provider now: the audience in the assertion no longer names us.
	asOther := cfg
	asOther.ClientID = "https://devices.arbor.example/saml/metadata"
	if _, err := s.Consume(asOther, encoded, id); err == nil {
		t.Fatal("an assertion for another audience was accepted")
	}
}

func TestSAMLEntraGroupsUnderDefaultClaim(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	idp.Attributes = []saml.Attribute{{
		Name: entraGroups, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
		Values: []saml.AttributeValue{{Value: "MDM-Owners"}, {Value: "All-Staff"}},
	}}
	idp.SignInAs(idptest.Person{Subject: "ada"})
	s := NewSAML()
	cfg := samlConfig(t, idp)
	cfg.RoleClaim = "groups"
	encoded, id := roundTrip(t, s, cfg)
	c, err := s.Consume(cfg, encoded, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Groups) != 2 || c.Groups[0] != "MDM-Owners" {
		t.Fatalf("Entra groups not read under the default claim: %v", c.Groups)
	}
}

func TestSAMLMetadataNamesUs(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	md, err := NewSAML().Metadata(samlConfig(t, idp))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(md)
	for _, want := range []string{`entityID="https://mdm.kalesi.example/saml/metadata"`, acs, "WantAssertionsSigned=\"true\""} {
		if !strings.Contains(doc, want) {
			t.Fatalf("metadata lacks %s:\n%s", want, doc)
		}
	}
}

func TestOIDCRefusesSAMLConfig(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	cfg := samlConfig(t, idp)
	if _, err := NewOIDC().AuthURL(context.Background(), cfg, "s", "n", "v"); err != ErrWrongProtocol {
		t.Fatalf("OIDC took a SAML config: %v", err)
	}
	if _, err := NewSAML().Metadata(Config{Issuer: "https://x", ClientID: "c", RedirectURL: "https://y"}); err != ErrWrongProtocol {
		t.Fatalf("SAML took an OIDC config: %v", err)
	}
}

func TestParseCertificateAcceptsBareBase64(t *testing.T) {
	idp, _ := idptest.NewSAML(acs)
	defer idp.Close()
	pemText := idp.CertificatePEM()
	bare := strings.NewReplacer("-----BEGIN CERTIFICATE-----", "", "-----END CERTIFICATE-----", "").Replace(pemText)
	c1, norm1, err := ParseCertificate(pemText)
	if err != nil {
		t.Fatal(err)
	}
	c2, norm2, err := ParseCertificate(bare)
	if err != nil {
		t.Fatalf("bare base64 refused: %v", err)
	}
	if !c1.Equal(c2) || norm1 != norm2 {
		t.Fatal("the two spellings did not normalise to the same certificate")
	}
	if _, _, err := ParseCertificate("not a certificate"); err == nil {
		t.Fatal("junk was accepted as a certificate")
	}
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func encodeB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

var _ = url.Parse
