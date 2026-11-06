package idptest

// A working SAML 2.0 identity provider for tests, for the same reason the
// OIDC one exists: a fake adapter would skip the signature, the audience,
// the request binding and the validity window, which are the checks that
// make the real one safe. This one signs real assertions with a real key
// through the same library the gateway verifies them with, so the tests
// walk the path an Entra or ADFS sign-in walks.

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	dsig "github.com/russellhaering/goxmldsig"
)

type SAMLServer struct {
	http *httptest.Server
	idp  *saml.IdentityProvider
	cert *x509.Certificate
	acs  string

	mu     sync.Mutex
	person Person
	spCert *x509.Certificate
	spSLO  string
	// LoggedOut records the NameIDs logout requests named; Answered
	// counts logout responses the service provider sent back.
	LoggedOut []string
	Answered  int
	// Attributes are extra attributes emitted on every assertion, for
	// tests that want a provider's exact spelling (Entra's group URI).
	Attributes []saml.Attribute
	// Served counts assertions issued.
	Served int
}

// NewSAML starts a provider that will answer any service provider whose
// assertion consumer service is acsURL.
func NewSAML(acsURL string) (*SAMLServer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "idptest SAML signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	s := &SAMLServer{cert: cert, acs: acsURL}
	mux := http.NewServeMux()
	s.http = httptest.NewServer(mux)
	meta, _ := url.Parse(s.http.URL + "/metadata")
	sso, _ := url.Parse(s.http.URL + "/sso")
	s.idp = &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		Logger:                  logger.DefaultLogger,
		MetadataURL:             *meta,
		SSOURL:                  *sso,
		ServiceProviderProvider: s,
		SessionProvider:         s,
	}
	mux.HandleFunc("/metadata", s.idp.ServeMetadata)
	mux.HandleFunc("/sso", s.idp.ServeSSO)
	mux.HandleFunc("/slo", s.serveSLO)
	return s, nil
}

// SLOURL is where a tenant sends logout requests.
func (s *SAMLServer) SLOURL() string { return s.http.URL + "/slo" }

// TrustServiceProvider pins the service provider's signing certificate, as
// a real provider does from the metadata: a logout request not signed by
// it is refused.
func (s *SAMLServer) TrustServiceProvider(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("idptest: not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spCert = cert
	return nil
}

// signer is this provider as a signer of logout messages: the library
// signs through a ServiceProvider value, and only its key, certificate
// and entity id are used here.
func (s *SAMLServer) signer() *saml.ServiceProvider {
	return &saml.ServiceProvider{
		EntityID: s.EntityID(), Key: s.idp.Key.(*rsa.PrivateKey), Certificate: s.cert,
		SignatureMethod: dsig.RSASHA256SignatureMethod,
		IDPMetadata:     &saml.EntityDescriptor{EntityID: s.EntityID()},
	}
}

// serveSLO is the provider's logout endpoint: a signed LogoutRequest from
// the service provider ends the session here and is answered with a
// signed LogoutResponse to the service provider's logout URL, which the
// request's Issuer metadata says. The one the tests use is remembered.
func (s *SAMLServer) serveSLO(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("SAMLResponse") != "" {
		// The service provider answering a logout this provider started.
		s.mu.Lock()
		s.Answered++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("idptest: signed out everywhere"))
		return
	}
	raw, err := inflate(r.URL.Query().Get("SAMLRequest"))
	if err != nil {
		http.Error(w, "idptest: bad logout request: "+err.Error(), http.StatusBadRequest)
		return
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		http.Error(w, "idptest: bad xml", http.StatusBadRequest)
		return
	}
	root := doc.Root()
	s.mu.Lock()
	spCert := s.spCert
	s.mu.Unlock()
	if spCert == nil {
		http.Error(w, "idptest: no service provider certificate pinned; call TrustServiceProvider", http.StatusForbidden)
		return
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{spCert}})
	if _, err := vc.Validate(root); err != nil {
		http.Error(w, "idptest: logout request not signed by the pinned certificate: "+err.Error(), http.StatusForbidden)
		return
	}
	nameID := ""
	if el := root.FindElement("./NameID"); el != nil {
		nameID = el.Text()
	}
	s.mu.Lock()
	s.LoggedOut = append(s.LoggedOut, nameID)
	s.mu.Unlock()
	resp, err := s.signer().MakeLogoutResponse(s.spSLO, root.SelectAttrValue("ID", ""))
	if err != nil {
		http.Error(w, "idptest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, resp.Redirect("").String(), http.StatusFound)
}

// SetServiceProviderSLO is where this provider sends its answers and its
// own logout requests: the tenant's /signout/saml.
func (s *SAMLServer) SetServiceProviderSLO(u string) { s.spSLO = u }

// LogOut is the provider ending a session it started elsewhere: a signed
// LogoutRequest for nameID, addressed to the service provider's logout
// URL, as a redirect for a browser to follow.
func (s *SAMLServer) LogOut(nameID string) (string, error) {
	req, err := s.signer().MakeLogoutRequest(s.spSLO, nameID)
	if err != nil {
		return "", err
	}
	return req.Redirect("").String(), nil
}

// UnsignedLogOut is LogOut without the signature, for the test that
// proves an unsigned request is refused.
func (s *SAMLServer) UnsignedLogOut(nameID string) string {
	sp := s.signer()
	sp.SignatureMethod = ""
	req, _ := sp.MakeLogoutRequest(s.spSLO, nameID)
	return req.Redirect("").String()
}

func inflate(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<20))
}

func (s *SAMLServer) Close() { s.http.Close() }

// EntityID is what a tenant stores as the issuer.
func (s *SAMLServer) EntityID() string { return s.idp.MetadataURL.String() }

// SSOURL is where the browser is sent.
func (s *SAMLServer) SSOURL() string { return s.idp.SSOURL.String() }

// CertificatePEM is what a tenant pastes into the console.
func (s *SAMLServer) CertificatePEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert.Raw}))
}

// SignInAs decides who the next assertion is about.
func (s *SAMLServer) SignInAs(p Person) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.person = p
}

// GetServiceProvider is the library's hook for "who is asking". Any entity
// id is accepted and handed back as its own metadata, with the one
// assertion consumer service this server was told about.
func (s *SAMLServer) GetServiceProvider(_ *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	return &saml.EntityDescriptor{
		EntityID: entityID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			}},
			AssertionConsumerServices: []saml.IndexedEndpoint{{
				Binding: saml.HTTPPostBinding, Location: s.acs, Index: 1,
			}},
		}},
	}, nil
}

// GetSession is the library's hook for "who is signed in here". There is
// no login page: whoever SignInAs named is signed in.
func (s *SAMLServer) GetSession(w http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.person.Subject == "" {
		http.Error(w, "idptest: nobody is signed in; call SignInAs first", http.StatusUnauthorized)
		return nil
	}
	s.Served++
	now := time.Now()
	return &saml.Session{
		ID:               fmt.Sprintf("session-%d", now.UnixNano()),
		CreateTime:       now,
		ExpireTime:       now.Add(time.Hour),
		Index:            "idx",
		NameID:           s.person.Subject,
		NameIDFormat:     string(saml.UnspecifiedNameIDFormat),
		UserEmail:        s.person.Email,
		UserCommonName:   s.person.Name,
		UserName:         s.person.Subject,
		Groups:           s.person.Groups,
		CustomAttributes: s.Attributes,
	}
}
