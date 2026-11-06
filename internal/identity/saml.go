package identity

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// The two protocols a tenant's identity provider can speak. OIDC is the
// default and covers Entra, Google, Okta, Ping and Keycloak; SAML is for
// the providers that predate it (ADFS, Shibboleth) and for the tenants
// whose security team has a SAML application already approved and will not
// approve a second one.
const (
	ProtocolOIDC = "oidc"
	ProtocolSAML = "saml"
	// ProtocolLocal is no provider at all: accounts held in the platform,
	// with a password and a second factor (0044).
	ProtocolLocal = "local"
)

var (
	ErrSAMLResponse   = errors.New("identity: the SAML response did not pass our checks")
	ErrWrongProtocol  = errors.New("identity: this tenant signs in with a different protocol")
	ErrBadCertificate = errors.New("identity: that is not an X.509 certificate")
)

// SAML is the second adapter behind the same shape as OIDC. It holds no
// per-tenant state: every call takes the tenant's Config, so nothing about
// one tenant can be read by the next request.
//
// What it does, and what the library underneath does for it: the assertion
// must be signed by the certificate the tenant pasted (or the whole
// response must be), it must name OUR entity id as its audience, it must be
// in response to a request THIS browser started, it must be addressed to
// our assertion consumer service, and its validity window must contain now.
// An unsolicited assertion (identity-provider-initiated sign-in) is refused
// outright: it has no request to answer, which makes it a replay with a
// different name.
//
// Verified 2026-11-05: github.com/crewjam/saml v0.5.1, which carries the
// fixes for CVE-2020-27846 (signature bypass) and CVE-2022-41912 (multiple
// assertions); the response is run through the XML round-trip validator
// before parsing so a signature-wrapping document is rejected whole.
type SAML struct{}

func NewSAML() *SAML { return &SAML{} }

// ParseCertificate accepts what identity providers hand out: a PEM block,
// or the bare base64 that Entra calls "Certificate (Base64)" and Okta shows
// in a text box. It returns the certificate and its normalised PEM form,
// which is what gets stored.
func ParseCertificate(text string) (*x509.Certificate, string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, "", ErrBadCertificate
	}
	var der []byte
	if block, _ := pem.Decode([]byte(text)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, "", fmt.Errorf("%w: the PEM block is a %s", ErrBadCertificate, block.Type)
		}
		der = block.Bytes
	} else {
		stripped := regexp.MustCompile(`\s+`).ReplaceAllString(text, "")
		b, err := base64.StdEncoding.DecodeString(stripped)
		if err != nil {
			return nil, "", fmt.Errorf("%w: neither PEM nor base64", ErrBadCertificate)
		}
		der = b
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrBadCertificate, err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return cert, string(out), nil
}

// provider builds the library's service provider for one tenant from its
// Config. Nothing is fetched: the identity provider's metadata is assembled
// from the three things the tenant typed, so a provider that is down does
// not stop us building a request to it, and one that is lying about itself
// cannot replace the certificate the tenant pinned.
func (s *SAML) provider(cfg Config) (*saml.ServiceProvider, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Protocol != ProtocolSAML {
		return nil, ErrWrongProtocol
	}
	cert, _, err := ParseCertificate(cfg.SAMLCertificate)
	if err != nil {
		return nil, err
	}
	acs, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("identity: bad assertion consumer url: %w", err)
	}
	meta, err := url.Parse(cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("identity: bad entity id: %w", err)
	}
	slo, err := sloURL(cfg)
	if err != nil {
		return nil, fmt.Errorf("identity: bad entity id: %w", err)
	}
	sp := &saml.ServiceProvider{
		EntityID:    cfg.ClientID,
		MetadataURL: *meta,
		AcsURL:      *acs,
		SloURL:      *slo,
		// Unspecified lets the provider send the identifier it is set up
		// to send (Entra: a persistent pairwise id; Okta: the username).
		// Transient, the library's default, would hand us a different
		// subject every sign-in, and seats, sign-out-per-person and the
		// audit trail all key on the subject.
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
		AllowIDPInitiated: false,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: cfg.Issuer,
			IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{
					KeyDescriptors: []saml.KeyDescriptor{{
						Use: "signing",
						KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{
							Data: base64.StdEncoding.EncodeToString(cert.Raw),
						}}}},
					}},
				}},
				SingleSignOnServices: []saml.Endpoint{{
					Binding: saml.HTTPRedirectBinding, Location: cfg.SAMLSSOURL,
				}},
			}},
		},
	}
	// Our own signing key (0043): with it, our logout requests and
	// responses are signed, and our metadata carries the certificate the
	// provider verifies them with. Without it, sign-in still works and
	// single logout is simply not offered.
	if cfg.SAMLSigningKey != "" && cfg.SAMLSigningCert != "" {
		key, err := parseSigningKey(cfg.SAMLSigningKey)
		if err != nil {
			return nil, err
		}
		cert, _, err := ParseCertificate(cfg.SAMLSigningCert)
		if err != nil {
			return nil, err
		}
		sp.Key, sp.Certificate, sp.SignatureMethod = key, cert, dsig.RSASHA256SignatureMethod
	}
	if cfg.SAMLSLOURL != "" {
		sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = []saml.Endpoint{{
			Binding: saml.HTTPRedirectBinding, Location: cfg.SAMLSLOURL,
		}}
		// And our own logout endpoint goes into our metadata, by the
		// redirect binding, which is the one both directions use.
		sp.LogoutBindings = []string{saml.HTTPRedirectBinding}
	}
	return sp, nil
}

// AuthURL is where the browser goes to sign in, and the id of the request
// it carries. The id is what the assertion must answer, so the caller holds
// it in the signed flow cookie exactly as OIDC holds its state.
func (s *SAML) AuthURL(cfg Config) (redirect string, requestID string, err error) {
	sp, err := s.provider(cfg)
	if err != nil {
		return "", "", err
	}
	req, err := sp.MakeAuthenticationRequest(cfg.SAMLSSOURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("identity: could not build the sign-in request: %w", err)
	}
	u, err := req.Redirect("", sp)
	if err != nil {
		return "", "", fmt.Errorf("identity: could not build the sign-in redirect: %w", err)
	}
	return u.String(), req.ID, nil
}

// Consume turns the posted SAMLResponse into a verified identity. requestID
// is the one AuthURL handed out for this browser; a response answering any
// other request, or none, is refused.
func (s *SAML) Consume(cfg Config, encoded, requestID string) (Claims, error) {
	sp, err := s.provider(cfg)
	if err != nil {
		return Claims{}, err
	}
	if requestID == "" {
		return Claims{}, fmt.Errorf("%w: no sign-in request to answer", ErrSAMLResponse)
	}
	raw, err := base64.StdEncoding.DecodeString(regexp.MustCompile(`\s+`).ReplaceAllString(encoded, ""))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: the response is not base64", ErrSAMLResponse)
	}
	a, err := sp.ParseXMLResponse(raw, []string{requestID}, sp.AcsURL)
	if err != nil {
		// The library's public error says only "authentication failed";
		// the reason is on the private side so it never reaches a browser.
		// It belongs in our log, where the tenant's administrator will be
		// asking about it.
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return Claims{}, fmt.Errorf("%w: %v", ErrSAMLResponse, ire.PrivateErr)
		}
		return Claims{}, fmt.Errorf("%w: %v", ErrSAMLResponse, err)
	}
	return claimsFromAssertion(a, cfg.RoleClaim)
}

// Metadata is our half of the handshake: the document the tenant's
// administrator uploads to their identity provider so it knows our entity
// id and where to post assertions.
func (s *SAML) Metadata(cfg Config) ([]byte, error) {
	sp, err := s.provider(cfg)
	if err != nil {
		return nil, err
	}
	out, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// Attribute names providers use for the same three facts. SAML never agreed
// on a vocabulary: Entra and ADFS use the schemas.xmlsoap.org claim URIs,
// Shibboleth and most European federations use urn:oid, Okta and Google
// use whatever the administrator typed. Matching the known spellings, by
// full name or friendly name, means a tenant maps groups and nothing else.
var (
	emailAttrs = []string{
		"email", "mail", "emailaddress",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"urn:oid:0.9.2342.19200300.100.1.3",
	}
	nameAttrs = []string{
		"displayName", "displayname", "name", "cn",
		"http://schemas.microsoft.com/identity/claims/displayname",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"urn:oid:2.5.4.3",
	}
	// Entra's group claim, accepted when the tenant left the attribute
	// name at its default: it is the one spelling every Entra SAML
	// application emits, and asking an administrator to paste a 60
	// character URI to get the default behaviour is a support ticket.
	entraGroups = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
)

func claimsFromAssertion(a *saml.Assertion, roleClaim string) (Claims, error) {
	if a == nil || a.Subject == nil || a.Subject.NameID == nil || a.Subject.NameID.Value == "" {
		return Claims{}, fmt.Errorf("%w: the assertion names no subject", ErrSAMLResponse)
	}
	attrs := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			var vals []string
			for _, v := range at.Values {
				if s := strings.TrimSpace(v.Value); s != "" {
					vals = append(vals, s)
				}
			}
			for _, key := range []string{at.Name, at.FriendlyName} {
				if key != "" {
					attrs[key] = append(attrs[key], vals...)
				}
			}
		}
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := attrs[k]; len(v) > 0 {
				return v[0]
			}
		}
		return ""
	}
	c := Claims{
		Subject: a.Subject.NameID.Value,
		Email:   first(emailAttrs...),
		Name:    first(nameAttrs...),
	}
	if c.Email == "" && a.Subject.NameID.Format == string(saml.EmailAddressNameIDFormat) {
		c.Email = a.Subject.NameID.Value
	}
	if roleClaim == "" {
		roleClaim = "groups"
	}
	c.Groups = attrs[roleClaim]
	if len(c.Groups) == 0 && roleClaim == "groups" {
		c.Groups = attrs[entraGroups]
	}
	return c, nil
}
