package identity

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

// Single logout (0043). Two directions.
//
// Ours: sign-out sends the browser to the provider with a LogoutRequest we
// signed, naming the person's NameID; the provider ends its session and
// sends the browser back to our logout endpoint with a signed
// LogoutResponse that has to answer the request we made.
//
// Theirs: the provider, ending a session it started elsewhere, sends the
// browser to our logout endpoint with a signed LogoutRequest; we verify
// the signature against the certificate the tenant pinned, end our
// session, and send the browser back with a LogoutResponse.
//
// Both need a key of our own to sign with, which is why 0043 gives each
// tenant one. A provider that cannot verify our signature refuses our
// request, and a logout that is refused is a sign-out that looks finished
// and is not.

var ErrSAMLLogout = errors.New("identity: the SAML logout message did not pass our checks")

// GenerateSigningKey makes a tenant's own SAML signing key and a
// self-signed certificate for it: ten years, the console's hostname as
// its name. Self-signed is what every provider expects of a service
// provider's signing certificate; it is pinned by exchange of metadata,
// not by a chain.
func GenerateSigningKey(host string, now time.Time) (keyPEM, certPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, OrganizationalUnit: []string{"SAML signing"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func parseSigningKey(keyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("identity: the signing key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("identity: the signing key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// sloURL is our single logout endpoint, beside the metadata and the
// assertion consumer service on the same hostname.
func sloURL(cfg Config) (*url.URL, error) {
	u, err := url.Parse(cfg.ClientID)
	if err != nil {
		return nil, err
	}
	u.Path, u.RawQuery = "/signout/saml", ""
	return u, nil
}

// CanLogout says whether this tenant can take part in single logout: the
// provider's logout URL is known and we have a key to sign with.
func (cfg Config) CanLogout() bool {
	return cfg.IsSAML() && cfg.SAMLSLOURL != "" && cfg.SAMLSigningKey != "" && cfg.SAMLSigningCert != ""
}

// LogoutURL is where the browser goes to sign out at the provider, and
// the id of the request it carries, which the provider's answer has to
// name.
func (s *SAML) LogoutURL(cfg Config, nameID string) (redirect, requestID string, err error) {
	if !cfg.CanLogout() {
		return "", "", fmt.Errorf("%w: this tenant has no logout URL or signing key", ErrSAMLLogout)
	}
	if nameID == "" {
		return "", "", fmt.Errorf("%w: no subject to sign out", ErrSAMLLogout)
	}
	sp, err := s.provider(cfg)
	if err != nil {
		return "", "", err
	}
	req, err := sp.MakeLogoutRequest(cfg.SAMLSLOURL, nameID)
	if err != nil {
		return "", "", fmt.Errorf("identity: could not build the logout request: %w", err)
	}
	return req.Redirect("").String(), req.ID, nil
}

// logoutResponse is the little of a LogoutResponse this code reads itself:
// the library verifies the signature, the issuer, the destination and the
// status, and leaves which request it answers to the caller.
type logoutResponse struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	InResponseTo string   `xml:"InResponseTo,attr"`
}

// FinishLogout checks the provider's answer to the request LogoutURL made.
func (s *SAML) FinishLogout(cfg Config, encoded, requestID string) error {
	if !cfg.CanLogout() {
		return fmt.Errorf("%w: this tenant has no logout URL or signing key", ErrSAMLLogout)
	}
	if requestID == "" {
		return fmt.Errorf("%w: no logout request to answer", ErrSAMLLogout)
	}
	sp, err := s.provider(cfg)
	if err != nil {
		return err
	}
	if err := sp.ValidateLogoutResponseRedirect(encoded); err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return fmt.Errorf("%w: %v", ErrSAMLLogout, ire.PrivateErr)
		}
		return fmt.Errorf("%w: %v", ErrSAMLLogout, err)
	}
	raw, err := inflate(encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSAMLLogout, err)
	}
	var resp logoutResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("%w: %v", ErrSAMLLogout, err)
	}
	if resp.InResponseTo != requestID {
		return fmt.Errorf("%w: the response answers request %q, not ours", ErrSAMLLogout, resp.InResponseTo)
	}
	return nil
}

// ProviderLogoutRequest is the provider telling us the person has signed
// out elsewhere. The request has to be signed by the certificate the
// tenant pinned, come from the provider's entity id, and be addressed to
// our logout endpoint. It returns the request's id, for the answer, and
// the NameID it names. The control --break-slosig takes it unsigned.
func (s *SAML) ProviderLogoutRequest(cfg Config, encoded string) (requestID, nameID string, err error) {
	if !cfg.CanLogout() {
		return "", "", fmt.Errorf("%w: this tenant has no logout URL or signing key", ErrSAMLLogout)
	}
	idpCert, _, err := ParseCertificate(cfg.SAMLCertificate)
	if err != nil {
		return "", "", err
	}
	raw, err := inflate(encoded)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrSAMLLogout, err)
	}
	// The same round-trip check the library runs on an assertion, so a
	// document that parses one way and canonicalises another is refused
	// whole.
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrSAMLLogout, err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrSAMLLogout, err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "LogoutRequest" {
		return "", "", fmt.Errorf("%w: not a LogoutRequest", ErrSAMLLogout)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idpCert}})
	if _, err := vc.Validate(root); err != nil {
		return "", "", fmt.Errorf("%w: the logout request is not signed by the provider's certificate: %v", ErrSAMLLogout, err)
	}
	ours, err := sloURL(cfg)
	if err != nil {
		return "", "", err
	}
	if dest := root.SelectAttrValue("Destination", ""); dest != ours.String() {
		return "", "", fmt.Errorf("%w: addressed to %q, not to us", ErrSAMLLogout, dest)
	}
	if iss := root.FindElement("./Issuer"); iss == nil || strings.TrimSpace(iss.Text()) != cfg.Issuer {
		return "", "", fmt.Errorf("%w: not from this tenant's provider", ErrSAMLLogout)
	}
	requestID = root.SelectAttrValue("ID", "")
	if nid := root.FindElement("./NameID"); nid != nil {
		nameID = strings.TrimSpace(nid.Text())
	}
	if requestID == "" || nameID == "" {
		return "", "", fmt.Errorf("%w: the logout request names no id or no subject", ErrSAMLLogout)
	}
	return requestID, nameID, nil
}

// LogoutResponseURL is our signed answer to the provider's request, sent
// as a redirect to its logout URL.
func (s *SAML) LogoutResponseURL(cfg Config, requestID string) (string, error) {
	sp, err := s.provider(cfg)
	if err != nil {
		return "", err
	}
	resp, err := sp.MakeLogoutResponse(cfg.SAMLSLOURL, requestID)
	if err != nil {
		return "", fmt.Errorf("identity: could not build the logout response: %w", err)
	}
	return resp.Redirect("").String(), nil
}

// inflate undoes the redirect binding's encoding: base64, then DEFLATE,
// capped at a megabyte so a tiny message cannot expand into a large one.
func inflate(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.New("not base64")
	}
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<20))
	if err != nil {
		return nil, fmt.Errorf("not deflated: %v", err)
	}
	return out, nil
}
