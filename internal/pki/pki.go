// Package pki is each tenant's own certificate authority: the thing that
// issues the device identity certificates the gateway has been trusting
// since the gateway was written.
//
// One authority per tenant, not one for the platform. With a shared root,
// a certificate issued for Kalesi and one issued for Arbor would be
// cryptographically indistinguishable, and the only thing keeping a device
// out of the wrong tenant would be a string comparison on the organisational
// unit. Separate roots mean a Kalesi certificate does not verify against
// Arbor's authority at all, so the boundary is held by the cryptography
// rather than by our care in comparing fields.
//
// The rule that matters most in this file: a certificate signing request is
// a request for a key to be certified, not a statement of who the holder is.
// Everything in its subject is discarded and the subject is built here from
// what the server already knows. A certificate authority that signs the name
// it was asked to sign is not an authority.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

const (
	// AuthorityLife is long because replacing a tenant's authority means
	// re-enrolling every device it has. Ten years is the usual figure for a
	// private root that is never published.
	AuthorityLife = 10 * 365 * 24 * time.Hour

	// DeviceCertLife is short because a device certificate is a credential
	// held on a machine that can be lost. Renewal is not built, which makes
	// this a limit with a date on it rather than a setting.
	DeviceCertLife = 365 * 24 * time.Hour

	// MinRSABits refuses a key that is too small to be worth signing. A
	// certificate authority that will certify a 1024-bit key is a
	// certificate authority that will certify a forged device.
	MinRSABits = 2048
)

var (
	ErrBadCSR       = errors.New("pki: the certificate signing request is malformed")
	ErrCSRSignature = errors.New("pki: the certificate signing request is not signed by the key it carries")
	ErrWeakKey      = errors.New("pki: the key in the request is too weak to certify")
	ErrNotAnCA      = errors.New("pki: the stored certificate is not a certificate authority")
)

// Authority is one tenant's root, loaded and usable.
type Authority struct {
	cert *x509.Certificate
	key  crypto.Signer
	der  []byte
}

// Created is a brand new authority, with its private key in the form the
// caller has to seal before storing. The key is returned rather than stored
// so that this package never touches the sealing key or the database.
type Created struct {
	Authority  *Authority
	CertDER    []byte
	PrivateDER []byte // PKCS#8, to be sealed by the caller
	Subject    string
	NotBefore  time.Time
	NotAfter   time.Time
}

// Create makes a tenant's authority.
//
// ECDSA P-256 rather than RSA: smaller, faster to generate, and accepted by
// every platform this product manages. One thing to carry forward, since it
// will come up in the Apple sprint: SCEP's PKCS#7 enveloping needs an RSA
// recipient key, so the SCEP registration authority will need an RSA key of
// its own. That is a separate key for a separate job and does not argue for
// making this one RSA.
func Create(tenantID uuid.UUID, tenantName string, now time.Time) (Created, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Created{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return Created{}, err
	}

	// The subject names the tenant, not the operator. T12 applies to a
	// certificate the same as it applies to a page: a device administrator
	// inspecting this in Keychain Access sees their own organisation.
	subject := pkix.Name{
		CommonName:         tenantName + " Device Authority",
		OrganizationalUnit: []string{tenantID.String()},
	}
	notBefore := now.Add(-5 * time.Minute).Truncate(time.Second)
	notAfter := now.Add(AuthorityLife).Truncate(time.Second)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		// MaxPathLen zero: this root signs device certificates and nothing
		// that can itself sign. There are no intermediates and there is no
		// path by which one could be introduced.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return Created{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Created{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Created{}, err
	}
	return Created{
		Authority:  &Authority{cert: cert, key: key, der: der},
		CertDER:    der,
		PrivateDER: pkcs8,
		Subject:    subject.CommonName,
		NotBefore:  notBefore,
		NotAfter:   notAfter,
	}, nil
}

// Load rebuilds an authority from what was stored. The private key arrives
// already unsealed; this package has no opinion about how.
func Load(certDER, privateDER []byte) (*Authority, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, ErrNotAnCA
	}
	k, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("pki: the stored private key cannot sign")
	}
	return &Authority{cert: cert, key: signer, der: certDER}, nil
}

func (a *Authority) CertificateDER() []byte { return a.der }

// CertificatePEM is what a device needs to verify the chain on the
// certificate it has just been given, and what an administrator pins.
func (a *Authority) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.der})
}

func (a *Authority) NotAfter() time.Time { return a.cert.NotAfter }

// Issued is one device certificate and the facts about it worth recording.
type Issued struct {
	DER         []byte
	PEM         []byte
	Serial      string // hex
	Fingerprint []byte // sha256 of the DER
	NotBefore   time.Time
	NotAfter    time.Time
}

// Issue certifies the public key in the request as belonging to one device
// in one tenant.
//
// Read what is taken from the request and what is not. Taken: the public key,
// and nothing else. Not taken: the subject, the requested extensions, the
// subject alternative names, the basic constraints. A request that asks to
// be a certificate authority, or to be a different device, or to be valid
// for a hostname, gets a certificate that says none of those things, because
// the template below is built from arguments rather than from the request.
func (a *Authority) Issue(csrDER []byte, tenantID, deviceID uuid.UUID, now time.Time) (Issued, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return Issued{}, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	// Proof of possession. Without this check a request can carry anyone's
	// public key, and we would hand out a certificate for a key the
	// requester does not hold, to a requester who can then impersonate
	// whoever does.
	if err := csr.CheckSignature(); err != nil {
		return Issued{}, fmt.Errorf("%w: %v", ErrCSRSignature, err)
	}
	if err := checkKeyStrength(csr.PublicKey); err != nil {
		return Issued{}, err
	}

	serial, err := newSerial()
	if err != nil {
		return Issued{}, err
	}
	notBefore := now.Add(-5 * time.Minute).Truncate(time.Second)
	notAfter := now.Add(DeviceCertLife).Truncate(time.Second)
	if notAfter.After(a.cert.NotAfter) {
		// A device certificate outliving its own authority would verify
		// today and fail on a date nobody has written down.
		notAfter = a.cert.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// This is the shape the gateway reads: tenant in the organisational
		// unit, device in the common name. It is written here, from
		// arguments, which is the only place it can be written and still be
		// true.
		Subject: pkix.Name{
			CommonName:         deviceID.String(),
			OrganizationalUnit: []string{tenantID.String()},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		// Client authentication and nothing else. Not ServerAuth: a device
		// certificate that can stand up a TLS server is a device
		// certificate that can be used to impersonate this platform to
		// another device on the same network.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return Issued{}, err
	}
	sum := sha256.Sum256(der)
	return Issued{
		DER:         der,
		PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:      serial.Text(16),
		Fingerprint: sum[:],
		NotBefore:   notBefore,
		NotAfter:    notAfter,
	}, nil
}

// Fingerprint is how a presented certificate is matched against what we
// issued. It is in this package so that the issuing side and the checking
// side cannot drift apart on what they are hashing.
func Fingerprint(der []byte) []byte {
	sum := sha256.Sum256(der)
	return sum[:]
}

func checkKeyStrength(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return fmt.Errorf("%w: %d-bit RSA, the minimum is %d",
				ErrWeakKey, k.N.BitLen(), MinRSABits)
		}
		return nil
	case *ecdsa.PublicKey:
		// P-256 and above. P-224 is still in the standard library and is
		// below what anyone should be certifying in 2026.
		if k.Curve.Params().BitSize < 256 {
			return fmt.Errorf("%w: %s", ErrWeakKey, k.Curve.Params().Name)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrWeakKey, pub)
	}
}

// newSerial is 128 bits of randomness rather than a counter.
//
// A counter has to be stored, has to be incremented atomically, and leaks
// how many devices a tenant has enrolled to anyone who sees two
// certificates. RFC 5280 asks for a positive integer of at most 20 octets;
// this is 16, and the database carries a uniqueness constraint that would
// catch a collision rather than trusting that one cannot happen.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	// Zero is not a valid serial number, and a negative one is not
	// representable here, so the only case to handle is zero.
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n, nil
}
