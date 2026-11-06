package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	tenantA = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	deviceA = uuid.MustParse("aaaaaaaa-0000-4000-8000-000000000001")
	deviceB = uuid.MustParse("bbbbbbbb-0000-4000-8000-000000000002")
)

func authority(t *testing.T, tenant uuid.UUID, name string) *Authority {
	t.Helper()
	c, err := Create(tenant, name, time.Now().UTC())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return c.Authority
}

// csr builds a request the way a device agent would, with whatever subject
// the caller wants to try asking for.
func csr(t *testing.T, subject pkix.Name, dns []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject, DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return der
}

func plainCSR(t *testing.T) []byte {
	return csr(t, pkix.Name{CommonName: "whatever-the-device-called-itself"}, nil)
}

func issue(t *testing.T, a *Authority, der []byte, tenant, device uuid.UUID) *x509.Certificate {
	t.Helper()
	got, err := a.Issue(der, tenant, device, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cert, err := x509.ParseCertificate(got.DER)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

// ---------------------------------------------------------------- the root

func TestTheAuthorityIsARootThatCannotDelegate(t *testing.T) {
	c, err := Create(tenantA, "Kalesi Device Care", time.Now().UTC())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cert, err := x509.ParseCertificate(c.CertDER)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatal("the authority is not marked as one")
	}
	// Path length zero: it signs devices, never another authority. Without
	// this, a device certificate could in principle be made to sign others.
	if cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Fatalf("path length is %d, want a hard zero", cert.MaxPathLen)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("the authority cannot sign certificates")
	}
	// T12 reaches the certificate too: a device administrator opening this
	// in Keychain Access sees their own organisation, not ours.
	if cert.Subject.CommonName != "Kalesi Device Care Device Authority" {
		t.Fatalf("subject is %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.OrganizationalUnit) != 1 ||
		cert.Subject.OrganizationalUnit[0] != tenantA.String() {
		t.Fatalf("the authority does not name its tenant: %v", cert.Subject.OrganizationalUnit)
	}
}

func TestAnAuthorityRoundTripsThroughStorage(t *testing.T) {
	c, err := Create(tenantA, "Kalesi", time.Now().UTC())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	loaded, err := Load(c.CertDER, c.PrivateDER)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// It still signs, which is the only property that matters after a
	// restart.
	if _, err := loaded.Issue(plainCSR(t), tenantA, deviceA, time.Now().UTC()); err != nil {
		t.Fatalf("a reloaded authority could not issue: %v", err)
	}
}

func TestSomethingThatIsNotAnAuthorityIsRefusedAtLoad(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	got, err := a.Issue(plainCSR(t), tenantA, deviceA, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// A device certificate put in the authority column.
	if _, err := Load(got.DER, nil); !errors.Is(err, ErrNotAnCA) {
		t.Fatalf("got %v, want ErrNotAnCA", err)
	}
}

// ------------------------------------------------- a request is a request

// The single most important test in this package. A certificate signing
// request carries a subject because the format has a field for one, not
// because the requester gets to decide it.
func TestTheRequestedSubjectIsDiscarded(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")

	// A device asking to be a different device, in a different tenant, with
	// an organisation of its choosing and a hostname attached.
	asked := csr(t, pkix.Name{
		CommonName:         deviceB.String(),
		OrganizationalUnit: []string{tenantB.String()},
		Organization:       []string{"Definitely The Administrators"},
		Country:            []string{"ZZ"},
	}, []string{"mdm.kalesi.example", "localhost"})

	cert := issue(t, a, asked, tenantA, deviceA)

	if cert.Subject.CommonName != deviceA.String() {
		t.Fatalf("the certificate names %q, the request asked for %q",
			cert.Subject.CommonName, deviceB)
	}
	if len(cert.Subject.OrganizationalUnit) != 1 ||
		cert.Subject.OrganizationalUnit[0] != tenantA.String() {
		t.Fatalf("tenant is %v, the request asked for %s",
			cert.Subject.OrganizationalUnit, tenantB)
	}
	if len(cert.Subject.Organization) != 0 || len(cert.Subject.Country) != 0 {
		t.Fatalf("fields from the request survived: %+v", cert.Subject)
	}
	// A subject alternative name would make this certificate usable to
	// impersonate the platform's own hostname.
	if len(cert.DNSNames) != 0 {
		t.Fatalf("requested hostnames survived: %v", cert.DNSNames)
	}
}

func TestADeviceCannotAskToBecomeAnAuthority(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	cert := issue(t, a, plainCSR(t), tenantA, deviceA)

	if cert.IsCA {
		t.Fatal("a device certificate came back able to sign others")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("a device certificate may sign certificates")
	}
}

// Client authentication only. A device certificate that can stand up a TLS
// server is one that can impersonate this platform to another device on the
// same network.
func TestADeviceCertificateCannotServe(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	cert := issue(t, a, plainCSR(t), tenantA, deviceA)

	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("extended key usage is %v, want client authentication only", cert.ExtKeyUsage)
	}
}

// Proof of possession. Without it, a request can carry anyone's public key
// and we certify a key the requester does not hold.
func TestARequestNotSignedByItsOwnKeyIsRefused(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")

	// Build it with a common name of known bytes, then change those bytes.
	// The structure stays valid DER and the signature no longer covers it,
	// which is exactly the tampering this check exists for.
	der := csr(t, pkix.Name{CommonName: "aaaaaaaaaaaaaaaa"}, nil)
	tampered := bytes.Replace(der, []byte("aaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbb"), 1)
	if bytes.Equal(der, tampered) {
		t.Fatal("the test did not manage to tamper with anything")
	}

	if _, err := a.Issue(tampered, tenantA, deviceA, time.Now().UTC()); !errors.Is(err, ErrCSRSignature) {
		t.Fatalf("got %v, want ErrCSRSignature", err)
	}
}

func TestRubbishIsRefusedAsARequest(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	for name, in := range map[string][]byte{
		"empty":     {},
		"text":      []byte("please give me a certificate"),
		"truncated": plainCSR(t)[:20],
	} {
		if _, err := a.Issue(in, tenantA, deviceA, time.Now().UTC()); !errors.Is(err, ErrBadCSR) {
			t.Fatalf("%s: got %v, want ErrBadCSR", name, err)
		}
	}
}

func TestAWeakKeyIsNotCertified(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, weak)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	if _, err := a.Issue(der, tenantA, deviceA, time.Now().UTC()); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("got %v, want ErrWeakKey", err)
	}
}

func TestAStrongRSAKeyIsCertified(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	// Devices do turn up with RSA, and SCEP will bring more of them.
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, strong)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	if _, err := a.Issue(der, tenantA, deviceA, time.Now().UTC()); err != nil {
		t.Fatalf("a 2048-bit RSA key was refused: %v", err)
	}
}

// ------------------------------------------------------- the trust boundary

// The reason there is an authority per tenant rather than one for the
// platform. With a shared root this test could not exist: a Kalesi
// certificate and an Arbor certificate would both verify, and the only thing
// keeping them apart would be our care in comparing a string.
func TestOneTenantsCertificateDoesNotVerifyAgainstAnothersAuthority(t *testing.T) {
	kalesi := authority(t, tenantA, "Kalesi")
	arbor := authority(t, tenantB, "Arbor")

	cert := issue(t, kalesi, plainCSR(t), tenantA, deviceA)

	ownPool := x509.NewCertPool()
	ownCert, err := x509.ParseCertificate(kalesi.CertificateDER())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ownPool.AddCert(ownCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: ownPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("a certificate did not verify against its own authority: %v", err)
	}

	otherPool := x509.NewCertPool()
	otherCert, err := x509.ParseCertificate(arbor.CertificateDER())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	otherPool.AddCert(otherCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: otherPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("a Kalesi certificate verified against Arbor's authority")
	}
}

// ---------------------------------------------------------------- details

func TestSerialNumbersAreUnpredictableAndUnique(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		got, err := a.Issue(plainCSR(t), tenantA, deviceA, time.Now().UTC())
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if seen[got.Serial] {
			t.Fatalf("serial %s was issued twice", got.Serial)
		}
		seen[got.Serial] = true
		// A counter would leak how many devices a tenant has enrolled.
		if len(got.Serial) < 24 {
			t.Fatalf("serial %q is too short to be 128 bits of randomness", got.Serial)
		}
	}
}

// A device certificate outliving its own authority would verify today and
// fail on a date nobody has written down.
func TestADeviceCertificateNeverOutlivesItsAuthority(t *testing.T) {
	// An authority almost at its end: make one in the past so that the
	// device certificate's natural year would overshoot it.
	long := time.Now().UTC().Add(-AuthorityLife + 24*time.Hour)
	c, err := Create(tenantA, "Kalesi", long)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := c.Authority.Issue(plainCSR(t), tenantA, deviceA, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got.NotAfter.After(c.NotAfter) {
		t.Fatalf("device certificate expires %v, its authority %v", got.NotAfter, c.NotAfter)
	}
}

func TestTheFingerprintIsTheHashOfTheCertificateWeIssued(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	got, err := a.Issue(plainCSR(t), tenantA, deviceA, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// The gateway recomputes this from the bytes a device presents. If the
	// two sides ever disagreed, every device would be refused, so they are
	// the same function.
	if !bytes.Equal(got.Fingerprint, Fingerprint(got.DER)) {
		t.Fatal("the recorded fingerprint is not the one the gateway will compute")
	}
	if len(got.Fingerprint) != 32 {
		t.Fatalf("fingerprint is %d bytes", len(got.Fingerprint))
	}
}

func TestTheIssuedCertificateIsValidFromSlightlyInThePast(t *testing.T) {
	a := authority(t, tenantA, "Kalesi")
	now := time.Now().UTC()
	got, err := a.Issue(plainCSR(t), tenantA, deviceA, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Clock skew between here and a laptop is normal and is not a reason to
	// refuse a device the moment it enrols.
	if !got.NotBefore.Before(now) {
		t.Fatalf("not valid until %v, which is not before %v", got.NotBefore, now)
	}
}
