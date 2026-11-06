package notify

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// ---------------------------------------------------------------- the key

func newIdentity(t *testing.T, domain string) (*SenderIdentity, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("public: %v", err)
	}
	return &SenderIdentity{
		Domain: domain, Selector: DKIMSelector,
		From: "notifications@" + domain, PrivateKey: key,
	}, base64.StdEncoding.EncodeToString(pub)
}

// ------------------------------------------------------------- signing

// The signature has to actually verify. go-msgauth signs it and go-msgauth
// verifies it, which is not independent, and the honest mitigation is the
// tampering tests below: a signature that survives a changed body is
// decorative, and these prove this one is not.
func TestTheSignatureVerifiesAgainstThePublishedKey(t *testing.T) {
	id, public := newIdentity(t, "kalesi.example")
	e := Email{From: "operator@example.net"}

	msg, err := e.Compose([]string{"security@kalesi.example"},
		Message{Topic: DeviceLost, Subject: "HQ-MBP-002 was reported lost",
			Body: "t.eze reported it lost", Tenant: "Kalesi Device Care", Sender: id})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	signed, err := sign(msg, id)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !bytes.Contains(signed, []byte("DKIM-Signature:")) {
		t.Fatalf("no signature header:\n%s", signed)
	}

	verifyOK(t, signed, "kalesi.example", public)
}

// verifyOK checks the signature with the published key, resolving DNS from
// a map rather than the internet.
func verifyOK(t *testing.T, msg []byte, domain, public string) {
	t.Helper()
	res, err := dkim.VerifyWithOptions(bytes.NewReader(msg), &dkim.VerifyOptions{
		LookupTXT: func(name string) ([]string, error) {
			want := DKIMSelector + "._domainkey." + domain
			if strings.TrimSuffix(name, ".") != want {
				return nil, errors.New("no such record: " + name)
			}
			return []string{"v=DKIM1; k=rsa; p=" + public}, nil
		},
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d verifications", len(res))
	}
	if res[0].Err != nil {
		t.Fatalf("the signature did not verify: %v", res[0].Err)
	}
	if res[0].Domain != domain {
		t.Fatalf("signed as %s, want %s", res[0].Domain, domain)
	}
}

// The tests that prove the signature is doing work rather than decorating
// the message.
func TestATamperedMessageDoesNotVerify(t *testing.T) {
	id, public := newIdentity(t, "kalesi.example")
	e := Email{From: "operator@example.net"}
	msg, err := e.Compose([]string{"security@kalesi.example"},
		Message{Subject: "HQ-MBP-002 was reported lost",
			Body: "t.eze reported it lost", Sender: id})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	signed, err := sign(msg, id)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifyOK(t, signed, "kalesi.example", public)

	tampered := map[string][]byte{
		"the body changed": bytes.Replace(signed,
			[]byte("t.eze reported it lost"),
			[]byte("t.eze reported it FOUND"), 1),
		"the subject changed": bytes.Replace(signed,
			[]byte("Subject: HQ-MBP-002 was reported lost"),
			[]byte("Subject: Nothing to worry about"), 1),
		"the sender changed": bytes.Replace(signed,
			[]byte("notifications@kalesi.example"),
			[]byte("attacker@elsewhere.example"), 1),
	}
	for name, bad := range tampered {
		res, err := dkim.VerifyWithOptions(bytes.NewReader(bad), &dkim.VerifyOptions{
			LookupTXT: func(string) ([]string, error) {
				return []string{"v=DKIM1; k=rsa; p=" + public}, nil
			},
		})
		if err == nil && len(res) == 1 && res[0].Err == nil {
			t.Fatalf("%s: the signature still verified", name)
		}
	}
}

// A signature that does not cover From is one an attacker can lift onto a
// message of their own.
func TestTheSignatureCoversTheSender(t *testing.T) {
	id, _ := newIdentity(t, "kalesi.example")
	e := Email{From: "operator@example.net"}
	msg, _ := e.Compose([]string{"a@kalesi.example"}, Message{Subject: "x", Sender: id})
	signed, err := sign(msg, id)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	header := string(signed[:bytes.Index(signed, []byte("\r\n\r\n"))])
	var h string
	for _, line := range strings.Split(header, "\r\n") {
		if strings.HasPrefix(line, "DKIM-Signature:") || strings.HasPrefix(line, " ") {
			h += line
		}
	}
	if !strings.Contains(strings.ToLower(h), "from") {
		t.Fatalf("From is not in the signed headers: %s", h)
	}
	if !strings.Contains(h, "d=kalesi.example") {
		t.Fatalf("signed as the wrong domain: %s", h)
	}
	if !strings.Contains(h, "s="+DKIMSelector) {
		t.Fatalf("wrong selector: %s", h)
	}
}

// Alignment is the whole point. A message signed as one domain and sent
// from another has a valid signature and still fails DMARC.
func TestTheSenderAddressMatchesTheSignedDomain(t *testing.T) {
	id, _ := newIdentity(t, "kalesi.example")
	// The operator's own From, which must be overridden by the tenant's.
	e := Email{From: "notifications@mdmoperator.example"}
	msg, err := e.Compose([]string{"a@kalesi.example"}, Message{Subject: "x", Sender: id})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	if !bytes.Contains(msg, []byte("notifications@kalesi.example")) {
		t.Fatalf("the message is not from the tenant's domain:\n%s", msg)
	}
	if bytes.Contains(msg, []byte("mdmoperator.example")) {
		t.Fatalf("the operator's address survived into a tenant's mail:\n%s", msg)
	}
}

// A tenant with no verified domain gets what they had before: an unsigned
// message from the operator's address. Signing as a domain nobody proved
// would be the alternative.
func TestNoVerifiedDomainMeansNoSignature(t *testing.T) {
	e := Email{From: "notifications@mdmoperator.example"}
	msg, err := e.Compose([]string{"a@kalesi.example"}, Message{Subject: "x"})
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	signed, err := sign(msg, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if bytes.Contains(signed, []byte("DKIM-Signature")) {
		t.Fatal("an unverified tenant's mail was signed")
	}
	if !bytes.Contains(signed, []byte("notifications@mdmoperator.example")) {
		t.Fatal("the fallback address was not used")
	}
}

// ---------------------------------------------------------------- records

func TestTheRecordIsWhatATenantHasToPublish(t *testing.T) {
	d := SendingDomain{Domain: "kalesi.example", Selector: "mdm",
		PublicKey: strings.Repeat("A", 392)}

	if got := d.RecordName(); got != "mdm._domainkey.kalesi.example" {
		t.Fatalf("record name is %q", got)
	}
	if !strings.HasPrefix(d.RecordValue(), "v=DKIM1; k=rsa; p=") {
		t.Fatalf("record value is %q", d.RecordValue())
	}

	// A TXT string is limited to 255 characters and a 2048-bit key is about
	// four hundred, so the record has to be published as several quoted
	// strings. Administrators meet this once, usually by the record
	// silently not working.
	parts := d.RecordValueSplit()
	if len(parts) < 2 {
		t.Fatalf("a long key was not split: %d part(s)", len(parts))
	}
	for i, p := range parts {
		if len(p) > 255 {
			t.Fatalf("part %d is %d characters", i, len(p))
		}
	}
	if strings.Join(parts, "") != d.RecordValue() {
		t.Fatal("the split parts do not rejoin into the record")
	}
}

// The question every administrator asks on that page, answered where they
// will ask it.
func TestTheConsoleExplainsWhyThereIsNoSpfRecord(t *testing.T) {
	for _, want := range []string{"SPF", "DKIM", "bounces"} {
		if !strings.Contains(WhyNoSPFRecord, want) {
			t.Fatalf("the explanation does not mention %q", want)
		}
	}
}

// ---------------------------------------------------------------- domains

func TestOnlySomethingThatLooksLikeADomainIsAccepted(t *testing.T) {
	good := map[string]string{
		"kalesi.example":       "kalesi.example",
		"  Kalesi.Example  ":   "kalesi.example",
		"mail.kalesi.example.": "mail.kalesi.example",
		"a.b.c.d.example":      "a.b.c.d.example",
	}
	for in, want := range good {
		got, err := cleanDomain(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q gave %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"", "   ", "localhost", "kalesi", "a@kalesi.example",
		"https://kalesi.example", "kalesi.example/path", ".kalesi.example",
		"kalesi..example", "kalesi.example:25", "has space.example",
		strings.Repeat("a", 64) + ".example",
	} {
		if got, err := cleanDomain(bad); err == nil {
			t.Fatalf("%q was accepted as %q", bad, got)
		}
	}
}

func TestTheKeyIsReadOutOfARecordHoweverItIsFormatted(t *testing.T) {
	key := strings.Repeat("A", 40)
	for _, record := range []string{
		"v=DKIM1; k=rsa; p=" + key,
		"v=DKIM1;k=rsa;p=" + key,
		"v=DKIM1; k=rsa; p=" + key + ";",
		"k=rsa; p=" + key + "; t=s",
		// Some DNS consoles fold a long value with whitespace.
		"v=DKIM1; k=rsa; p=" + key[:20] + " " + key[20:],
	} {
		if got := keyIn(record); got != key {
			t.Fatalf("%q gave %q", record, got)
		}
	}
	if got := keyIn("v=DKIM1; k=rsa"); got != "" {
		t.Fatalf("a record with no key gave %q", got)
	}
}
