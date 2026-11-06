package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"platform/internal/notify/smtptest"
)

func server(t *testing.T) *smtptest.Server {
	t.Helper()
	s, err := smtptest.New()
	if err != nil {
		t.Fatalf("smtptest: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func channel(s *smtptest.Server) Email {
	return Email{
		Server: s.Addr(), From: "notifications@kalesi.example",
		Security: "starttls", RootCAs: s.RootCAs(),
		Helo: "mdm.kalesi.example", Timeout: 10 * time.Second,
	}
}

var msg = Message{
	Topic:     DeviceLost,
	Subject:   "HQ-MBP-002 was reported lost",
	Body:      "t.eze reported HQ-MBP-002 lost. They said: left it in a taxi",
	ObjectRef: "device:9f2c1a40-0000-4000-8000-000000000001",
	Tenant:    "Kalesi Device Care",
}

// ------------------------------------------------------- header injection
//
// The control this channel exists around. An address field containing a
// newline is not a malformed address, it is extra headers, and a Bcc written
// that way is a silent copy of every notification to somebody else,
// configured through a form by anyone who can reach the settings page.

func TestAnAddressCarryingExtraHeadersIsRefused(t *testing.T) {
	attempts := []string{
		"security@kalesi.example\r\nBcc: attacker@elsewhere.example",
		"security@kalesi.example\nBcc: attacker@elsewhere.example",
		"security@kalesi.example\rX-Thing: no",
		"security@kalesi.example\r\n\r\nInjected body",
		"security@kalesi.example\x00",
		"\r\nBcc: attacker@elsewhere.example",
	}
	for _, attempt := range attempts {
		got, err := ParseRecipients(attempt)
		if err == nil {
			t.Fatalf("%q was accepted as %v", attempt, got)
		}
	}
}

// The end-to-end version, because the assertion that matters is about the
// ENVELOPE the server was given, which is a different list from the To
// header and is where a Bcc would actually show up.
func TestNoExtraRecipientReachesTheServer(t *testing.T) {
	s := server(t)
	e := channel(s)

	err := e.Deliver(context.Background(),
		"security@kalesi.example\r\nBcc: attacker@elsewhere.example", msg)
	if err == nil {
		t.Fatal("the injected address was delivered")
	}
	if !errors.Is(err, ErrHeaderInjection) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if n := len(s.Received()); n != 0 {
		t.Fatalf("the server received %d messages", n)
	}

	// And a legitimate send does reach exactly the addresses asked for.
	if err := e.Deliver(context.Background(),
		"security@kalesi.example, it@kalesi.example", msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	got := s.Received()
	if len(got) != 1 {
		t.Fatalf("got %d messages", len(got))
	}
	if len(got[0].To) != 2 {
		t.Fatalf("envelope has %d recipients: %v", len(got[0].To), got[0].To)
	}
	for _, addr := range got[0].To {
		if strings.Contains(addr, "elsewhere") {
			t.Fatalf("an unexpected recipient: %s", addr)
		}
	}
}

// A subject built from a device name is ours, but a device name comes from
// a machine, so it is still untrusted input reaching a header.
func TestASubjectCarryingALineBreakIsRefused(t *testing.T) {
	e := Email{From: "a@b.example"}
	_, err := e.Compose([]string{"c@d.example"}, Message{
		Subject: "Lost\r\nBcc: attacker@elsewhere.example",
	})
	if !errors.Is(err, ErrHeaderInjection) {
		t.Fatalf("got %v", err)
	}
	// And a tenant's own product name, which an administrator types.
	_, err = e.Compose([]string{"c@d.example"}, Message{
		Subject: "fine", Tenant: "Kalesi\r\nBcc: attacker@elsewhere.example",
	})
	if !errors.Is(err, ErrHeaderInjection) {
		t.Fatalf("got %v", err)
	}
}

// ---------------------------------------------------------- the message

func TestTheMessageIsWellFormed(t *testing.T) {
	s := server(t)
	if err := channel(s).Deliver(context.Background(), "security@kalesi.example", msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	got := s.Received()[0]

	for _, want := range []string{
		"From: \"Kalesi Device Care\" <notifications@kalesi.example>",
		"To: security@kalesi.example",
		"Subject: HQ-MBP-002 was reported lost",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		// Tells a mail system this is machine-generated, so a holiday
		// auto-reply does not bounce back at the platform forever.
		"Auto-Submitted: auto-generated",
		"X-Notification-Topic: device.lost",
		"left it in a taxi",
	} {
		if !strings.Contains(got.Data, want) {
			t.Fatalf("the message does not contain %q:\n%s", want, got.Data)
		}
	}
	// Headers and body are separated by exactly one blank line, or the
	// body becomes headers.
	if !strings.Contains(got.Data, "\r\n\r\n") {
		t.Fatal("no header/body separator")
	}
	if !strings.Contains(got.Data, "Message-ID: <") {
		t.Fatal("no Message-ID")
	}
}

// T12 reaches the inbox. A message landing in a tenant's staff inbox is as
// tenant-facing as a page in the console.
func TestTheSenderWearsTheTenantsNameNotOurs(t *testing.T) {
	s := server(t)
	if err := channel(s).Deliver(context.Background(), "a@kalesi.example", msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	data := s.Received()[0].Data
	if !strings.Contains(data, "Kalesi Device Care") {
		t.Fatalf("the tenant's name is not on the message:\n%s", data)
	}
	for _, ours := range []string{"MDM Platform", "platform operator"} {
		if strings.Contains(data, ours) {
			t.Fatalf("the operator's name leaked into a tenant's mail: %q", ours)
		}
	}
}

// A non-ASCII subject has to be encoded, or some servers reject it and
// others mangle it.
func TestANonAsciiSubjectIsEncoded(t *testing.T) {
	s := server(t)
	m := msg
	m.Subject = "Gerät HQ-MBP-002 wurde als verloren gemeldet"
	if err := channel(s).Deliver(context.Background(), "a@kalesi.example", m); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	// The assertion is about the HEADER. The same text appears in the body,
	// where raw UTF-8 is correct and expected, so checking the whole
	// message would fail for the wrong reason.
	var subject string
	for _, line := range strings.Split(s.Received()[0].Data, "\r\n") {
		if strings.HasPrefix(line, "Subject: ") {
			subject = line
		}
	}
	if subject == "" {
		t.Fatal("no Subject header")
	}
	if strings.Contains(subject, "Gerät") {
		t.Fatalf("a non-ASCII subject went out as raw bytes in a header: %s", subject)
	}
	if !strings.Contains(subject, "=?utf-8?") {
		t.Fatalf("the subject was not encoded: %s", subject)
	}
	// The body is a different matter: it is declared utf-8 and should read
	// as the words somebody wrote.
	if !strings.Contains(s.Received()[0].Data, "Gerät") {
		t.Fatal("the body lost its accented characters")
	}
}

// A line in the body that is a single full stop ends the DATA command. A
// message containing one would be truncated there and the rest fed to the
// server as commands.
func TestAFullStopOnItsOwnLineDoesNotEndTheMessage(t *testing.T) {
	s := server(t)
	m := msg
	m.Body = "first line\r\n.\r\nlast line"
	if err := channel(s).Deliver(context.Background(), "a@kalesi.example", m); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	data := s.Received()[0].Data
	if !strings.Contains(data, "last line") {
		t.Fatalf("the message was truncated at the full stop:\n%s", data)
	}
}

// ---------------------------------------------------------- the transport

func TestTheConversationIsEncryptedBeforeTheMessageIsSent(t *testing.T) {
	s := server(t)
	if err := channel(s).Deliver(context.Background(), "a@kalesi.example", msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if !s.Received()[0].Encrypted {
		t.Fatal("the message was handed over in the clear")
	}
}

// The check that matters on this path. A server that does not offer
// encryption must not be handed a password anyway: that is how credentials
// end up on the wire, and the failure is silent because the mail still
// arrives.
func TestAPasswordIsNeverSentOverAnUnencryptedConnection(t *testing.T) {
	s := server(t)
	s.OfferSTARTTLS = false

	e := channel(s)
	e.Security = "none"
	e.Username = "mdm@kalesi.example"
	e.Password = "the-password"

	err := e.Deliver(context.Background(), "a@kalesi.example", msg)
	if !errors.Is(err, ErrCleartextAuth) {
		t.Fatalf("got %v, want a refusal to authenticate in the clear", err)
	}
	for _, r := range s.Received() {
		if r.AuthSeen && !r.AuthEncrypted {
			t.Fatal("a password was sent in the clear")
		}
	}
	if n := len(s.Received()); n != 0 {
		t.Fatalf("the message was sent anyway: %d", n)
	}
}

// A server that has been configured for STARTTLS and does not offer it is a
// downgrade, whether by a misconfiguration or by somebody in the middle
// stripping the capability. Sending anyway is the failure.
func TestAServerThatWillNotEncryptIsRefusedRatherThanDowngraded(t *testing.T) {
	s := server(t)
	s.OfferSTARTTLS = false

	err := channel(s).Deliver(context.Background(), "a@kalesi.example", msg)
	if err == nil {
		t.Fatal("the message was sent without encryption")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if n := len(s.Received()); n != 0 {
		t.Fatalf("the message went out anyway: %d", n)
	}
}

func TestSendingWithoutCredentialsNeedsNoAuth(t *testing.T) {
	s := server(t)
	if err := channel(s).Deliver(context.Background(), "a@kalesi.example", msg); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if s.Received()[0].AuthSeen {
		t.Fatal("the client authenticated with no credentials configured")
	}
}

func TestARefusedRecipientIsReportedRatherThanSwallowed(t *testing.T) {
	s := server(t)
	s.RejectRecipient = "gone@kalesi.example"

	err := channel(s).Deliver(context.Background(),
		"security@kalesi.example, gone@kalesi.example", msg)
	if err == nil {
		t.Fatal("a refused recipient was swallowed")
	}
	if !strings.Contains(err.Error(), "gone@kalesi.example") {
		t.Fatalf("the error does not name the address: %v", err)
	}
}

// ---------------------------------------------------------- the addresses

func TestAddressesAreParsedAndTidied(t *testing.T) {
	cases := map[string][]string{
		"a@b.example":                        {"a@b.example"},
		"a@b.example, c@d.example":           {"a@b.example", "c@d.example"},
		"a@b.example; c@d.example":           {"a@b.example", "c@d.example"},
		"a@b.example  c@d.example":           {"a@b.example", "c@d.example"},
		"  a@b.example  ":                    {"a@b.example"},
		"a@b.example, A@B.EXAMPLE":           {"a@b.example"},
		"Security Team <sec@kalesi.example>": {"sec@kalesi.example"},
	}
	for in, want := range cases {
		got, err := ParseRecipients(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%q gave %v, want %v", in, got, want)
		}
		for i := range got {
			if !strings.EqualFold(got[i], want[i]) {
				t.Fatalf("%q gave %v, want %v", in, got, want)
			}
		}
	}
}

func TestRubbishIsNotAnAddress(t *testing.T) {
	for _, bad := range []string{
		"", "   ", "not-an-address", "@kalesi.example", "a@", "a b@c.example",
	} {
		if got, err := ParseRecipients(bad); err == nil {
			t.Fatalf("%q was accepted as %v", bad, got)
		}
	}
}

// A notification target is a mailbox or a small list, not a mailing list. A
// form that takes two hundred addresses is one somebody will paste a leaked
// list into.
func TestATargetCannotBecomeAMailingList(t *testing.T) {
	many := make([]string, MaxRecipients+1)
	for i := range many {
		many[i] = "person" + string(rune('a'+i)) + "@kalesi.example"
	}
	if _, err := ParseRecipients(strings.Join(many, ",")); err == nil {
		t.Fatalf("%d addresses were accepted", len(many))
	}
}

func TestNoMailServerIsAnHonestFailure(t *testing.T) {
	e := Email{From: "a@b.example"}
	err := e.Deliver(context.Background(), "c@d.example", msg)
	if err == nil {
		t.Fatal("it claimed to send with no server configured")
	}
	if !strings.Contains(err.Error(), "mail server") {
		t.Fatalf("unhelpful: %v", err)
	}
}

// T4 in the inbox: the HTML half wears the tenant's colour, name and legal
// footer, and nothing the message carries is markup. A body that tries to
// be markup is shown as text.
func TestTheHTMLHalfWearsTheBrandAndEscapesTheMessage(t *testing.T) {
	s := server(t)
	m := msg
	m.Colour, m.Footer = "#0F6E66", "Kalesi Foods Ltd · RC 1184420 · Lagos"
	m.Body = "left it in a taxi <script>alert(1)</script>\n\nOpen https://console.kalesi.example/devices?x=1&y=2 to release it."
	if err := channel(s).Deliver(context.Background(), "security@kalesi.example", m); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	data := s.Received()[0].Data
	for _, want := range []string{
		"multipart/alternative", "Content-Type: text/plain; charset=utf-8", "Content-Type: text/html; charset=utf-8",
		"background:#0F6E66", "Kalesi Device Care", "Kalesi Foods Ltd · RC 1184420 · Lagos",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		`<a href="https://console.kalesi.example/devices?x=1&amp;y=2"`,
	} {
		if !strings.Contains(data, want) {
			t.Fatalf("the message does not carry %q:\n%s", want, data)
		}
	}
	// The plain half carries the text as typed; the HTML half must not.
	htmlHalf := data[strings.Index(data, "Content-Type: text/html"):]
	if strings.Contains(htmlHalf, "<script>") {
		t.Fatalf("markup from the body reached the HTML:\n%s", htmlHalf)
	}
}
