package notify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// Email delivers over SMTP.
//
// THE RISK THIS CHANNEL CARRIES is not the one the webhook carries. A
// tenant-supplied webhook address is a request this platform makes from
// inside its own network, which is why that one is checked at dial time. A
// tenant-supplied email address is not: nothing here connects to it, it is
// handed to a mail server the operator chose. The two look similar on the
// settings form and are not the same risk at all.
//
// What email brings instead is HEADER INJECTION. An address field containing
// a newline is not a malformed address, it is extra headers:
//
//	security@kalesi.example\r\nBcc: attacker@elsewhere.example
//
// written straight into the message, that is a silent copy of every
// notification to somebody else, configured through a form field by anyone
// who can reach the settings page. Every value that reaches a header in this
// file goes through checkHeaderValue first, and the addresses are parsed by
// net/mail rather than trusted, and the two together are the control.
//
// The other thing worth stating: this sends as the TENANT, not as us. T12
// says no operator brand appears on a tenant-facing surface, and an email
// landing in a tenant's staff inbox is as tenant-facing as a page.
type Email struct {
	// Server is host:port. Operator configuration, never a tenant's.
	Server string
	From   string
	// Username and Password authenticate to the server. They are refused
	// over an unencrypted connection: handing a password to a server in
	// cleartext because the server did not offer STARTTLS is the failure
	// this check exists to make impossible rather than merely unlikely.
	Username string
	Password string
	// Security is "starttls" (the usual, port 587), "tls" (implicit, port
	// 465), or "none". "none" is for a local relay on the same host and
	// refuses to carry credentials.
	Security string
	// Timeout bounds the whole conversation. A mail server that accepts a
	// connection and then says nothing would otherwise hold a worker open
	// indefinitely.
	Timeout time.Duration
	// Helo is the name this platform announces itself as.
	Helo string
	// RootCAs trusts a private certificate authority, which an internal
	// mail relay usually has. Nil means the host's own trust store.
	RootCAs *x509.CertPool
}

func (e Email) tlsConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, RootCAs: e.RootCAs}
}

func (Email) Name() string { return "email" }

var (
	ErrHeaderInjection = errors.New("notify: that address contains line breaks")
	ErrNoRecipients    = errors.New("notify: no address to write to")
	ErrCleartextAuth   = errors.New(
		"notify: refusing to send a password over an unencrypted connection")
)

// MaxRecipients bounds one target. A notification target is a mailbox or a
// small list, not a mailing list: anything larger belongs in a real mail
// system with unsubscribe handling, and a form that accepts two hundred
// addresses is a form somebody will paste a leaked list into.
const MaxRecipients = 10

// ParseRecipients turns what an administrator typed into addresses, and
// refuses anything that would reach a header as something other than an
// address.
//
// It is exported because the settings form calls it at save time: a person
// who mistypes an address should be told on the form, not an hour later by a
// delivery that failed.
func ParseRecipients(s string) ([]string, error) {
	// The injection check runs on the WHOLE input first, before anything
	// tries to make sense of it. Everything below either parses or splits,
	// and a check that happens after a parse is a check a parser can be
	// talked around.
	if err := checkHeaderValue(s); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s) == "" {
		return nil, ErrNoRecipients
	}

	// net/mail first, which understands "Security Team <sec@kalesi.example>"
	// and the comma-separated form. Splitting on whitespace would tear a
	// display name in half, which is what the first version of this did.
	var raw []string
	if list, err := mail.ParseAddressList(s); err == nil {
		for _, a := range list {
			raw = append(raw, a.Address)
		}
	} else {
		// Somebody typed addresses separated by semicolons or spaces,
		// which net/mail does not accept and a person reasonably might.
		raw = strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		})
	}
	if len(raw) == 0 {
		return nil, ErrNoRecipients
	}
	if len(raw) > MaxRecipients {
		return nil, fmt.Errorf("notify: at most %d addresses, got %d",
			MaxRecipients, len(raw))
	}

	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, candidate := range raw {
		// Checked BEFORE parsing. net/mail is strict and would almost
		// certainly refuse these anyway, but "almost certainly" is not the
		// standard for the one check standing between a form field and a
		// Bcc header.
		if err := checkHeaderValue(candidate); err != nil {
			return nil, err
		}
		addr, err := mail.ParseAddress(candidate)
		if err != nil {
			return nil, fmt.Errorf("notify: %q is not an email address", candidate)
		}
		if err := checkHeaderValue(addr.Address); err != nil {
			return nil, err
		}
		if !strings.Contains(addr.Address, "@") {
			return nil, fmt.Errorf("notify: %q is not an email address", candidate)
		}
		low := strings.ToLower(addr.Address)
		if seen[low] {
			continue
		}
		seen[low] = true
		out = append(out, addr.Address)
	}
	return out, nil
}

// checkHeaderValue refuses anything that would end a header line.
//
// Carriage return and line feed are the attack. The others are refused
// because a NUL or a lone control character in a header is never a thing
// somebody typed on purpose, and a header this platform cannot vouch for is
// one it should not write.
func checkHeaderValue(v string) error {
	for _, r := range v {
		if r == '\r' || r == '\n' || r == 0 {
			return fmt.Errorf("%w: %q", ErrHeaderInjection, v)
		}
		if r < 0x20 && r != '\t' {
			return fmt.Errorf("%w: %q", ErrHeaderInjection, v)
		}
	}
	return nil
}

// header writes one header, with the value encoded if it is not plain ASCII.
//
// RFC 2047 encoding is not decoration: a subject containing a device name
// with an accent in it would otherwise go out as raw bytes in a header,
// which some servers reject and others mangle.
func header(b *strings.Builder, name, value string) error {
	if err := checkHeaderValue(value); err != nil {
		return err
	}
	b.WriteString(name)
	b.WriteString(": ")
	if isASCII(value) {
		b.WriteString(value)
	} else {
		b.WriteString(mime.QEncoding.Encode("utf-8", value))
	}
	b.WriteString("\r\n")
	return nil
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// Compose builds the message. Separated from sending so the exact bytes can
// be asserted in a test without a mail server, which is the only way to be
// sure about something as fiddly as header encoding.
func (e Email) Compose(to []string, m Message) ([]byte, error) {
	if len(to) == 0 {
		return nil, ErrNoRecipients
	}
	// The tenant's own address when they have proven a domain, ours
	// otherwise. This has to match the DKIM d= below or the signature is
	// valid and DMARC still fails: an aligned signature is the whole point
	// of a sending domain, and a message signed as one domain and sent
	// from another aligns with nothing.
	from := e.From
	if m.Sender != nil && m.Sender.From != "" {
		from = m.Sender.From
	}
	if from == "" {
		from = "notifications@localhost"
	}
	if err := checkHeaderValue(from); err != nil {
		return nil, err
	}

	// T12: the display name is the tenant's own product, never ours. A
	// message landing in a tenant's staff inbox is as tenant-facing as a
	// page in the console.
	fromHeader := from
	if m.Tenant != "" {
		if err := checkHeaderValue(m.Tenant); err != nil {
			return nil, err
		}
		fromHeader = (&mail.Address{Name: m.Tenant, Address: from}).String()
	}

	var b strings.Builder
	if err := header(&b, "From", fromHeader); err != nil {
		return nil, err
	}
	if err := header(&b, "To", strings.Join(to, ", ")); err != nil {
		return nil, err
	}
	if err := header(&b, "Subject", m.Subject); err != nil {
		return nil, err
	}
	if err := header(&b, "Date", time.Now().UTC().Format(time.RFC1123Z)); err != nil {
		return nil, err
	}
	id, err := messageID(from)
	if err != nil {
		return nil, err
	}
	if err := header(&b, "Message-ID", id); err != nil {
		return nil, err
	}
	// Tells a mail system this is machine-generated, so a holiday
	// auto-reply does not bounce back at the platform forever.
	if err := header(&b, "Auto-Submitted", "auto-generated"); err != nil {
		return nil, err
	}
	if err := header(&b, "X-Notification-Topic", string(m.Topic)); err != nil {
		return nil, err
	}
	if err := header(&b, "MIME-Version", "1.0"); err != nil {
		return nil, err
	}
	// Two halves of the same message: plain text for whatever reads it,
	// and HTML wearing the tenant's brand (T4) for a mail client. The
	// boundary is random so no body can end a part early.
	boundary, err := messageID("")
	if err != nil {
		return nil, err
	}
	boundary = "=_" + strings.Trim(boundary, "<>@")
	boundary = strings.ReplaceAll(boundary, "@", "")
	if err := header(&b, "Content-Type", `multipart/alternative; boundary="`+boundary+`"`); err != nil {
		return nil, err
	}
	b.WriteString("\r\n")

	body := m.Subject + "\r\n\r\n"
	if m.Body != "" {
		body += m.Body + "\r\n\r\n"
	}
	if m.ObjectRef != "" {
		body += m.ObjectRef + "\r\n\r\n"
	}
	if m.Footer != "" {
		body += m.Footer + "\r\n"
	}
	body += "This is an automatic message from your device management console.\r\n"

	var parts strings.Builder
	parts.WriteString("--" + boundary + "\r\n")
	parts.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	parts.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	parts.WriteString(body)
	parts.WriteString("\r\n--" + boundary + "\r\n")
	parts.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	parts.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	parts.WriteString(RenderHTML(m))
	parts.WriteString("\r\n--" + boundary + "--\r\n")
	// Dot-stuffing. A line in the body that is a single full stop ends the
	// DATA command, so a message whose body happened to contain one would
	// be truncated there and the rest fed to the server as commands.
	b.WriteString(stuffDots(parts.String()))

	return []byte(b.String()), nil
}

// RenderHTML is the HTML half of an email, and the Branding page's
// preview: a band in the tenant's colour with the product name, the
// message, and the legal footer. Everything from the message is escaped;
// the only markup is this function's own. Links the body carries become
// links, with the address escaped like everything else.
func RenderHTML(m Message) string {
	colour := m.Colour
	if colour == "" {
		colour = "#1F2937"
	}
	name := m.Tenant
	if name == "" {
		name = "Device management"
	}
	var out strings.Builder
	out.WriteString(`<!doctype html><html><body style="margin:0;background:#f4f5f7;font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif">`)
	out.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">`)
	out.WriteString(`<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden">`)
	out.WriteString(`<tr><td style="background:` + html.EscapeString(colour) + `;color:#ffffff;padding:16px 24px;font-size:18px;font-weight:600">` + html.EscapeString(name) + `</td></tr>`)
	out.WriteString(`<tr><td style="padding:24px;color:#1f2937;font-size:15px;line-height:1.5">`)
	out.WriteString(`<p style="margin:0 0 14px;font-size:17px;font-weight:600">` + html.EscapeString(m.Subject) + `</p>`)
	for _, para := range strings.Split(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n\n") {
		if strings.TrimSpace(para) == "" {
			continue
		}
		out.WriteString(`<p style="margin:0 0 12px">` + linkify(html.EscapeString(para)) + `</p>`)
	}
	if m.ObjectRef != "" {
		out.WriteString(`<p style="margin:0 0 12px;color:#6b7280;font-size:13px">` + html.EscapeString(m.ObjectRef) + `</p>`)
	}
	out.WriteString(`</td></tr>`)
	out.WriteString(`<tr><td style="padding:16px 24px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:12px;line-height:1.5">`)
	if m.Footer != "" {
		out.WriteString(html.EscapeString(m.Footer) + `<br>`)
	}
	out.WriteString(`This is an automatic message from your device management console.</td></tr>`)
	out.WriteString(`</table></td></tr></table></body></html>`)
	return out.String()
}

// linkify turns an https:// address in already-escaped text into a link.
// It runs after escaping, so the address inside href is escaped text too;
// a quote or angle bracket in it has already become an entity.
func linkify(escaped string) string {
	var out strings.Builder
	for _, line := range strings.Split(escaped, "\n") {
		words := strings.Fields(line)
		for i, w := range words {
			if strings.HasPrefix(w, "https://") {
				words[i] = `<a href="` + w + `" style="color:#1d4ed8">` + w + `</a>`
			}
		}
		if out.Len() > 0 {
			out.WriteString("<br>")
		}
		out.WriteString(strings.Join(words, " "))
	}
	return out.String()
}

func stuffDots(body string) string {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, ".") {
			lines[i] = "." + l
		}
	}
	return strings.Join(lines, "\r\n")
}

func messageID(from string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	domain := "localhost"
	if i := strings.LastIndex(from, "@"); i >= 0 {
		domain = from[i+1:]
	}
	return "<" + base64.RawURLEncoding.EncodeToString(b) + "@" + domain + ">", nil
}

// Deliver sends to the addresses in endpoint.
func (e Email) Deliver(ctx context.Context, endpoint string, m Message) error {
	to, err := ParseRecipients(endpoint)
	if err != nil {
		return err
	}
	msg, err := e.Compose(to, m)
	if err != nil {
		return err
	}
	msg, err = sign(msg, m.Sender)
	if err != nil {
		return err
	}
	return e.send(ctx, to, msg)
}

func (e Email) send(ctx context.Context, to []string, msg []byte) error {
	if e.Server == "" {
		return errors.New("notify: this deployment has no mail server configured")
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host, _, err := net.SplitHostPort(e.Server)
	if err != nil {
		return fmt.Errorf("notify: the mail server address is not host:port: %w", err)
	}

	var conn net.Conn
	d := &net.Dialer{Timeout: timeout}
	if e.Security == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", e.Server, e.tlsConfig(host))
	} else {
		conn, err = d.DialContext(ctx, "tcp", e.Server)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	// Belt to the context's braces: a server that accepts the connection
	// and then stops talking would otherwise hold this open.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()

	helo := e.Helo
	if helo == "" {
		helo = "localhost"
	}
	if err := c.Hello(helo); err != nil {
		return err
	}

	encrypted := e.Security == "tls"
	if e.Security == "starttls" {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			return errors.New("notify: the mail server does not offer STARTTLS")
		}
		if err := c.StartTLS(e.tlsConfig(host)); err != nil {
			return err
		}
		encrypted = true
	}

	if e.Username != "" {
		// The check that matters. A server that does not offer encryption,
		// or that fails to negotiate it, must not be handed a password
		// anyway: that is how credentials end up on the wire, and the
		// failure is silent because the mail still arrives.
		if !encrypted {
			return ErrCleartextAuth
		}
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, host)); err != nil {
			return err
		}
	}

	from := e.From
	if from == "" {
		from = "notifications@localhost"
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return fmt.Errorf("notify: the mail server refused %s: %w", addr, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// sign adds the DKIM-Signature header.
//
// The canonicalisation and the signature are RFC 6376's, and they are
// go-msgauth's implementation of it rather than mine. That is the same call
// made for OpenID Connect: relaxed header canonicalisation, body hashing and
// the tag ordering are the kind of fiddly that fails quietly, and a DKIM
// signature that does not verify is worse than none, because a receiver
// running DMARC reads it as a failure rather than as an absence.
//
// A tenant with no verified domain gets an unsigned message, which is what
// they had before and is honest: the alternative would be signing as a
// domain nobody proved.
func sign(msg []byte, id *SenderIdentity) ([]byte, error) {
	if id == nil || id.PrivateKey == nil {
		return msg, nil
	}
	var out bytes.Buffer
	err := dkim.Sign(&out, bytes.NewReader(msg), &dkim.SignOptions{
		Domain:   id.Domain,
		Selector: id.Selector,
		Signer:   id.PrivateKey,
		Hash:     crypto.SHA256,
		// What is covered. From is not optional: a signature that does not
		// cover From is one an attacker can reuse on a message of their
		// own. The rest are the headers worth protecting from being
		// rewritten in transit.
		HeaderKeys: []string{
			"From", "To", "Subject", "Date", "Message-ID",
			"MIME-Version", "Content-Type", "Auto-Submitted",
			"X-Notification-Topic",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("notify: could not sign as %s: %w", id.Domain, err)
	}
	return out.Bytes(), nil
}
