package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Webhook posts a message as JSON. One channel covers Slack, Microsoft
// Teams, Google Chat and anything else that accepts a POST, which is where
// operations teams already are.
//
// THE RISK THIS CHANNEL CARRIES. The endpoint is supplied by a tenant
// administrator, and this platform then makes a request to it from inside
// its own network. That is server-side request forgery handed to us on a
// form: a tenant who points a webhook at the cloud metadata service, or at a
// database on the internal network, is asking our server to fetch something
// they cannot reach themselves.
//
// So the address is checked at DIAL time, after DNS, rather than by looking
// at the URL. Checking the hostname is not enough: a name that resolves to a
// public address when it is saved and to 169.254.169.254 when it is called
// is a thirty-second attack, and the URL still looks fine.
type Webhook struct {
	client *http.Client
	log    *slog.Logger
	// AllowPrivateAddresses defeats the protection above. It exists so a
	// test and a local demonstration can post to 127.0.0.1, it is named to
	// be uncomfortable, and anything that switches it on says so out loud.
	AllowPrivateAddresses bool
}

func NewWebhook(log *slog.Logger) *Webhook {
	w := &Webhook{log: log}
	w.client = &http.Client{
		// Short. A notification is not worth holding a worker open for.
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(_, address string, _ syscall.RawConn) error {
					return w.allowAddress(address)
				},
			}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		// Redirects go through the same dialler, so a redirect to an
		// internal address is refused by the same check. Still bounded:
		// a redirect loop is a worker that never finishes.
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("%w: too many redirects", ErrBadEndpoint)
			}
			return nil
		},
	}
	return w
}

func (*Webhook) Name() string { return "webhook" }

func (w *Webhook) allowAddress(address string) error {
	if w.AllowPrivateAddresses {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBadEndpoint, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %s is not an address", ErrBadEndpoint, host)
	}
	if !publicIP(ip) {
		// Deliberately specific in the log and vague to the tenant: they
		// should learn that the address is refused, not learn what is
		// reachable from in here.
		return fmt.Errorf("%w: that endpoint resolves to an address inside "+
			"this platform's own network", ErrBadEndpoint)
	}
	return nil
}

// publicIP is the allow-list direction: everything that is not clearly
// routable on the public internet is refused. Written as refusals of named
// ranges rather than as a single IsPrivate call, because IsPrivate alone
// misses loopback, link-local and the metadata address that matters most.
func publicIP(ip net.IP) bool {
	switch {
	case ip.IsLoopback(), ip.IsPrivate(), ip.IsUnspecified(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		// Carrier-grade NAT, which is not private by Go's definition and
		// is not the public internet either.
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127:
			return false
		// Benchmarking, reserved, and the documentation ranges.
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19):
			return false
		case v4[0] >= 240:
			return false
		}
		return true
	}
	// IPv6. The IPv4-mapped form (::ffff:a.b.c.d) never reaches here: To4
	// above converts it, so it is judged by the IPv4 rules.
	//
	// What is left is an allow-list, because the refusal list is the wrong
	// shape here: global unicast is 2000::/3 and everything outside it is
	// unique-local, link-local, the discard prefix, the documentation
	// range, or one of the transition formats that carries an IPv4
	// address inside an IPv6 one. NAT64 (64:ff9b::/96) is the sharpest of
	// those: with a translator on the path, 64:ff9b::169.254.169.254 is
	// the metadata service wearing an IPv6 address, and it is outside
	// 2000::/3, so it is refused here.
	if ip[0]&0xe0 != 0x20 {
		return false
	}
	// Inside 2000::/3, 6to4 (2002::/16) carries its IPv4 address in the
	// next four bytes: 2002:a9fe:a9fe:: is 169.254.169.254 again. Judge
	// the address it carries by the rules above.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return publicIP(net.IPv4(ip[2], ip[3], ip[4], ip[5]))
	}
	// The documentation range, which nothing routable uses.
	if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	return true
}

// checkWebhook is the check made when a target is SAVED. It is the cheap
// half: it catches an obvious mistake at the moment someone makes it, so
// they get a message on the form rather than a failed delivery an hour
// later. It is not the protection. The dial-time check is.
func checkWebhook(endpoint string) error {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return fmt.Errorf("%w: that is not a web address", ErrBadEndpoint)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%w: a webhook address starts with https://", ErrBadEndpoint)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: that address names no server", ErrBadEndpoint)
	}
	if u.User != nil {
		// Credentials in the URL end up in logs and in error messages.
		return fmt.Errorf("%w: put no username or password in the address", ErrBadEndpoint)
	}
	return nil
}

type webhookBody struct {
	Topic     string    `json:"topic"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	ObjectRef string    `json:"object_ref,omitempty"`
	SentAt    time.Time `json:"sent_at"`
	// Text is what Slack, Teams and Google Chat all read when they are
	// handed JSON they do not recognise, so one body works in all three
	// without an adapter each.
	Text string `json:"text"`
}

func (w *Webhook) Deliver(ctx context.Context, endpoint string, m Message) error {
	text := m.Subject
	if m.Body != "" {
		text += "\n" + m.Body
	}
	payload, err := json.Marshal(webhookBody{
		Topic: string(m.Topic), Subject: m.Subject, Body: m.Body,
		ObjectRef: m.ObjectRef, SentAt: time.Now().UTC(), Text: text,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadEndpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Read a little of the answer for the error message, and no more: the
	// endpoint is not ours and a reply is not a reason to allocate.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the endpoint answered %d: %s",
			resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// ---------------------------------------------------------------- the log

// Log writes the notification to this platform's own log.
//
// It is the channel a tenant gets before they have configured anything, and
// it is honest about what it is: an operator reading the log will see it, and
// the tenant will not. It exists so that a deployment with no chat
// integration still has somewhere for a notification to go other than
// nowhere.
type Log struct{ log *slog.Logger }

func NewLog(l *slog.Logger) Log { return Log{log: l} }

func (Log) Name() string { return "log" }

func (l Log) Deliver(_ context.Context, _ string, m Message) error {
	l.log.Warn("NOTIFICATION", "topic", string(m.Topic),
		"subject", m.Subject, "body", m.Body, "object", m.ObjectRef)
	return nil
}

// PublicIPForTest exposes the address rule so the ranges can be asserted
// directly. They are the kind of thing that is wrong in a way no end-to-end
// test would reveal: a missed range only matters on the day somebody points
// a webhook at it.
func PublicIPForTest(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return publicIP(ip)
}

// PublicIP says whether an address is one on the public internet, by the
// same rules the webhook dials by. The export-to-bucket sender uses it.
func PublicIP(ip net.IP) bool { return publicIP(ip) }
