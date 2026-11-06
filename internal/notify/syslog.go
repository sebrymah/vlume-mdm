package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Syslog is the SIEM channel: one line per message over TCP, optionally
// TLS, in the form every collector reads. The message body IS the line;
// the exporter formats CEF or LEEF, this only carries it.
//
// The endpoint is syslog://host:port (plain) or syslogs://host:port (TLS),
// with ?format=leef to choose LEEF over CEF. Like the webhook channel it
// refuses addresses inside this platform's own network unless the operator
// says otherwise: a tenant administrator choosing a destination must not
// be able to make this platform open connections to its own internals.
type Syslog struct {
	AllowPrivateAddresses bool
	Timeout               time.Duration
}

func NewSyslog() *Syslog { return &Syslog{Timeout: 10 * time.Second} }

func (*Syslog) Name() string { return "syslog" }

type SyslogEndpoint struct {
	Host   string
	Port   string
	TLS    bool
	Format string // cef or leef
}

func ParseSyslog(endpoint string) (SyslogEndpoint, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (u.Scheme != "syslog" && u.Scheme != "syslogs") || u.Host == "" {
		return SyslogEndpoint{}, fmt.Errorf("%w: a SIEM destination is syslog://host:port or syslogs://host:port", ErrBadEndpoint)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || port == "" {
		return SyslogEndpoint{}, fmt.Errorf("%w: the destination needs a host and a port", ErrBadEndpoint)
	}
	format := strings.ToLower(u.Query().Get("format"))
	switch format {
	case "", "cef":
		format = "cef"
	case "leef":
	default:
		return SyslogEndpoint{}, fmt.Errorf("%w: format is cef or leef", ErrBadEndpoint)
	}
	return SyslogEndpoint{Host: host, Port: port, TLS: u.Scheme == "syslogs", Format: format}, nil
}

func checkSyslog(endpoint string) error {
	_, err := ParseSyslog(endpoint)
	return err
}

func (s *Syslog) Deliver(ctx context.Context, endpoint string, m Message) error {
	ep, err := ParseSyslog(endpoint)
	if err != nil {
		return err
	}
	if !s.AllowPrivateAddresses {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, ep.Host)
		if err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
		for _, ip := range ips {
			if !publicIP(ip.IP) {
				return errors.New("syslog: that destination is inside this platform's own network")
			}
		}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	if ep.TLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ep.Host, ep.Port),
			&tls.Config{ServerName: ep.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(ep.Host, ep.Port))
	}
	if err != nil {
		return fmt.Errorf("syslog: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	line := strings.ReplaceAll(strings.TrimSpace(m.Body), "\n", " ")
	// RFC 5424 header, then the structured line. The app-name is the
	// tenant's own product (Message.Tenant), never ours.
	app := strings.ReplaceAll(m.Tenant, " ", "_")
	if app == "" {
		app = "-"
	}
	header := fmt.Sprintf("<134>1 %s - %s - - - ", time.Now().UTC().Format(time.RFC3339), app)
	_, err = conn.Write([]byte(header + line + "\n"))
	if err != nil {
		return fmt.Errorf("syslog: %w", err)
	}
	return nil
}
