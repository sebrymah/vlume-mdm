// Package smtptest is a working SMTP server for tests.
//
// It exists for the same reason internal/identity/idptest does: a fake
// channel that records what it was handed proves the calling code ran, and
// proves nothing about the thing that actually matters. For email the thing
// that matters is the ENVELOPE — which addresses the server was told to
// deliver to — and that is a different list from the To header. Header
// injection is exactly the case where the two diverge, and only a server
// that speaks the protocol can tell them apart.
//
// So this one does the conversation: greeting, EHLO, optional STARTTLS,
// optional AUTH, MAIL FROM, RCPT TO, DATA terminated by a lone full stop,
// QUIT. Tests then assert on the recipients the server was given and on the
// exact bytes of the message.
package smtptest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// Received is one delivery, as the server saw it.
type Received struct {
	// From and To are the ENVELOPE, not the headers. A message whose To
	// header says one thing and whose envelope says another is the whole
	// point of looking.
	From string
	To   []string
	Data string
	// Encrypted records whether the conversation had been upgraded by the
	// time the message was handed over.
	Encrypted bool
	// AuthSeen records whether the client authenticated, and in the clear
	// or not, so a test can assert a password was never sent unencrypted.
	AuthSeen      bool
	AuthEncrypted bool
}

type Server struct {
	ln   net.Listener
	cert tls.Certificate
	pool *x509.CertPool

	// OfferSTARTTLS controls whether EHLO advertises it. Switching it off
	// is how a test produces the server that cannot encrypt, which is the
	// case the cleartext-password refusal exists for.
	OfferSTARTTLS bool
	OfferAuth     bool
	// RejectRecipient refuses one address, for the test that a refusal is
	// reported rather than swallowed.
	RejectRecipient string

	mu   sync.Mutex
	got  []Received
	done chan struct{}
}

// New starts a server on a loopback port.
func New() (*Server, error) {
	cert, pool, err := selfSigned()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, cert: cert, pool: pool,
		OfferSTARTTLS: true, OfferAuth: true, done: make(chan struct{})}
	go s.accept()
	return s, nil
}

func (s *Server) Addr() string            { return s.ln.Addr().String() }
func (s *Server) RootCAs() *x509.CertPool { return s.pool }

func (s *Server) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	_ = s.ln.Close()
}

// Received returns what has arrived so far.
func (s *Server) Received() []Received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Received(nil), s.got...)
}

func (s *Server) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	say := func(format string, args ...any) error {
		if _, err := fmt.Fprintf(w, format+"\r\n", args...); err != nil {
			return err
		}
		return w.Flush()
	}

	if err := say("220 smtptest ESMTP ready"); err != nil {
		return
	}

	var (
		encrypted bool
		authSeen  bool
		authEnc   bool
		from      string
		to        []string
	)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			lines := []string{"250-smtptest"}
			if s.OfferSTARTTLS && !encrypted {
				lines = append(lines, "250-STARTTLS")
			}
			if s.OfferAuth {
				lines = append(lines, "250-AUTH PLAIN LOGIN")
			}
			lines = append(lines, "250 SIZE 10485760")
			if err := say("%s", strings.Join(lines, "\r\n")); err != nil {
				return
			}

		case strings.HasPrefix(upper, "STARTTLS"):
			if !s.OfferSTARTTLS {
				_ = say("502 not implemented")
				continue
			}
			if err := say("220 go ahead"); err != nil {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			r = bufio.NewReader(conn)
			w = bufio.NewWriter(conn)
			say = func(format string, args ...any) error {
				if _, err := fmt.Fprintf(w, format+"\r\n", args...); err != nil {
					return err
				}
				return w.Flush()
			}
			encrypted = true

		case strings.HasPrefix(upper, "AUTH"):
			authSeen = true
			authEnc = encrypted
			if err := say("235 2.7.0 accepted"); err != nil {
				return
			}

		case strings.HasPrefix(upper, "MAIL FROM:"):
			from = addressIn(line)
			to = nil
			if err := say("250 2.1.0 ok"); err != nil {
				return
			}

		case strings.HasPrefix(upper, "RCPT TO:"):
			addr := addressIn(line)
			if s.RejectRecipient != "" && strings.EqualFold(addr, s.RejectRecipient) {
				if err := say("550 5.1.1 no such mailbox"); err != nil {
					return
				}
				continue
			}
			to = append(to, addr)
			if err := say("250 2.1.5 ok"); err != nil {
				return
			}

		case upper == "DATA":
			if err := say("354 end with <CRLF>.<CRLF>"); err != nil {
				return
			}
			var body strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" || l == ".\n" {
					break
				}
				// Undo dot-stuffing, so a test sees what was meant rather
				// than what the protocol required.
				if strings.HasPrefix(l, "..") {
					l = l[1:]
				}
				body.WriteString(l)
			}
			s.mu.Lock()
			s.got = append(s.got, Received{
				From: from, To: append([]string(nil), to...), Data: body.String(),
				Encrypted: encrypted, AuthSeen: authSeen, AuthEncrypted: authEnc,
			})
			s.mu.Unlock()
			if err := say("250 2.0.0 queued"); err != nil {
				return
			}

		case upper == "QUIT":
			_ = say("221 2.0.0 bye")
			return

		case upper == "RSET":
			from, to = "", nil
			_ = say("250 2.0.0 ok")

		case upper == "NOOP":
			_ = say("250 2.0.0 ok")

		default:
			_ = say("500 5.5.1 unrecognised")
		}
	}
}

// addressIn pulls the address out of "MAIL FROM:<a@b>" or "RCPT TO:<a@b>".
func addressIn(line string) string {
	i := strings.Index(line, "<")
	j := strings.LastIndex(line, ">")
	if i >= 0 && j > i {
		return line[i+1 : j]
	}
	if k := strings.Index(line, ":"); k >= 0 {
		return strings.TrimSpace(line[k+1:])
	}
	return ""
}

func selfSigned() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "smtptest"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:     []string{"localhost", "smtptest"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, nil
}

var ErrClosed = errors.New("smtptest: server closed")
