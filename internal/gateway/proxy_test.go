package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The header is read only from a trusted peer, and then the caller is the
// rightmost hop we did not add ourselves.
func TestTheForwardedHeaderIsReadOnlyFromATrustedProxy(t *testing.T) {
	lb, _ := ParseTrustedProxies("203.0.113.50, 10.0.0.0/8")
	for _, c := range []struct {
		name, remote, xff, want string
	}{
		{"no proxies configured: the header is ignored",
			"203.0.113.50:1", "198.51.100.1", "203.0.113.50"},
		{"a stranger sending the header gets their own address",
			"198.51.100.7:1", "1.2.3.4", "198.51.100.7"},
		{"the balancer speaks for its client",
			"203.0.113.50:1", "198.51.100.1", "198.51.100.1"},
		{"two of our hops: the rightmost untrusted entry is the client",
			"10.0.0.9:1", "1.2.3.4, 198.51.100.1, 203.0.113.50", "198.51.100.1"},
		{"a client-written leading entry is not believed",
			"203.0.113.50:1", "9.9.9.9, 198.51.100.1", "198.51.100.1"},
		{"the header carries only our own hops: the proxy itself",
			"203.0.113.50:1", "10.0.0.3", "203.0.113.50"},
		{"no header from a trusted peer: the peer",
			"203.0.113.50:1", "", "203.0.113.50"},
		{"junk in the header: the peer",
			"203.0.113.50:1", "not-an-address", "203.0.113.50"},
		{"ipv6 with a port",
			"[2001:db8::1]:443", "", "2001:db8::1"},
	} {
		trusted := lb
		if strings.HasPrefix(c.name, "no proxies") {
			trusted = nil
		}
		if got := callerAddr(c.remote, c.xff, trusted); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if _, err := ParseTrustedProxies("10.0.0.0/8, nonsense"); err == nil {
		t.Fatal("a bad entry was accepted")
	}
}

// End to end on the one route that keys on the caller: the sign-up cap.
func TestASpoofedAddressDoesNotEscapeTheSignupCap(t *testing.T) {
	f := withSignup(t, newFixture(t))

	// Nobody trusted. Ten from one socket, each claiming to be somebody
	// else, and the eleventh is refused: the claims counted for nothing.
	for i := 0; i < 10; i++ {
		rec := forwarded(t, f, "198.51.100.7", "1.2.3."+string(rune('0'+i)),
			"p@co"+string(rune('a'+i))+".example")
		if rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if rec := forwarded(t, f, "198.51.100.7", "9.9.9.9", "p@other.example"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a spoofed address escaped the cap: %d", rec.Code)
	}

	// Now the socket peer is a trusted balancer, and the header is the
	// client. Ten different clients through it are ten callers.
	f.g.trustedProxies, _ = ParseTrustedProxies("203.0.113.50")
	for i := 0; i < 10; i++ {
		rec := forwarded(t, f, "203.0.113.50", "100.64.0."+string(rune('0'+i)),
			"q@co"+string(rune('a'+i))+".example")
		if rec.Code != 200 {
			t.Fatalf("via proxy, client %d: %d", i, rec.Code)
		}
	}
	// And one client through it ten more times is one caller, capped.
	for i := 0; i < 10; i++ {
		rec := forwarded(t, f, "203.0.113.50", "100.64.1.1", "r@co"+string(rune('a'+i))+".example")
		if rec.Code != 200 {
			t.Fatalf("via proxy, same client %d: %d", i, rec.Code)
		}
	}
	if rec := forwarded(t, f, "203.0.113.50", "100.64.1.1", "r@other.example"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("one client through the proxy escaped the cap: %d", rec.Code)
	}
}

func forwarded(t *testing.T, f fixture, peer, xff, email string) *httptest.ResponseRecorder {
	t.Helper()
	vals := url.Values{"email": {email}, "company": {"Co"}}
	r := httptest.NewRequest("POST", "http://"+signupHost+"/signup", strings.NewReader(vals.Encode()))
	r.Host = signupHost
	r.RemoteAddr = peer + ":40000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Forwarded-For", xff)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}
