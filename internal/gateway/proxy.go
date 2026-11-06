package gateway

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Who is calling, when there is a proxy in the way.
//
// X-Forwarded-For is a header anybody can send. Trusting it from everyone
// means a stranger picks their own address, and every per-address limit in
// the platform becomes a suggestion. Trusting it from nobody means that
// behind a load balancer every caller is the balancer, and the same limits
// collapse to one bucket for the whole internet.
//
// The rule here is the usual one, stated so it can be tested: the header is
// read ONLY when the socket peer is a trusted proxy, and then the caller is
// the rightmost entry that is not itself a trusted proxy. Entries to the
// left of that were written by whoever was in front of our first proxy, and
// that could be the stranger.

// callerAddr applies the rule. remote is the socket peer as Go reports it
// (host:port). It returns an address, never empty, never with a port.
func callerAddr(remote, forwardedFor string, trusted []netip.Prefix) string {
	peer := hostOnly(remote)
	if len(trusted) == 0 || !inAny(peer, trusted) {
		return peer
	}
	// Right to left: the last hop we did not add ourselves.
	parts := strings.Split(forwardedFor, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop := hostOnly(strings.TrimSpace(parts[i]))
		if hop == "" {
			continue
		}
		if _, err := netip.ParseAddr(hop); err != nil {
			// A header with something that is not an address in it is a
			// header we do not understand. The peer is the only address
			// we are sure of.
			return peer
		}
		if !inAny(hop, trusted) {
			return hop
		}
	}
	// Every entry was one of ours, or there were none: the proxy spoke for
	// itself.
	return peer
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.Trim(s, "[]")
}

func inAny(addr string, prefixes []netip.Prefix) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies reads the operator's list: comma-separated CIDRs, or
// bare addresses which mean that one host.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// callerIP is callerAddr on a request, with this gateway's trusted set.
func (g *Gateway) callerIP(r *http.Request) string {
	return callerAddr(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), g.trustedProxies)
}
