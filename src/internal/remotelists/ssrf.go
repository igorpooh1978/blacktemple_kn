package remotelists

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// LookupFunc resolves a hostname to addresses. Tests inject a fake resolver
// so DNS-rebinding protection can be exercised without the public internet.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// DialFunc opens a TCP connection to an already-checked host:port.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Guard enforces URL scheme and destination checks at request time and at dial.
type Guard struct {
	Lookup LookupFunc
	Dial   DialFunc
}

func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func defaultDial(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, network, address)
}

func (g *Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if g != nil && g.Lookup != nil {
		return g.Lookup(ctx, host)
	}
	return defaultLookup(ctx, host)
}

func (g *Guard) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if g != nil && g.Dial != nil {
		return g.Dial(ctx, network, address)
	}
	return defaultDial(ctx, network, address)
}

// ValidateURL checks scheme and, for IP literals, the destination. Hostnames
// are resolved and checked in DialContext so the connect-time address is used.
func (g *Guard) ValidateURL(raw string, trusted bool) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return ErrBlockedScheme
	}
	return g.ValidateParsed(u, trusted)
}

// ValidateParsed checks a parsed URL (including redirect targets).
func (g *Guard) ValidateParsed(u *url.URL, trusted bool) error {
	if u == nil {
		return ErrBlockedScheme
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		// default allow
	case "http":
		if !trusted {
			return ErrHTTPSRequired
		}
	case "file", "ftp", "data", "unix", "javascript", "gopher", "ws", "wss":
		return ErrBlockedScheme
	default:
		return ErrBlockedScheme
	}
	host := u.Hostname()
	if host == "" {
		return ErrBlockedDestination
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return CheckIP(ip, trusted)
	}
	return nil
}

// ResolveAndCheck resolves host and requires every address to be allowed.
// Used for redirect checks and pre-dial hostname policy.
func (g *Guard) ResolveAndCheck(ctx context.Context, host string, trusted bool) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := CheckIP(ip, trusted); err != nil {
			return nil, err
		}
		return []netip.Addr{ip}, nil
	}
	ips, err := g.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, ErrBlockedDestination
	}
	var out []netip.Addr
	for _, ip := range ips {
		if err := CheckIP(ip, trusted); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, nil
}

// DialContext resolves, verifies every IP, then dials a numeric address so a
// later DNS rebinding cannot change the connected destination.
func (g *Guard) DialContext(trusted bool) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := g.ResolveAndCheck(ctx, host, trusted)
		if err != nil {
			return nil, err
		}
		var last error
		for _, ip := range ips {
			// Re-verify immediately before connect (rebinding seam).
			if err := CheckIP(ip, trusted); err != nil {
				last = err
				continue
			}
			target := net.JoinHostPort(ip.String(), port)
			c, err := g.dial(ctx, network, target)
			if err == nil {
				return c, nil
			}
			last = err
		}
		if last == nil {
			return nil, ErrBlockedDestination
		}
		return nil, last
	}
}

// CheckRedirect rejects disallowed schemes and destinations. The same
// TrustedOrigin flag as the original request is applied.
func (g *Guard) CheckRedirect(trusted bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return ErrTooManyRedirects
		}
		if req == nil || req.URL == nil {
			return ErrRedirect
		}
		if err := g.ValidateParsed(req.URL, trusted); err != nil {
			return ErrRedirect
		}
		host := req.URL.Hostname()
		if host == "" {
			return ErrRedirect
		}
		if _, err := g.ResolveAndCheck(req.Context(), host, trusted); err != nil {
			return ErrRedirect
		}
		return nil
	}
}

// CheckIP reports whether an address is allowed as a remote-list destination.
func CheckIP(ip netip.Addr, trusted bool) error {
	if !ip.IsValid() {
		return ErrBlockedDestination
	}
	ip = ip.Unmap()
	if trusted {
		return nil
	}
	if ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsInterfaceLocalMulticast() {
		return ErrBlockedDestination
	}
	if isUniqueLocal(ip) || isRouterLocal(ip) {
		return ErrBlockedDestination
	}
	return nil
}

func isUniqueLocal(ip netip.Addr) bool {
	if !ip.Is6() {
		return false
	}
	// fc00::/7
	b := ip.As16()
	return b[0]&0xfe == 0xfc
}

func isRouterLocal(ip netip.Addr) bool {
	// Keenetic LAN and typical router-own addresses are RFC1918 (already
	// IsPrivate). Also treat IPv4 link-local as router-adjacent.
	if ip.Is4() {
		a := ip.As4()
		if a[0] == 169 && a[1] == 254 {
			return true
		}
	}
	return false
}

func newHTTPClient(g *Guard, trusted bool, timeout time.Duration, base *http.Client) *http.Client {
	if timeout <= 0 {
		timeout = defaultFetchTimeout
	}
	var transport *http.Transport
	if base != nil && base.Transport != nil {
		if t, ok := base.Transport.(*http.Transport); ok && t != nil {
			transport = t.Clone()
		}
	}
	if transport == nil {
		transport = &http.Transport{}
	}
	transport.DialContext = g.DialContext(trusted)
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: g.CheckRedirect(trusted),
		Timeout:       timeout,
	}
	if base != nil && base.Jar != nil {
		client.Jar = base.Jar
	}
	return client
}
