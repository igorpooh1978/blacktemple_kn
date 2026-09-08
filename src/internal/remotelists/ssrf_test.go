package remotelists

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func TestCheckIPBlocksPrivateLoopbackAndSpecial(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"127.0.0.2",
		"::1",
		"10.1.2.3",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.1.1",
		"224.0.0.1",
		"0.0.0.0",
		"::",
		"fe80::1",
		"fd12:3456:789a::1",
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
	}
	for _, s := range blocked {
		ip := netip.MustParseAddr(s)
		if err := CheckIP(ip, false); err != ErrBlockedDestination {
			t.Fatalf("%s: %v", s, err)
		}
		if err := CheckIP(ip, true); err != nil {
			t.Fatalf("trusted %s: %v", s, err)
		}
	}
	if err := CheckIP(netip.MustParseAddr("203.0.113.10"), false); err != nil {
		t.Fatalf("test-net: %v", err)
	}
}

func TestValidateURLSchemes(t *testing.T) {
	g := &Guard{}
	if err := g.ValidateURL("http://203.0.113.10/list", false); err != ErrHTTPSRequired {
		t.Fatalf("http: %v", err)
	}
	if err := g.ValidateURL("https://203.0.113.10/list", false); err != nil {
		t.Fatalf("https public: %v", err)
	}
	if err := g.ValidateURL("https://127.0.0.1/list", false); err != ErrBlockedDestination {
		t.Fatalf("loopback: %v", err)
	}
	if err := g.ValidateURL("https://10.0.0.1/list", false); err != ErrBlockedDestination {
		t.Fatalf("private: %v", err)
	}
	denied := []string{
		"file:///etc/passwd",
		"ftp://203.0.113.10/a",
		"data:text/plain,aaa",
		"unix:///var/run/docker.sock",
		"javascript:alert(1)",
	}
	for _, u := range denied {
		if err := g.ValidateURL(u, true); err != ErrBlockedScheme {
			t.Fatalf("%s trusted still: %v", u, err)
		}
	}
}

func TestCheckRedirectBadTargets(t *testing.T) {
	g := &Guard{}
	check := g.CheckRedirect(false)
	via := []*http.Request{{URL: mustURL("https://203.0.113.10/a")}}
	req := &http.Request{URL: mustURL("https://192.168.0.1/secret")}
	if err := check(req, via); err != ErrRedirect {
		t.Fatalf("private redirect: %v", err)
	}
	req = &http.Request{URL: mustURL("https://127.0.0.1/")}
	if err := check(req, via); err != ErrRedirect {
		t.Fatalf("loopback redirect: %v", err)
	}
	req = &http.Request{URL: mustURL("file:///etc/passwd")}
	if err := g.CheckRedirect(true)(req, via); err != ErrRedirect {
		t.Fatalf("file redirect: %v", err)
	}
}

func TestDNSRebindingProtectionSeam(t *testing.T) {
	var dialed []string
	g := &Guard{
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host == "evil.example" {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			if host == "ok.example" {
				return []netip.Addr{netip.MustParseAddr("203.0.113.50")}, nil
			}
			return nil, errors.New("unexpected host " + host)
		},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			return nil, errors.New("stop")
		},
	}
	ctx := context.Background()
	_, err := g.DialContext(false)(ctx, "tcp", "evil.example:443")
	if err != ErrBlockedDestination {
		t.Fatalf("rebinding host: %v", err)
	}
	if len(dialed) != 0 {
		t.Fatalf("must not dial loopback via hostname: %v", dialed)
	}

	_, err = g.DialContext(false)(ctx, "tcp", "ok.example:443")
	if err == nil || err.Error() != "stop" {
		t.Fatalf("ok dial: %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "203.0.113.50:443" {
		t.Fatalf("must pin resolved IP at connect, got %v", dialed)
	}
}

func TestDefaultBackoffIsHours(t *testing.T) {
	b := ExponentialBackoff{Base: time.Hour, Max: 24 * time.Hour, Jitter: 0}
	if b.Next(1) != time.Hour {
		t.Fatalf("attempt1=%s", b.Next(1))
	}
	if b.Next(2) != 2*time.Hour {
		t.Fatalf("attempt2=%s", b.Next(2))
	}
	if b.Next(10) != 24*time.Hour {
		t.Fatalf("cap=%s", b.Next(10))
	}
	if DefaultRefreshInterval() < time.Hour {
		t.Fatal("refresh interval")
	}
}

func TestBackoffJitterUsesInjectedRand(t *testing.T) {
	b := ExponentialBackoff{
		Base:   time.Hour,
		Max:    24 * time.Hour,
		Jitter: 0.5,
		Rand:   func() float64 { return 1 },
	}
	// d * (1 + 0.5) = 1.5h
	if b.Next(1) != time.Duration(float64(time.Hour)*1.5) {
		t.Fatalf("got %s", b.Next(1))
	}
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
