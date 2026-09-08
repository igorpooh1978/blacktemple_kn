package dns

import "github.com/igorpooh1978/blacktemple_kn/src/internal/routing"

// ResolverKind is which resolver a query should use.
type ResolverKind string

const (
	ResolverLocal  ResolverKind = "local"   // LAN / local DNS
	ResolverDirect ResolverKind = "direct"  // Direct DNS (not through VPN)
	ResolverProxy  ResolverKind = "proxy"   // VPN / Xray resolver (model only)
	ResolverFake   ResolverKind = "fakedns" // optional FakeDNS; not a daemon
)

// Endpoint is an informational resolver address. Nothing is bound.
type Endpoint struct {
	Kind    ResolverKind
	Address string
}

// FakeDNS is optional. When enabled it is a plan flag for Xray FakeDNS later.
type FakeDNS struct {
	Enabled bool
}

// Policy describes available resolvers. Split DNS is the intended model:
// private/LAN → local/direct; proxied domains → proxy; direct domains → direct.
type Policy struct {
	Direct   Endpoint
	Proxy    Endpoint
	Local    Endpoint
	FakeDNS  FakeDNS
	SplitDNS bool
}

func DefaultPolicy() Policy {
	return Policy{
		Local:    Endpoint{Kind: ResolverLocal},
		Direct:   Endpoint{Kind: ResolverDirect},
		Proxy:    Endpoint{Kind: ResolverProxy},
		SplitDNS: true,
	}
}

// Rule is one DNS split-horizon entry, derived from a routing rule.
type Rule struct {
	ID       string
	Priority int
	Match    routing.Match
	Resolver ResolverKind
}

// Plan is a deterministic DNS plan. Empty remote lists do not panic.
type Plan struct {
	SplitDNS bool
	FakeDNS  FakeDNS
	Rules    []Rule
	Default  ResolverKind
}
