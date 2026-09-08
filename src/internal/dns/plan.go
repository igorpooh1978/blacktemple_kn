package dns

import (
	"net/netip"
	"strings"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/routing"
)

func resolverForRouting(action routing.Action, match routing.Match) ResolverKind {
	if match.IsPrivateOrLocal() {
		return ResolverLocal
	}
	switch action {
	case routing.ActionProxy:
		return ResolverProxy
	case routing.ActionDirect, routing.ActionBlock:
		return ResolverDirect
	default:
		return ResolverDirect
	}
}

func defaultResolver(action routing.Action) ResolverKind {
	if action == routing.ActionProxy {
		return ResolverProxy
	}
	return ResolverDirect
}

// Build derives a DNS plan from a routing plan. Extra/remote lists may be empty.
func Build(rt routing.Plan, pol Policy) Plan {
	if pol.Local.Kind == "" {
		pol.Local = Endpoint{Kind: ResolverLocal}
	}
	if pol.Direct.Kind == "" {
		pol.Direct = Endpoint{Kind: ResolverDirect}
	}
	if pol.Proxy.Kind == "" {
		pol.Proxy = Endpoint{Kind: ResolverProxy}
	}
	rules := make([]Rule, 0, len(rt.Rules))
	for _, r := range rt.Rules {
		rules = append(rules, Rule{
			ID:       r.ID,
			Priority: r.Priority,
			Match:    r.Match,
			Resolver: resolverForRouting(r.Action, r.Match),
		})
	}
	return Plan{
		SplitDNS: pol.SplitDNS,
		FakeDNS:  pol.FakeDNS,
		Rules:    rules,
		Default:  defaultResolver(rt.Fallback),
	}
}

// ResolverFor picks the first matching rule, else Default.
// Proxied domain rules must not fall through to the direct resolver.
func (p Plan) ResolverFor(name string) ResolverKind {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return p.Default
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		for _, r := range p.Rules {
			if r.Match.MatchesIP(ip) {
				return r.Resolver
			}
		}
		return p.Default
	}
	for _, r := range p.Rules {
		if r.Match.MatchesHost(name) {
			return r.Resolver
		}
	}
	return p.Default
}
