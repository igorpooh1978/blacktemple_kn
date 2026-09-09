package routing

import "net/netip"

// Builtin private/LAN, localhost, multicast, and broadcast CIDRs.
// Order is the single source of truth; never derived from map iteration.
// Capture engines must use BuiltinDirectPrefixes / IPv4DirectPrefixes
// rather than copying this list.
var (
	privateCIDRs = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
	localhostCIDRs = []string{
		"127.0.0.0/8",
		"::1/128",
	}
	multicastBroadcastCIDRs = []string{
		"224.0.0.0/4",
		"255.255.255.255/32",
		"ff00::/8",
	}
)

// BuiltinDirectPrefixes returns destinations that must stay DIRECT
// (loopback, RFC1918, link-local, multicast, broadcast).
func BuiltinDirectPrefixes() []netip.Prefix {
	n := len(privateCIDRs) + len(localhostCIDRs) + len(multicastBroadcastCIDRs)
	out := make([]netip.Prefix, 0, n)
	for _, cidr := range privateCIDRs {
		if p := parsePrefix(cidr); p.IsValid() {
			out = append(out, p)
		}
	}
	for _, cidr := range localhostCIDRs {
		if p := parsePrefix(cidr); p.IsValid() {
			out = append(out, p)
		}
	}
	for _, cidr := range multicastBroadcastCIDRs {
		if p := parsePrefix(cidr); p.IsValid() {
			out = append(out, p)
		}
	}
	return out
}

// IPv4DirectPrefixes returns the IPv4 subset of BuiltinDirectPrefixes.
func IPv4DirectPrefixes() []netip.Prefix {
	all := BuiltinDirectPrefixes()
	out := make([]netip.Prefix, 0, len(all))
	for _, p := range all {
		if p.Addr().Is4() {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}
	}
	return p.Masked()
}

func builtinRules() []Rule {
	out := make([]Rule, 0, len(privateCIDRs)+len(localhostCIDRs)+len(multicastBroadcastCIDRs)+1)
	for i, cidr := range privateCIDRs {
		pfx := parsePrefix(cidr)
		if !pfx.IsValid() {
			continue
		}
		out = append(out, Rule{
			ID:       builtinID("private", i, pfx.String()),
			Source:   SourceBuiltin,
			Priority: PriorityBuiltinSmart,
			Action:   ActionDirect,
			Match:    Match{Kind: MatchCIDR, Value: pfx.String(), Prefix: pfx},
			Enabled:  true,
		})
	}
	for i, cidr := range localhostCIDRs {
		pfx := parsePrefix(cidr)
		if !pfx.IsValid() {
			continue
		}
		out = append(out, Rule{
			ID:       builtinID("localhost", i, pfx.String()),
			Source:   SourceBuiltin,
			Priority: PriorityBuiltinSmart,
			Action:   ActionDirect,
			Match:    Match{Kind: MatchCIDR, Value: pfx.String(), Prefix: pfx},
			Enabled:  true,
		})
	}
	for i, cidr := range multicastBroadcastCIDRs {
		pfx := parsePrefix(cidr)
		if !pfx.IsValid() {
			continue
		}
		group := "multicast"
		if pfx.Addr().Is4() && pfx.Addr().As4() == [4]byte{255, 255, 255, 255} {
			group = "broadcast"
		}
		out = append(out, Rule{
			ID:       builtinID(group, i, pfx.String()),
			Source:   SourceBuiltin,
			Priority: PriorityBuiltinSmart,
			Action:   ActionDirect,
			Match:    Match{Kind: MatchCIDR, Value: pfx.String(), Prefix: pfx},
			Enabled:  true,
		})
	}
	out = append(out, Rule{
		ID:       "builtin-localhost-name",
		Source:   SourceBuiltin,
		Priority: PriorityBuiltinSmart,
		Action:   ActionDirect,
		Match:    Match{Kind: MatchFullDomain, Value: "localhost"},
		Enabled:  true,
	})
	return out
}

func builtinID(group string, i int, suffix string) string {
	return "builtin-" + group + "-" + itoa(i) + "-" + sanitizeID(suffix)
}

func sanitizeID(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b = append(b, c)
		default:
			b = append(b, '-')
		}
	}
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func reservedBuiltinIDs() []string {
	rules := builtinRules()
	ids := make([]string, 0, len(rules)+1)
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	ids = append(ids, "builtin-fallback")
	return ids
}

func fallbackAction(mode Mode) Action {
	switch mode {
	case ModeAll:
		return ActionProxy
	default:
		// Smart: unmatched waits for geodata/remote/user/provider; empty lists
		// do not panic. Fail-open: unmatched is DIRECT.
		// Selected: only selected rules are PROXY; unmatched is DIRECT.
		return ActionDirect
	}
}
