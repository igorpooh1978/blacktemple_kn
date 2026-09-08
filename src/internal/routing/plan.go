package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Input is planner input. Extra Rules may be empty (no panic).
type Input struct {
	Mode      Mode
	Rules     []Rule
	BlockQUIC bool
}

// Plan is a deterministic, sorted routing plan.
//
// BlockQUIC is a policy flag only. FirewallRules is always empty: this package
// must not emit iptables, ip rule, ip route, or ipset.
//
// FailOpen is always true in this wave (kill switch is not implemented).
type Plan struct {
	Mode      Mode
	Rules     []Rule
	BlockQUIC bool
	FailOpen  bool
	Fallback  Action
}

// FirewallRules always returns nil. blockQUIC must not become filter rules.
func (p Plan) FirewallRules() []string {
	return nil
}

// Build validates extra rules, merges builtins, and sorts stably by (priority, id).
func Build(in Input) (Plan, error) {
	if err := in.Mode.Valid(); err != nil {
		return Plan{}, err
	}

	extra := make([]Rule, 0, len(in.Rules))
	seen := make(map[string]struct{}, len(in.Rules)+16)
	for _, id := range reservedBuiltinIDs() {
		seen[id] = struct{}{}
	}

	for i := range in.Rules {
		r := in.Rules[i].clone()
		if err := r.normalize(); err != nil {
			return Plan{}, err
		}
		if _, dup := seen[r.ID]; dup {
			return Plan{}, fmt.Errorf("routing: id %q: %w", r.ID, ErrDuplicateRule)
		}
		seen[r.ID] = struct{}{}
		if !r.Enabled {
			continue
		}
		extra = append(extra, r)
	}

	builtins := builtinRules()
	rules := make([]Rule, 0, len(builtins)+len(extra))
	rules = append(rules, builtins...)
	rules = append(rules, extra...)
	sortStable(rules)

	return Plan{
		Mode:      in.Mode,
		Rules:     rules,
		BlockQUIC: in.BlockQUIC,
		FailOpen:  true,
		Fallback:  fallbackAction(in.Mode),
	}, nil
}

func sortStable(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
}

// ActionForHost returns the first matching action, else Fallback.
// geoip/geosite/protocol/remote-list do not match hosts here.
func (p Plan) ActionForHost(host string) Action {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return p.Fallback
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return p.ActionForIP(ip)
	}
	for _, r := range p.Rules {
		if r.Match.MatchesHost(host) {
			return r.Action
		}
	}
	return p.Fallback
}

// ActionForIP returns the first matching CIDR action, else Fallback.
func (p Plan) ActionForIP(ip netip.Addr) Action {
	for _, r := range p.Rules {
		if r.Match.MatchesIP(ip) {
			return r.Action
		}
	}
	return p.Fallback
}
