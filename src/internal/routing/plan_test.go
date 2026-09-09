package routing

import (
	"errors"
	"net/netip"
	"testing"
)

func TestDeterministicOrdering(t *testing.T) {
	in := Input{
		Mode: ModeSmart,
		Rules: []Rule{
			{ID: "b-user", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "b.example"}, Enabled: true, Priority: PriorityUserOverride},
			{ID: "a-user", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "a.example"}, Enabled: true, Priority: PriorityUserOverride},
			{ID: "z-list", Source: SourceRemoteList, Action: ActionProxy, Match: Match{Kind: MatchGeoSite, Value: "youtube"}, Enabled: true},
			{ID: "m-list", Source: SourceRemoteList, Action: ActionProxy, Match: Match{Kind: MatchGeoSite, Value: "telegram"}, Enabled: true},
		},
	}
	p1, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Rules) != len(p2.Rules) {
		t.Fatalf("len %d vs %d", len(p1.Rules), len(p2.Rules))
	}
	for i := range p1.Rules {
		if p1.Rules[i].ID != p2.Rules[i].ID || p1.Rules[i].Priority != p2.Rules[i].Priority {
			t.Fatalf("order drift at %d: %s vs %s", i, p1.Rules[i].ID, p2.Rules[i].ID)
		}
	}
	for i := 1; i < len(p1.Rules); i++ {
		prev, cur := p1.Rules[i-1], p1.Rules[i]
		if prev.Priority > cur.Priority {
			t.Fatalf("priority not sorted: %s:%d then %s:%d", prev.ID, prev.Priority, cur.ID, cur.Priority)
		}
		if prev.Priority == cur.Priority && prev.ID > cur.ID {
			t.Fatalf("id not sorted at equal priority: %s then %s", prev.ID, cur.ID)
		}
	}
	if idx("a-user", p1) > idx("b-user", p1) {
		t.Fatal("same-band ids must sort lexicographically")
	}
	if p1.Rules[idx("a-user", p1)].Priority >= p1.Rules[idx("m-list", p1)].Priority {
		t.Fatal("user override must precede remote list")
	}
}

func idx(id string, p Plan) int {
	for i, r := range p.Rules {
		if r.ID == id {
			return i
		}
	}
	return -1
}

func TestPrivateDirect(t *testing.T) {
	for _, mode := range []Mode{ModeSmart, ModeAll, ModeSelected} {
		p, err := Build(Input{Mode: mode})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		cases := []string{"10.1.2.3", "192.168.0.1", "172.16.9.9", "127.0.0.1", "::1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "ff02::1"}
		for _, s := range cases {
			ip := netip.MustParseAddr(s)
			if got := p.ActionForIP(ip); got != ActionDirect {
				t.Errorf("%s %s: got %s want direct", mode, s, got)
			}
		}
		if p.ActionForHost("localhost") != ActionDirect {
			t.Errorf("%s localhost: want direct", mode)
		}
	}
}

func TestAllFallback(t *testing.T) {
	p, err := Build(Input{Mode: ModeAll})
	if err != nil {
		t.Fatal(err)
	}
	if p.Fallback != ActionProxy {
		t.Fatalf("fallback %s", p.Fallback)
	}
	if p.ActionForHost("example.com") != ActionProxy {
		t.Fatal("unmatched in all must PROXY")
	}
	if p.ActionForIP(netip.MustParseAddr("8.8.8.8")) != ActionProxy {
		t.Fatal("public IP in all must PROXY")
	}
	if !p.FailOpen {
		t.Fatal("kill switch is not implemented; fail-open required")
	}
}

func TestSelectedFallback(t *testing.T) {
	p, err := Build(Input{
		Mode: ModeSelected,
		Rules: []Rule{
			{ID: "sel-yt", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "youtube.com"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Fallback != ActionDirect {
		t.Fatalf("fallback %s", p.Fallback)
	}
	if p.ActionForHost("youtube.com") != ActionProxy {
		t.Fatal("selected domain must PROXY")
	}
	if p.ActionForHost("www.youtube.com") != ActionProxy {
		t.Fatal("selected domain must include subdomain")
	}
	if p.ActionForHost("example.com") != ActionDirect {
		t.Fatal("unmatched selected must DIRECT")
	}
}

func TestSmartEmptyListsNoPanic(t *testing.T) {
	p, err := Build(Input{Mode: ModeSmart, Rules: nil})
	if err != nil {
		t.Fatal(err)
	}
	if p.Fallback != ActionDirect {
		t.Fatalf("smart empty lists fallback=%s", p.Fallback)
	}
	if p.ActionForHost("missing.example") != ActionDirect {
		t.Fatal("smart with empty extra lists must not panic and must fallback")
	}
}

func TestInvalidRule(t *testing.T) {
	cases := []Input{
		{Mode: Mode("nope")},
		{Mode: ModeSmart, Rules: []Rule{{ID: "", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "a.com"}, Enabled: true}}},
		{Mode: ModeSmart, Rules: []Rule{{ID: "x", Source: Source("nope"), Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "a.com"}, Enabled: true}}},
		{Mode: ModeSmart, Rules: []Rule{{ID: "x", Source: SourceUser, Action: Action("drop"), Match: Match{Kind: MatchDomain, Value: "a.com"}, Enabled: true}}},
		{Mode: ModeSmart, Rules: []Rule{{ID: "x", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchKind("glob"), Value: "a.com"}, Enabled: true}}},
		{Mode: ModeSmart, Rules: []Rule{{ID: "x", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchCIDR, Value: "not-a-cidr"}, Enabled: true}}},
		{Mode: ModeSmart, Rules: []Rule{{ID: "x", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: ""}, Enabled: true}}},
		{Mode: ModeSmart, Rules: []Rule{{ID: "x", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchGeoIP, Value: ""}, Enabled: true}}},
	}
	for i, in := range cases {
		_, err := Build(in)
		if err == nil {
			t.Fatalf("case %d: expected error", i)
		}
		if !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
}

func TestDuplicateRule(t *testing.T) {
	_, err := Build(Input{
		Mode: ModeSmart,
		Rules: []Rule{
			{ID: "dup", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "a.com"}, Enabled: true},
			{ID: "dup", Source: SourceUser, Action: ActionDirect, Match: Match{Kind: MatchDomain, Value: "b.com"}, Enabled: true},
		},
	})
	if !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("got %v", err)
	}

	_, err = Build(Input{
		Mode: ModeSmart,
		Rules: []Rule{
			{ID: "builtin-localhost-name", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "a.com"}, Enabled: true},
		},
	})
	if !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("reserved id: %v", err)
	}
}

func TestGeoIPGeoSiteReferencePreservation(t *testing.T) {
	p, err := Build(Input{
		Mode: ModeSmart,
		Rules: []Rule{
			{ID: "geo-cn", Source: SourceProvider, Action: ActionDirect, Match: Match{Kind: MatchGeoIP, Value: "geoip:cn"}, Enabled: true},
			{ID: "site-yt", Source: SourceRemoteList, Action: ActionProxy, Match: Match{Kind: MatchGeoSite, Value: "youtube"}, Enabled: true},
			{ID: "proto", Source: SourceUser, Action: ActionBlock, Match: Match{Kind: MatchProtocol, Value: "bittorrent"}, Enabled: true},
			{ID: "rlist", Source: SourceRemoteList, Action: ActionProxy, Match: Match{Kind: MatchRemoteList, Value: "telegram-ips"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	geo := p.Rules[idx("geo-cn", p)]
	if geo.Match.Kind != MatchGeoIP || geo.Match.Value != "cn" || geo.Match.GeoReference() != "geoip:cn" {
		t.Fatalf("geoip not preserved: %+v", geo.Match)
	}
	site := p.Rules[idx("site-yt", p)]
	if site.Match.Kind != MatchGeoSite || site.Match.Value != "youtube" || site.Match.GeoReference() != "geosite:youtube" {
		t.Fatalf("geosite not preserved: %+v", site.Match)
	}
	if p.ActionForHost("youtube.com") != p.Fallback {
		t.Fatal("geosite must not be resolved against a host")
	}
}

func TestBlockQUICDoesNotEmitFirewall(t *testing.T) {
	p, err := Build(Input{Mode: ModeAll, BlockQUIC: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.BlockQUIC {
		t.Fatal("flag must be kept")
	}
	if rules := p.FirewallRules(); len(rules) != 0 {
		t.Fatalf("firewall rules emitted: %v", rules)
	}
}

func TestDisabledRuleOmitted(t *testing.T) {
	p, err := Build(Input{
		Mode: ModeSelected,
		Rules: []Rule{
			{ID: "off", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "off.example"}, Enabled: false},
			{ID: "on", Source: SourceUser, Action: ActionProxy, Match: Match{Kind: MatchDomain, Value: "on.example"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if idx("off", p) != -1 {
		t.Fatal("disabled rule must be omitted")
	}
	if idx("on", p) < 0 {
		t.Fatal("enabled rule missing")
	}
}

func TestLANDeviceUnused(t *testing.T) {
	p, err := Build(Input{
		Mode: ModeSmart,
		Rules: []Rule{{
			ID:     "dev",
			Source: SourceUser,
			Action: ActionProxy,
			Match: Match{
				Kind:      MatchDomain,
				Value:     "only-host.example",
				LANDevice: LANDevice{IP: "10.0.0.50", MAC: "aa:bb", Hostname: "phone"},
			},
			Enabled: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Rules[idx("dev", p)]
	if r.Match.LANDevice.IP != "10.0.0.50" {
		t.Fatal("LANDevice field must be preserved even when unused")
	}
	if p.ActionForIP(netip.MustParseAddr("10.0.0.50")) != ActionDirect {
		t.Fatal("LAN device IP must not match via unused LANDevice field")
	}
}
