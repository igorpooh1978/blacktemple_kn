package dns

import (
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/routing"
)

func TestProxiedDomainDoesNotPickDirect(t *testing.T) {
	rt, err := routing.Build(routing.Input{
		Mode: routing.ModeSelected,
		Rules: []routing.Rule{
			{
				ID:      "yt",
				Source:  routing.SourceUser,
				Action:  routing.ActionProxy,
				Match:   routing.Match{Kind: routing.MatchDomain, Value: "youtube.com"},
				Enabled: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := Build(rt, DefaultPolicy())
	if got := p.ResolverFor("youtube.com"); got != ResolverProxy {
		t.Fatalf("youtube.com: %s", got)
	}
	if got := p.ResolverFor("www.youtube.com"); got != ResolverProxy {
		t.Fatalf("www.youtube.com: %s", got)
	}
	if got := p.ResolverFor("youtube.com"); got == ResolverDirect {
		t.Fatal("proxied domain accidentally picked direct")
	}
}

func TestPrivateLANNameStaysLocal(t *testing.T) {
	rt, err := routing.Build(routing.Input{Mode: routing.ModeAll})
	if err != nil {
		t.Fatal(err)
	}
	p := Build(rt, DefaultPolicy())
	if got := p.ResolverFor("localhost"); got != ResolverLocal {
		t.Fatalf("localhost: %s", got)
	}
	if got := p.ResolverFor("192.168.1.1"); got != ResolverLocal {
		t.Fatalf("LAN IP: %s", got)
	}
	if got := p.ResolverFor("10.0.0.4"); got != ResolverLocal {
		t.Fatalf("private IP: %s", got)
	}
	if got := p.ResolverFor("127.0.0.1"); got != ResolverLocal {
		t.Fatalf("loopback: %s", got)
	}
}

func TestSelectedDirectUsesIntendedResolver(t *testing.T) {
	rt, err := routing.Build(routing.Input{
		Mode: routing.ModeSelected,
		Rules: []routing.Rule{
			{
				ID:      "sel",
				Source:  routing.SourceUser,
				Action:  routing.ActionProxy,
				Match:   routing.Match{Kind: routing.MatchFullDomain, Value: "need.proxy.example"},
				Enabled: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := Build(rt, DefaultPolicy())
	if p.Default != ResolverDirect {
		t.Fatalf("selected default %s", p.Default)
	}
	if got := p.ResolverFor("need.proxy.example"); got != ResolverProxy {
		t.Fatalf("selected: %s", got)
	}
	if got := p.ResolverFor("plain.example"); got != ResolverDirect {
		t.Fatalf("unselected: %s", got)
	}
}

func TestAllModePublicUsesProxyResolver(t *testing.T) {
	rt, err := routing.Build(routing.Input{Mode: routing.ModeAll})
	if err != nil {
		t.Fatal(err)
	}
	p := Build(rt, DefaultPolicy())
	if p.Default != ResolverProxy {
		t.Fatalf("all default %s", p.Default)
	}
	if got := p.ResolverFor("example.com"); got != ResolverProxy {
		t.Fatalf("public: %s", got)
	}
}

func TestEmptyRemoteListsNoPanic(t *testing.T) {
	rt, err := routing.Build(routing.Input{Mode: routing.ModeSmart, Rules: nil})
	if err != nil {
		t.Fatal(err)
	}
	p := Build(rt, Policy{})
	_ = p.ResolverFor("anything.example")
	if p.Rules == nil {
		t.Fatal("rules slice should be non-nil builtins")
	}
}

func TestFakeDNSFlagOnly(t *testing.T) {
	rt, err := routing.Build(routing.Input{Mode: routing.ModeSmart})
	if err != nil {
		t.Fatal(err)
	}
	p := Build(rt, Policy{FakeDNS: FakeDNS{Enabled: true}, SplitDNS: true})
	if !p.FakeDNS.Enabled {
		t.Fatal("FakeDNS flag must be preserved")
	}
}
