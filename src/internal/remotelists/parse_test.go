package remotelists

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestParseDomainsMetadata(t *testing.T) {
	body := []byte(`
# comment
example.com
EXAMPLE.COM
invalid..domain
*.cdn.example.net

not a domain
// also comment
1.2.3.4/24
`)
	p, err := Parse(TypeDomains, body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Entries != 2 {
		t.Fatalf("entries=%d issues=%v", p.Entries, p.Issues)
	}
	if p.Domains[0].Domain != "example.com" || p.Domains[0].Line == 0 {
		t.Fatalf("first=%+v", p.Domains[0])
	}
	if p.Domains[1].Domain != "*.cdn.example.net" {
		t.Fatalf("wild=%+v", p.Domains[1])
	}
	if p.Dupes < 1 || p.Skipped < 2 {
		t.Fatalf("dupes=%d skipped=%d", p.Dupes, p.Skipped)
	}
}

func TestParseCIDRsAndBareIPs(t *testing.T) {
	body := []byte("10.0.0.0/8\n192.0.2.1\n2001:db8::/32\nnot-a-cidr\n10.0.0.0/8\n")
	p, err := Parse(TypeCIDRs, body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Entries != 3 {
		t.Fatalf("entries=%d issues=%v", p.Entries, p.Issues)
	}
	if p.CIDRs[1].Prefix.Bits() != 32 {
		t.Fatalf("bare ip bits=%d", p.CIDRs[1].Prefix.Bits())
	}
}

func TestParseTelegramIPsTypedNoBuiltin(t *testing.T) {
	if hints := BuiltInIPHints(ListIDTelegramIPs); hints != nil {
		t.Fatalf("hardcoded ips: %v", hints)
	}
	p, err := Parse(TypeTelegramIPs, []byte("203.0.113.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeTelegramIPs || p.Entries != 1 {
		t.Fatalf("parsed=%+v", p)
	}
}

func TestParseWhatsAppIPsTyped(t *testing.T) {
	p, err := Parse(TypeWhatsAppIPs, []byte("198.51.100.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeWhatsAppIPs || len(p.CIDRs) != 1 {
		t.Fatalf("parsed=%+v", p)
	}
}

func TestParseProviderFormatsNotImplemented(t *testing.T) {
	types := []ListType{TypeCountries, TypeServers, TypeProviderRouting, TypeGeositeCatalog}
	for _, typ := range types {
		_, err := Parse(typ, []byte(`{"id":"nl"}`))
		if err != ErrProviderFormatNotImplemented {
			t.Fatalf("%s: %v", typ, err)
		}
	}
}

func TestParseInvalidContent(t *testing.T) {
	if _, err := Parse(TypeDomains, []byte("ok.com\x00evil.com")); err != ErrInvalidContent {
		t.Fatalf("nul: %v", err)
	}
	bad := []byte{0xff, 0xfe, 0x00, 0x41}
	if utf8.Valid(bad) {
		t.Fatal("fixture")
	}
	if _, err := Parse(TypeDomains, []byte{0xff, 0xfe, 0x41}); err != ErrInvalidContent {
		t.Fatalf("utf8: %v", err)
	}
}

func TestParseOverlongLineSkipped(t *testing.T) {
	lim := LimitsFor(TypeDomains)
	long := strings.Repeat("a", lim.MaxLine+8) + ".com"
	body := []byte("ok.example\n" + long + "\n")
	p, err := Parse(TypeDomains, body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Entries != 1 || p.Skipped < 1 {
		t.Fatalf("entries=%d skipped=%d issues=%v", p.Entries, p.Skipped, p.Issues)
	}
}

func TestParseUnknownType(t *testing.T) {
	if _, err := Parse(ListType("geoip"), nil); err != ErrUnknownType {
		t.Fatalf("got %v", err)
	}
}

func TestEffectiveMaxBytesCannotExceedHardCap(t *testing.T) {
	if got := EffectiveMaxBytes(TypeDomains, 1<<40); got != maxBytesSmall {
		t.Fatalf("got %d", got)
	}
	if got := EffectiveMaxBytes(TypeGeositeCatalog, 0); got != maxBytesMedium {
		t.Fatalf("medium %d", got)
	}
}

func TestClampTTLHoursNotSeconds(t *testing.T) {
	if ClampTTL(5*time.Second) < minOrdinaryTTL {
		t.Fatal("seconds must clamp to hour")
	}
	if ClampTTL(0) != defaultTTL {
		t.Fatal("zero means default")
	}
	if DefaultTTL() < minOrdinaryTTL {
		t.Fatal("default ttl")
	}
}
