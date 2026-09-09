package platform

import (
	"net/netip"
	"testing"
)

func TestParseSelectedClient(t *testing.T) {
	ok, err := ParseSelectedClient("192.168.1.50")
	if err != nil || ok.String() != "192.168.1.50" {
		t.Fatalf("got %v %v", ok, err)
	}
	ok, err = ParseSelectedClient("10.0.0.8/32")
	if err != nil || !ok.Is4() {
		t.Fatalf("cidr /32: %v %v", ok, err)
	}
	for _, bad := range []string{"", "0.0.0.0", "8.8.8.8", "192.168.1.0/24", "192.168.1.0", "192.168.1.255", "224.0.0.1", "not-an-ip", "::1"} {
		if _, err := ParseSelectedClient(bad); err == nil {
			t.Fatalf("expected reject %q", bad)
		}
	}
	if err := RejectRouterAddress(netip.MustParseAddr("192.168.1.1"), []netip.Addr{netip.MustParseAddr("192.168.1.1")}); err == nil {
		t.Fatal("router address must be rejected")
	}
}
