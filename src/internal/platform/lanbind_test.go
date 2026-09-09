package platform

import (
	"net"
	"testing"
)

func TestLANBindPrefersBr0PrivateNotWAN(t *testing.T) {
	br0 := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.17.100.1"), Mask: net.CIDRMask(24, 32)},
	}
	wan := []net.Addr{
		&net.IPNet{IP: net.ParseIP("100.88.1.1"), Mask: net.CIDRMask(16, 32)},
	}
	if got := firstPrivateIPv4(br0); got != "172.17.100.1" {
		t.Fatalf("br0 DHCP gateway got %q", got)
	}
	if got := firstPrivateIPv4(wan); got != "" {
		t.Fatalf("WAN/CGNAT must not be a UI bind address, got %q", got)
	}
	loop := []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}}
	if got := firstPrivateIPv4(loop); got != "" {
		t.Fatalf("loopback must not win LAN bind, got %q", got)
	}
	all := []net.Addr{
		&net.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)},
	}
	if got := firstPrivateIPv4(all); got != "192.168.1.1" {
		t.Fatalf("skip unspecified, got %q", got)
	}
}
