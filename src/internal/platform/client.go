package platform

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// ErrClientRequired is returned when live capture has no safe /32 LAN host.
var ErrClientRequired = fmt.Errorf("platform: selected client IPv4 required")

// ParseSelectedClient accepts a single IPv4 host or IPv4/32.
// It rejects unspecified, multicast, loopback-as-LAN-default, and non-/32 prefixes.
func ParseSelectedClient(raw string) (netip.Addr, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, ErrClientRequired
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %v", ErrClientRequired, err)
		}
		ones := p.Bits()
		if p.Addr().Is4() && ones != 32 {
			return netip.Addr{}, fmt.Errorf("%w: capture client must be exact /32", ErrClientRequired)
		}
		if p.Addr().Is6() {
			return netip.Addr{}, fmt.Errorf("%w: IPv6 client is not used in R6-I", ErrClientRequired)
		}
		s = p.Addr().String()
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", ErrClientRequired, err)
	}
	if !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("%w: need a unicast IPv4 host", ErrClientRequired)
	}
	if !addr.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("%w: client must be RFC1918/LAN", ErrClientRequired)
	}
	oct := addr.As4()
	if oct[3] == 0 || oct[3] == 255 {
		return netip.Addr{}, fmt.Errorf("%w: client must not be network/broadcast", ErrClientRequired)
	}
	return addr, nil
}

// ListRouterIPv4 returns IPv4 addresses currently assigned to local interfaces.
func ListRouterIPv4() []netip.Addr {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifaces {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP.To4())
		if !ok {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// RejectRouterAddress returns ErrClientRequired when client equals a router address.
func RejectRouterAddress(client netip.Addr, router []netip.Addr) error {
	for _, r := range router {
		if r.IsValid() && r == client {
			return fmt.Errorf("%w: client must not be the router address", ErrClientRequired)
		}
	}
	return nil
}

func loadClientString(cmd NFCommand) string {
	if strings.TrimSpace(cmd.Client) != "" {
		return cmd.Client
	}
	if v := strings.TrimSpace(os.Getenv("BTKN_TEST_CLIENT_IPV4")); v != "" {
		return v
	}
	if cmd.ClientFile == "" {
		return ""
	}
	b, err := os.ReadFile(cmd.ClientFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
