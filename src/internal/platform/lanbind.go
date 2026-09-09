package platform

import (
	"fmt"
	"net"
	"net/netip"
)

// BridgeLAN resolves the HTTP bind host from Keenetic LAN bridges.
// br0 is the DHCP gateway network; br1 is fallback. WAN/CGNAT addresses
// are never returned.
type BridgeLAN struct{}

// LANHost implements app.LANResolver.
func (BridgeLAN) LANHost() (string, error) {
	return LANBindIPv4()
}

// LANBindIPv4 returns the first RFC1918 IPv4 on br0, then br1.
func LANBindIPv4() (string, error) {
	for _, name := range []string{"br0", "br1"} {
		ip := privateIPv4OnInterface(name)
		if ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("platform: no RFC1918 IPv4 on br0/br1")
}

func privateIPv4OnInterface(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	return firstPrivateIPv4(addrs)
}

func firstPrivateIPv4(addrs []net.Addr) string {
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip.To4())
		if !ok {
			continue
		}
		if !addr.IsPrivate() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		return addr.String()
	}
	return ""
}
