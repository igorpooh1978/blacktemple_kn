package routing

import (
	"fmt"
	"net/netip"
	"strings"
)

// MatchKind is how a rule selects traffic. geoip/geosite are references only.
type MatchKind string

const (
	MatchDomain     MatchKind = "domain"
	MatchFullDomain MatchKind = "full-domain"
	MatchSuffix     MatchKind = "suffix"
	MatchCIDR       MatchKind = "cidr"
	MatchGeoIP      MatchKind = "geoip"
	MatchGeoSite    MatchKind = "geosite"
	MatchProtocol   MatchKind = "protocol"
	MatchRemoteList MatchKind = "remote-list"
)

func (k MatchKind) Valid() error {
	switch k {
	case MatchDomain, MatchFullDomain, MatchSuffix, MatchCIDR,
		MatchGeoIP, MatchGeoSite, MatchProtocol, MatchRemoteList:
		return nil
	default:
		return fmt.Errorf("routing: invalid match kind %q: %w", k, ErrInvalidRule)
	}
}

// LANDevice is a typed per-device selector reserved for a later wave.
// The planner does not evaluate it; PriorityDeviceOverride exists only as a band.
type LANDevice struct {
	IP       string
	MAC      string
	Hostname string
	Alias    string
}

// Match selects traffic. GeoIP/GeoSite values stay as tags (geoip:cn, geosite:youtube);
// this package never opens geoip.dat / geosite.dat.
type Match struct {
	Kind      MatchKind
	Value     string
	Prefix    netip.Prefix
	LANDevice LANDevice // unused by the planner
}

func (m *Match) normalize() error {
	if m == nil {
		return fmt.Errorf("routing: nil match: %w", ErrInvalidRule)
	}
	if err := m.Kind.Valid(); err != nil {
		return err
	}
	m.Value = strings.TrimSpace(m.Value)
	switch m.Kind {
	case MatchCIDR:
		if !m.Prefix.IsValid() {
			pfx, err := netip.ParsePrefix(m.Value)
			if err != nil {
				return fmt.Errorf("routing: invalid CIDR %q: %w", m.Value, ErrInvalidRule)
			}
			m.Prefix = pfx
		}
		m.Prefix = m.Prefix.Masked()
		m.Value = m.Prefix.String()
	case MatchDomain, MatchFullDomain, MatchSuffix:
		m.Value = strings.ToLower(strings.TrimSuffix(m.Value, "."))
		if m.Value == "" {
			return fmt.Errorf("routing: empty %s match: %w", m.Kind, ErrInvalidRule)
		}
	case MatchGeoIP:
		m.Value = stripRefPrefix(strings.ToLower(m.Value), "geoip:")
		if m.Value == "" {
			return fmt.Errorf("routing: empty geoip match: %w", ErrInvalidRule)
		}
	case MatchGeoSite:
		m.Value = stripRefPrefix(strings.ToLower(m.Value), "geosite:")
		if m.Value == "" {
			return fmt.Errorf("routing: empty geosite match: %w", ErrInvalidRule)
		}
	case MatchProtocol:
		m.Value = strings.ToLower(m.Value)
		if m.Value == "" {
			return fmt.Errorf("routing: empty protocol match: %w", ErrInvalidRule)
		}
	case MatchRemoteList:
		if m.Value == "" {
			return fmt.Errorf("routing: empty remote-list match: %w", ErrInvalidRule)
		}
	}
	return nil
}

func stripRefPrefix(v, prefix string) string {
	if strings.HasPrefix(v, prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return v
}

// GeoReference returns the opaque geoip:/geosite: form, or empty.
func (m Match) GeoReference() string {
	switch m.Kind {
	case MatchGeoIP:
		if m.Value == "" {
			return ""
		}
		return "geoip:" + m.Value
	case MatchGeoSite:
		if m.Value == "" {
			return ""
		}
		return "geosite:" + m.Value
	default:
		return ""
	}
}

// IsPrivateOrLocal reports builtin-style LAN/loopback matches. geoip:private
// is not resolved here.
func (m Match) IsPrivateOrLocal() bool {
	switch m.Kind {
	case MatchCIDR:
		if !m.Prefix.IsValid() {
			return false
		}
		return prefixIsPrivateOrLocal(m.Prefix)
	case MatchFullDomain, MatchDomain, MatchSuffix:
		return m.Value == "localhost"
	default:
		return false
	}
}

func prefixIsPrivateOrLocal(p netip.Prefix) bool {
	addr := p.Addr()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return true
	}
	// Unique local IPv6 (fc00::/7) is IsPrivate in Go 1.22+.
	return false
}

// MatchesHost evaluates domain-like kinds only. geoip/geosite/protocol/remote-list
// are not resolved here (no .dat, no panic).
func (m Match) MatchesHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return m.MatchesIP(ip)
	}
	switch m.Kind {
	case MatchFullDomain:
		return host == m.Value
	case MatchDomain:
		return host == m.Value || strings.HasSuffix(host, "."+m.Value)
	case MatchSuffix:
		if host == m.Value {
			return true
		}
		if strings.HasPrefix(m.Value, ".") {
			return strings.HasSuffix(host, m.Value)
		}
		return strings.HasSuffix(host, "."+m.Value)
	default:
		return false
	}
}

// MatchesIP evaluates CIDR matches only.
func (m Match) MatchesIP(ip netip.Addr) bool {
	if m.Kind != MatchCIDR || !m.Prefix.IsValid() {
		return false
	}
	return m.Prefix.Contains(ip)
}
