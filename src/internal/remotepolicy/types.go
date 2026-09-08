package remotepolicy

import "errors"

var (
	ErrInvalidJSON      = errors.New("remote policy is not a JSON object")
	ErrInvalidKnownKey  = errors.New("invalid value for known remote policy key")
	ErrUntrustedOrigin  = errors.New("remote policy origin is not trusted")
	ErrChecksumMismatch = errors.New("remote policy checksum mismatch")
	ErrSignature        = errors.New("remote policy signature verification failed")
	ErrInsecure         = errors.New("remote policy requires TLS, checksum pin, or signature")
)

// IntegrityStatus is honest about how the body was authenticated.
// HTTPS transport alone is TLS_ONLY, never SIGNATURE_VERIFIED.
type IntegrityStatus string

const (
	IntegrityTLSOnly           IntegrityStatus = "TLS_ONLY"
	IntegrityChecksumPinned    IntegrityStatus = "CHECKSUM_PINNED"
	IntegritySignatureVerified IntegrityStatus = "SIGNATURE_VERIFIED"
)

// OriginKind names who configured the source.
type OriginKind string

const (
	OriginTrustedProvider OriginKind = "trusted-provider"
	OriginUserConfigured  OriginKind = "user-configured"
)

// Origin is a remote policy source. Trusted must be explicit.
type Origin struct {
	Kind    OriginKind
	URL     string
	Trusted bool
}

func (o Origin) Allowed() bool {
	if !o.Trusted {
		return false
	}
	switch o.Kind {
	case OriginTrustedProvider, OriginUserConfigured:
		return true
	default:
		return false
	}
}

func (o Origin) String() string {
	return "Origin{Kind:" + string(o.Kind) + " Trusted:" + boolString(o.Trusted) + "}"
}

func (o Origin) GoString() string { return o.String() }

// Issue records an ignored unknown key or similar non-fatal note.
type Issue struct {
	Key    string
	Reason string
}

// Settings is the typed allowlist. There is no Command, Shell, Exec, or
// iptables field.
type Settings struct {
	AutoSwitch         *bool
	BlackKeyProtocol   *string
	BlockQUIC          *bool
	CustomRouteAction  *string
	CustomRouteDomains []string
	DNSDirect          *string
	DomainStrategy     *string
	FakeDNS            *bool
	FragmentEnabled    *bool
	FragmentInterval   *string
	FragmentLength     *string
	FragmentPackets    *string
	MemorySaver        *bool
	MTU                *int
	MuxConcurrency     *int
	MuxEnabled         *bool
	MuxXUDPConcurrency *int
	MuxXUDPQUIC        *string
	PolicyBufferSize   *int
	PolicyConnIdle     *int
	PolicyHandshake    *int
	Sniffing           *bool
	TCPFastOpen        *bool
	TCPNoDelay         *bool
	TelegramIPs        *string
	WhatsAppIPs        *string
}

func (s Settings) String() string {
	return "Settings{BlockQUIC:" + boolPtrString(s.BlockQUIC) + "}"
}

func (s Settings) GoString() string { return s.String() }

// RuntimeActions is always empty: policy never produces exec, shell,
// iptables, package install, file mutation, or service restart.
func (s Settings) RuntimeActions() []string {
	return nil
}

// FirewallCommands is always empty. blockQUIC is a setting, not a firewall emit.
func (s Settings) FirewallCommands() []string {
	return nil
}

// Document is a parsed remote policy body plus origin and integrity.
type Document struct {
	Settings  Settings
	Origin    Origin
	Integrity IntegrityStatus
	Ignored   []Issue
}

func (d Document) String() string {
	return "Document{Integrity:" + string(d.Integrity) + " Ignored:" + itoa(len(d.Ignored)) + "}"
}

func (d Document) GoString() string { return d.String() }

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func boolPtrString(v *bool) string {
	if v == nil {
		return "nil"
	}
	return boolString(*v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
