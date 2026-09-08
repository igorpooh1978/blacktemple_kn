package xray

// ConfigSecrets holds values that must never appear in logs. They are not in
// the frozen XrayProfileModel schema.
type ConfigSecrets struct {
	UUID       string
	Password   string
	PrivateKey string
}

// OutboundParams holds generator fields required for a working VLESS outbound
// that are not in the frozen schema (SNI, REALITY publicKey, transport extras).
type OutboundParams struct {
	Flow        string
	SNI         string
	PublicKey   string
	ShortID     string
	Fingerprint string
	SpiderX     string
	Path        string
	Host        string
	ServiceName string
	ALPN        []string
	Mode        string // xhttp mode, e.g. auto
}
