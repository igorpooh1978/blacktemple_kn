package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

const (
	defaultListenHost  = "127.0.0.1"
	defaultListenPort  = 11080
	defaultLogLevel    = "warning"
	defaultFingerprint = "chrome"
	visionFlow         = "xtls-rprx-vision"

	tagInbound  = "socks-in"
	tagOutbound = "proxy"
)

// Options controls inbound bind and debug pretty-print.
type Options struct {
	ListenHost    string
	ListenPort    int
	EphemeralPort bool // bind 127.0.0.1:0; Xray accepts port 0 at `run -test`
	Pretty        bool // debug only; production must stay compact
	LogLevel      string
}

func (o Options) withDefaults() Options {
	if o.ListenHost == "" {
		o.ListenHost = defaultListenHost
	}
	if o.LogLevel == "" {
		o.LogLevel = defaultLogLevel
	}
	if o.EphemeralPort {
		o.ListenPort = 0
	} else if o.ListenPort == 0 {
		o.ListenPort = defaultListenPort
	}
	return o
}

// Generate writes a deterministic minimal Xray JSON config for P0 VLESS.
func Generate(profile Profile, secrets ConfigSecrets, params OutboundParams, opts Options) ([]byte, error) {
	opts = opts.withDefaults()
	if err := validateProfile(profile, secrets, params, opts); err != nil {
		return nil, err
	}

	transport := profile.Transport
	if transport == "" {
		transport = "tcp"
	}
	streamSecurity, flow := mapSecurity(profile.Security, params.Flow, transport)

	user := vlessUser{
		ID:         secrets.UUID,
		Encryption: "none",
	}
	if flow != "" {
		user.Flow = flow
	}

	stream, err := buildStream(transport, streamSecurity, params)
	if err != nil {
		return nil, err
	}

	cfg := xrayConfig{
		Log: xrayLog{Loglevel: opts.LogLevel},
		Inbounds: []xrayInbound{{
			Tag:      tagInbound,
			Listen:   opts.ListenHost,
			Port:     opts.ListenPort,
			Protocol: "socks",
			Settings: inboundSettings{Auth: "noauth", UDP: true},
		}},
		Outbounds: []xrayOutbound{{
			Tag:      tagOutbound,
			Protocol: "vless",
			Settings: outboundSettings{Vnext: []vnext{{
				Address: profile.Server,
				Port:    profile.Port,
				Users:   []vlessUser{user},
			}}},
			StreamSettings: stream,
		}},
	}

	if opts.Pretty {
		return json.MarshalIndent(cfg, "", "  ")
	}
	return json.Marshal(cfg)
}

func mapSecurity(security, flow, transport string) (streamSecurity, outFlow string) {
	switch security {
	case "reality":
		streamSecurity = "reality"
	case "tls":
		streamSecurity = "tls"
	case "xtls-vision":
		streamSecurity = "tls"
	}
	if flow != "" {
		outFlow = flow
		return streamSecurity, outFlow
	}
	if transport == "tcp" && (security == "reality" || security == "tls" || security == "xtls-vision") {
		outFlow = visionFlow
	}
	return streamSecurity, outFlow
}

func buildStream(transport, streamSecurity string, params OutboundParams) (*streamSettings, error) {
	fp := params.Fingerprint
	if fp == "" {
		fp = defaultFingerprint
	}

	ss := &streamSettings{
		Network:  transport,
		Security: streamSecurity,
	}

	switch streamSecurity {
	case "tls":
		tls := &tlsSettings{
			ServerName:  params.SNI,
			Fingerprint: fp,
		}
		if len(params.ALPN) > 0 {
			tls.ALPN = append([]string(nil), params.ALPN...)
		}
		ss.TLSSettings = tls
	case "reality":
		ss.RealitySettings = &realitySettings{
			ServerName:  params.SNI,
			Fingerprint: fp,
			PublicKey:   params.PublicKey,
			ShortID:     params.ShortID,
			SpiderX:     params.SpiderX,
		}
	}

	switch transport {
	case "tcp":
		// no tcpSettings for minimal config
	case "ws":
		if params.Path != "" || params.Host != "" {
			ss.WSSettings = &wsSettings{Path: params.Path, Host: params.Host}
		}
	case "grpc":
		if params.ServiceName != "" {
			ss.GRPCSettings = &grpcSettings{ServiceName: params.ServiceName}
		}
	case "xhttp":
		mode := params.Mode
		if mode == "" && (params.Path != "" || params.Host != "") {
			mode = "auto"
		}
		if params.Path != "" || params.Host != "" || mode != "" {
			ss.XHTTPSettings = &xhttpSettings{Path: params.Path, Host: params.Host, Mode: mode}
		}
	default:
		return nil, fmt.Errorf("unsupported transport %q", transport)
	}
	return ss, nil
}

func validateProfile(profile Profile, secrets ConfigSecrets, params OutboundParams, opts Options) error {
	if strings.TrimSpace(profile.ID) == "" {
		return fmt.Errorf("profile id is required")
	}
	if strings.TrimSpace(profile.Protocol) == "" {
		return fmt.Errorf("profile protocol is required")
	}
	if profile.Protocol != "vless" {
		return fmt.Errorf("protocol %q is not generated in R4 P0 (vless only)", profile.Protocol)
	}
	if strings.TrimSpace(profile.Server) == "" {
		return fmt.Errorf("profile server is required")
	}
	if profile.Port < 1 || profile.Port > 65535 {
		return fmt.Errorf("profile port must be 1-65535")
	}

	switch profile.Security {
	case "tls", "reality", "xtls-vision":
	default:
		return fmt.Errorf("security %q is not generated in R4 P0 (tls, reality, xtls-vision)", profile.Security)
	}

	transport := profile.Transport
	if transport == "" {
		transport = "tcp"
	}
	switch transport {
	case "tcp", "ws", "grpc", "xhttp":
	default:
		return fmt.Errorf("transport %q is not emitted in R4 (tcp, ws, grpc, xhttp)", transport)
	}

	if strings.TrimSpace(secrets.UUID) == "" {
		return fmt.Errorf("uuid is required (not in frozen profile schema; pass ConfigSecrets)")
	}
	if !validUUID(secrets.UUID) {
		return fmt.Errorf("uuid is malformed")
	}

	if params.Flow != "" && params.Flow != visionFlow {
		return fmt.Errorf("flow %q is not generated in R4 P0", params.Flow)
	}

	if profile.Security == "reality" {
		if strings.TrimSpace(params.PublicKey) == "" {
			return fmt.Errorf("reality publicKey is required (not in frozen profile schema; pass OutboundParams)")
		}
		if strings.TrimSpace(params.SNI) == "" {
			return fmt.Errorf("reality sni is required (not in frozen profile schema; pass OutboundParams)")
		}
	}

	if err := validateLoopback(opts.ListenHost); err != nil {
		return err
	}
	if !opts.EphemeralPort && (opts.ListenPort < 1 || opts.ListenPort > 65535) {
		return fmt.Errorf("listen port must be 1-65535")
	}
	return nil
}

func validateLoopback(host string) error {
	if host == "localhost" {
		return fmt.Errorf("listen host must be 127.0.0.1 (loopback only, not LAN)")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || ip.To4() == nil {
		return fmt.Errorf("listen host must be 127.0.0.1 (loopback only, not LAN)")
	}
	if host != defaultListenHost {
		return fmt.Errorf("listen host must be 127.0.0.1 (loopback only, not LAN)")
	}
	return nil
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

func isHex(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

type xrayConfig struct {
	Log       xrayLog        `json:"log"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

type xrayLog struct {
	Loglevel string `json:"loglevel"`
}

type xrayInbound struct {
	Tag      string          `json:"tag"`
	Listen   string          `json:"listen"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	Settings inboundSettings `json:"settings"`
}

type inboundSettings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
}

type xrayOutbound struct {
	Tag            string           `json:"tag"`
	Protocol       string           `json:"protocol"`
	Settings       outboundSettings `json:"settings"`
	StreamSettings *streamSettings  `json:"streamSettings,omitempty"`
}

type outboundSettings struct {
	Vnext []vnext `json:"vnext"`
}

type vnext struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []vlessUser `json:"users"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

type streamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security,omitempty"`
	TLSSettings     *tlsSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`
	WSSettings      *wsSettings      `json:"wsSettings,omitempty"`
	GRPCSettings    *grpcSettings    `json:"grpcSettings,omitempty"`
	XHTTPSettings   *xhttpSettings   `json:"xhttpSettings,omitempty"`
}

type tlsSettings struct {
	ServerName  string   `json:"serverName,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
}

type realitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type wsSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName"`
}

type xhttpSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
	Mode string `json:"mode,omitempty"`
}
