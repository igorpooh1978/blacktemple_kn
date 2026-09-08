package remotepolicy

import (
	"bytes"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

const (
	keyAutoSwitch         = "x-auto-switch"
	keyBlackKeyProtocol   = "x-black-key-protocol"
	keyBlockQUIC          = "x-block-quic"
	keyCustomRouteAction  = "x-custom-route-action"
	keyCustomRouteDomains = "x-custom-route-domains"
	keyDNSDirect          = "x-dns-direct"
	keyDomainStrategy     = "x-domain-strategy"
	keyFakeDNS            = "x-fake-dns"
	keyFragmentEnabled    = "x-fragment-enabled"
	keyFragmentInterval   = "x-fragment-interval"
	keyFragmentLength     = "x-fragment-length"
	keyFragmentPackets    = "x-fragment-packets"
	keyMemorySaver        = "x-memory-saver"
	keyMTU                = "x-mtu"
	keyMuxConcurrency     = "x-mux-concurrency"
	keyMuxEnabled         = "x-mux-enabled"
	keyMuxXUDPConcurrency = "x-mux-xudp-concurrency"
	keyMuxXUDPQUIC        = "x-mux-xudp-quic"
	keyPolicyBufferSize   = "x-policy-buffer-size"
	keyPolicyConnIdle     = "x-policy-conn-idle"
	keyPolicyHandshake    = "x-policy-handshake"
	keySniffing           = "x-sniffing"
	keyTCPFastOpen        = "x-tcp-fast-open"
	keyTCPNoDelay         = "x-tcp-no-delay"
	keyTelegramIPs        = "x-telegram-ips"
	keyWhatsAppIPs        = "x-whatsapp-ips"
)

type valueKind int

const (
	kindBool valueKind = iota
	kindInt
	kindString
	kindEnum
	kindStringSlice
	kindURI
)

type keySpec struct {
	kind valueKind
	enum []string
}

var allowlist = map[string]keySpec{
	keyAutoSwitch:         {kind: kindBool},
	keyBlackKeyProtocol:   {kind: kindString},
	keyBlockQUIC:          {kind: kindBool},
	keyCustomRouteAction:  {kind: kindEnum, enum: []string{"direct", "proxy", "block"}},
	keyCustomRouteDomains: {kind: kindStringSlice},
	keyDNSDirect:          {kind: kindString},
	keyDomainStrategy:     {kind: kindString},
	keyFakeDNS:            {kind: kindBool},
	keyFragmentEnabled:    {kind: kindBool},
	keyFragmentInterval:   {kind: kindString},
	keyFragmentLength:     {kind: kindString},
	keyFragmentPackets:    {kind: kindString},
	keyMemorySaver:        {kind: kindBool},
	keyMTU:                {kind: kindInt},
	keyMuxConcurrency:     {kind: kindInt},
	keyMuxEnabled:         {kind: kindBool},
	keyMuxXUDPConcurrency: {kind: kindInt},
	keyMuxXUDPQUIC:        {kind: kindString},
	keyPolicyBufferSize:   {kind: kindInt},
	keyPolicyConnIdle:     {kind: kindInt},
	keyPolicyHandshake:    {kind: kindInt},
	keySniffing:           {kind: kindBool},
	keyTCPFastOpen:        {kind: kindBool},
	keyTCPNoDelay:         {kind: kindBool},
	keyTelegramIPs:        {kind: kindURI},
	keyWhatsAppIPs:        {kind: kindURI},
}

// KnownKeys is the parse allowlist (APK evidence subset assigned to this wave).
func KnownKeys() []string {
	keys := make([]string, 0, len(allowlist))
	for k := range allowlist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Parse decodes a JSON object into typed Settings. Unknown keys are ignored
// and reported. An invalid known key rejects the whole document.
func Parse(body []byte) (Document, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return Document{}, ErrInvalidJSON
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return Document{}, ErrInvalidJSON
	}
	if dec.More() {
		return Document{}, ErrInvalidJSON
	}
	var s Settings
	var ignored []Issue
	for k, v := range raw {
		spec, ok := allowlist[k]
		if !ok {
			ignored = append(ignored, Issue{Key: k, Reason: "unknown key ignored"})
			continue
		}
		if err := assign(&s, k, spec, v); err != nil {
			return Document{}, err
		}
	}
	sort.Slice(ignored, func(i, j int) bool { return ignored[i].Key < ignored[j].Key })
	return Document{Settings: s, Ignored: ignored}, nil
}

func assign(s *Settings, key string, spec keySpec, raw json.RawMessage) error {
	switch spec.kind {
	case kindBool:
		v, err := parseBool(raw)
		if err != nil {
			return wrapKnown(key, err)
		}
		switch key {
		case keyAutoSwitch:
			s.AutoSwitch = &v
		case keyBlockQUIC:
			s.BlockQUIC = &v
		case keyFakeDNS:
			s.FakeDNS = &v
		case keyFragmentEnabled:
			s.FragmentEnabled = &v
		case keyMemorySaver:
			s.MemorySaver = &v
		case keyMuxEnabled:
			s.MuxEnabled = &v
		case keySniffing:
			s.Sniffing = &v
		case keyTCPFastOpen:
			s.TCPFastOpen = &v
		case keyTCPNoDelay:
			s.TCPNoDelay = &v
		}
	case kindInt:
		v, err := parseInt(raw)
		if err != nil {
			return wrapKnown(key, err)
		}
		switch key {
		case keyMTU:
			s.MTU = &v
		case keyMuxConcurrency:
			s.MuxConcurrency = &v
		case keyMuxXUDPConcurrency:
			s.MuxXUDPConcurrency = &v
		case keyPolicyBufferSize:
			s.PolicyBufferSize = &v
		case keyPolicyConnIdle:
			s.PolicyConnIdle = &v
		case keyPolicyHandshake:
			s.PolicyHandshake = &v
		}
	case kindString:
		v, err := parseString(raw)
		if err != nil {
			return wrapKnown(key, err)
		}
		switch key {
		case keyBlackKeyProtocol:
			s.BlackKeyProtocol = &v
		case keyDNSDirect:
			s.DNSDirect = &v
		case keyDomainStrategy:
			s.DomainStrategy = &v
		case keyFragmentInterval:
			s.FragmentInterval = &v
		case keyFragmentLength:
			s.FragmentLength = &v
		case keyFragmentPackets:
			s.FragmentPackets = &v
		case keyMuxXUDPQUIC:
			s.MuxXUDPQUIC = &v
		}
	case kindEnum:
		v, err := parseString(raw)
		if err != nil {
			return wrapKnown(key, err)
		}
		if !enumOK(v, spec.enum) {
			return wrapKnown(key, ErrInvalidKnownKey)
		}
		s.CustomRouteAction = &v
	case kindStringSlice:
		v, err := parseStringSlice(raw)
		if err != nil {
			return wrapKnown(key, err)
		}
		s.CustomRouteDomains = v
	case kindURI:
		v, err := parseURI(raw)
		if err != nil {
			return wrapKnown(key, err)
		}
		switch key {
		case keyTelegramIPs:
			s.TelegramIPs = &v
		case keyWhatsAppIPs:
			s.WhatsAppIPs = &v
		}
	}
	return nil
}

func wrapKnown(key string, err error) error {
	_ = key
	_ = err
	return ErrInvalidKnownKey
}

func parseBool(raw json.RawMessage) (bool, error) {
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, err
	}
	return v, nil
}

func parseInt(raw json.RawMessage) (int, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	i, err := n.Int64()
	if err != nil {
		return 0, err
	}
	if int64(int(i)) != i {
		return 0, ErrInvalidKnownKey
	}
	return int(i), nil
}

func parseString(raw json.RawMessage) (string, error) {
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	return v, nil
}

func parseStringSlice(raw json.RawMessage) ([]string, error) {
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if v == nil {
		v = []string{}
	}
	return v, nil
}

func parseURI(raw json.RawMessage) (string, error) {
	v, err := parseString(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", ErrInvalidKnownKey
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return v, nil
	default:
		return "", ErrInvalidKnownKey
	}
}

func enumOK(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
