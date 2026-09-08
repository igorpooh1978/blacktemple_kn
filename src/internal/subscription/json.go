package subscription

import (
	"encoding/json"
	"strconv"
	"strings"
)

type flexPort struct {
	V int
}

func (p *flexPort) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		p.V = n
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return err
	}
	p.V = n
	return nil
}

func parseJSON(raw []byte) (Result, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		return parseJSONArray(arr)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return Result{}, ErrMalformed
	}
	if _, ok := obj["outbounds"]; ok {
		var wrapped struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return Result{}, ErrUnknownJSON
		}
		out, err := parseOutboundList(wrapped.Outbounds)
		if err != nil {
			return Result{}, err
		}
		out.Format = "json-outbound"
		out.Encoding = encIdentity
		return out, nil
	}
	if isVMessObject(obj) {
		p, err := parseVMessJSON(raw, "")
		if err != nil {
			return Result{}, err
		}
		return Result{
			Entries:    []ParsedShare{p},
			Encoding:   encIdentity,
			Format:     "json-vmess",
			FieldNames: p.FieldNames,
		}, nil
	}
	if _, ok := obj["protocol"]; ok {
		p, err := parseOutbound(raw)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Entries:    []ParsedShare{p},
			Encoding:   encIdentity,
			Format:     "json-outbound",
			FieldNames: p.FieldNames,
		}, nil
	}
	return Result{}, ErrUnknownJSON
}

func isVMessObject(obj map[string]json.RawMessage) bool {
	_, hasAdd := obj["add"]
	_, hasID := obj["id"]
	_, hasPort := obj["port"]
	return hasAdd && hasID && hasPort
}

func parseJSONArray(arr []json.RawMessage) (Result, error) {
	if len(arr) == 0 {
		return Result{}, ErrEmpty
	}
	var uriLines []string
	var outbounds []json.RawMessage
	for _, el := range arr {
		el = json.RawMessage(strings.TrimSpace(string(el)))
		if len(el) == 0 {
			return Result{}, ErrMalformed
		}
		if el[0] == '"' {
			var s string
			if err := json.Unmarshal(el, &s); err != nil {
				return Result{}, ErrMalformed
			}
			uriLines = append(uriLines, s)
			continue
		}
		if el[0] == '{' {
			outbounds = append(outbounds, el)
			continue
		}
		return Result{}, ErrUnknownJSON
	}
	if len(uriLines) > 0 && len(outbounds) > 0 {
		return Result{}, ErrUnknownJSON
	}
	if len(uriLines) > 0 {
		out, err := parseURIList(strings.Join(uriLines, "\n"))
		if err != nil {
			return Result{}, err
		}
		out.Format = "json-uri-array"
		out.Encoding = encIdentity
		return out, nil
	}
	out, err := parseOutboundList(outbounds)
	if err != nil {
		return Result{}, err
	}
	out.Format = "json-outbound"
	out.Encoding = encIdentity
	return out, nil
}

func parseOutboundList(items []json.RawMessage) (Result, error) {
	if len(items) == 0 {
		return Result{}, ErrEmpty
	}
	var entries []ParsedShare
	seen := map[string]struct{}{}
	dupes := 0
	skipped := 0
	fields := map[string]struct{}{}
	var firstErr error
	for _, raw := range items {
		p, err := parseOutbound(raw)
		if err != nil {
			skipped++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, ok := seen[p.StableID]; ok {
			dupes++
			continue
		}
		seen[p.StableID] = struct{}{}
		entries = append(entries, p)
		for _, n := range p.FieldNames {
			fields[n] = struct{}{}
		}
	}
	if len(entries) == 0 {
		if firstErr != nil {
			return Result{}, firstErr
		}
		return Result{}, ErrMalformed
	}
	return Result{
		Entries:        entries,
		DuplicateCount: dupes,
		Skipped:        skipped,
		FieldNames:     sortedKeys(fields),
	}, nil
}

type outboundJSON struct {
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *streamJSON     `json:"streamSettings"`
}

type streamJSON struct {
	Network  string `json:"network"`
	Security string `json:"security"`
}

type vnextSettings struct {
	Vnext []struct {
		Address string   `json:"address"`
		Port    flexPort `json:"port"`
		Users   []struct {
			ID         string `json:"id"`
			Password   string `json:"password"`
			Encryption string `json:"encryption"`
			Flow       string `json:"flow"`
		} `json:"users"`
	} `json:"vnext"`
}

type serverSettings struct {
	Servers []struct {
		Address  string   `json:"address"`
		Port     flexPort `json:"port"`
		Password string   `json:"password"`
		Method   string   `json:"method"`
		Email    string   `json:"email"`
	} `json:"servers"`
}

func parseOutbound(raw json.RawMessage) (ParsedShare, error) {
	var o outboundJSON
	if err := json.Unmarshal(raw, &o); err != nil {
		return ParsedShare{}, ErrUnknownJSON
	}
	proto := strings.ToLower(strings.TrimSpace(o.Protocol))
	switch proto {
	case "vless", "vmess":
		return parseVNextOutbound(o)
	case "trojan", "shadowsocks", "ss":
		if proto == "ss" {
			o.Protocol = "shadowsocks"
		}
		return parseServerOutbound(o)
	case "":
		return ParsedShare{}, ErrUnknownJSON
	default:
		return ParsedShare{}, ErrUnknownJSON
	}
}

func parseVNextOutbound(o outboundJSON) (ParsedShare, error) {
	var st vnextSettings
	if err := json.Unmarshal(o.Settings, &st); err != nil || len(st.Vnext) == 0 {
		return ParsedShare{}, ErrUnknownJSON
	}
	n := st.Vnext[0]
	if n.Address == "" || len(n.Users) == 0 || n.Users[0].ID == "" {
		return ParsedShare{}, ErrUnknownJSON
	}
	port := n.Port.V
	if port <= 0 || port > 65535 {
		return ParsedShare{}, ErrUnknownJSON
	}
	transport, security := streamMeta(o.StreamSettings)
	remark := strings.TrimSpace(o.Tag)
	proto := strings.ToLower(o.Protocol)
	fields := []string{"protocol", "settings", "address", "port", "id"}
	if o.StreamSettings != nil {
		fields = append(fields, "streamSettings", "network", "security")
	}
	return ParsedShare{
		Protocol:    proto,
		Host:        n.Address,
		Port:        port,
		Transport:   transport,
		Security:    security,
		Remark:      remark,
		CountryHint: countryHint(remark, ""),
		StableID:    stableID(proto, n.Address, port, transport, security, remark),
		FieldNames:  fields,
		secret:      secret(n.Users[0].ID),
	}, nil
}

func parseServerOutbound(o outboundJSON) (ParsedShare, error) {
	var st serverSettings
	if err := json.Unmarshal(o.Settings, &st); err != nil || len(st.Servers) == 0 {
		return ParsedShare{}, ErrUnknownJSON
	}
	s := st.Servers[0]
	if s.Address == "" || s.Password == "" {
		return ParsedShare{}, ErrUnknownJSON
	}
	port := s.Port.V
	if port <= 0 || port > 65535 {
		return ParsedShare{}, ErrUnknownJSON
	}
	proto := strings.ToLower(o.Protocol)
	if proto == "ss" {
		proto = "shadowsocks"
	}
	transport, security := streamMeta(o.StreamSettings)
	if proto == "shadowsocks" {
		transport = "tcp"
		security = "none"
	}
	if proto == "trojan" && security == "none" {
		security = "tls"
	}
	material := s.Password
	if proto == "shadowsocks" {
		method := s.Method
		if method == "" {
			return ParsedShare{}, ErrUnknownJSON
		}
		material = method + ":" + s.Password
	}
	remark := strings.TrimSpace(o.Tag)
	if remark == "" {
		remark = strings.TrimSpace(s.Email)
	}
	fields := []string{"protocol", "settings", "address", "port", "password"}
	if s.Method != "" {
		fields = append(fields, "method")
	}
	return ParsedShare{
		Protocol:    proto,
		Host:        s.Address,
		Port:        port,
		Transport:   transport,
		Security:    security,
		Remark:      remark,
		CountryHint: countryHint(remark, ""),
		StableID:    stableID(proto, s.Address, port, transport, security, remark),
		FieldNames:  fields,
		secret:      secret(material),
	}, nil
}

func streamMeta(s *streamJSON) (transport, security string) {
	if s == nil {
		return "tcp", "none"
	}
	return normalizeTransport(s.Network), normalizeSecurity(s.Security)
}
