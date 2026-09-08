package subscription

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func parseVLESS(raw string) (ParsedShare, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return ParsedShare{}, errParse("vless")
	}
	id := u.User.Username()
	if id == "" || u.Hostname() == "" {
		return ParsedShare{}, errParse("vless")
	}
	port, err := requiredPort(u)
	if err != nil {
		return ParsedShare{}, errParse("vless")
	}
	q := u.Query()
	fields := queryFieldNames(q, "type", "security", "encryption", "flow", "sni", "host", "path", "serviceName", "mode", "headerType", "alpn", "fp", "pbk", "sid", "spx")
	transport := normalizeTransport(first(q.Get("type"), q.Get("network")))
	security := normalizeSecurity(q.Get("security"))
	remark := fragmentRemark(u)
	hint := countryHint(remark, q.Get("country"))
	return ParsedShare{
		Protocol:    "vless",
		Host:        u.Hostname(),
		Port:        port,
		Transport:   transport,
		Security:    security,
		Remark:      remark,
		CountryHint: hint,
		StableID:    stableID("vless", u.Hostname(), port, transport, security, remark),
		FieldNames:  fields,
		secret:      secret(id),
	}, nil
}

func parseTrojan(raw string) (ParsedShare, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return ParsedShare{}, errParse("trojan")
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	if password == "" || u.Hostname() == "" {
		return ParsedShare{}, errParse("trojan")
	}
	port, err := requiredPort(u)
	if err != nil {
		return ParsedShare{}, errParse("trojan")
	}
	q := u.Query()
	fields := queryFieldNames(q, "type", "security", "sni", "host", "path", "alpn", "fp", "allowInsecure")
	transport := normalizeTransport(first(q.Get("type"), q.Get("network")))
	security := normalizeSecurity(first(q.Get("security"), "tls"))
	remark := fragmentRemark(u)
	hint := countryHint(remark, q.Get("country"))
	return ParsedShare{
		Protocol:    "trojan",
		Host:        u.Hostname(),
		Port:        port,
		Transport:   transport,
		Security:    security,
		Remark:      remark,
		CountryHint: hint,
		StableID:    stableID("trojan", u.Hostname(), port, transport, security, remark),
		FieldNames:  fields,
		secret:      secret(password),
	}, nil
}

func parseVMess(raw string) (ParsedShare, error) {
	rest := raw
	if i := strings.Index(strings.ToLower(raw), "vmess://"); i >= 0 {
		rest = raw[i+len("vmess://"):]
	}
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	if strings.Contains(rest, "@") && !looksLikeJSON(strings.TrimSpace(rest)) {
		return parseVMessURI(raw)
	}
	decoded, err := decodeBase64(rest)
	if err != nil {
		if strings.Contains(rest, "@") {
			return parseVMessURI(raw)
		}
		return ParsedShare{}, errParse("vmess")
	}
	trimmed := strings.TrimSpace(string(decoded))
	if looksLikeJSON(trimmed) {
		return parseVMessJSON([]byte(trimmed), "")
	}
	return parseVMessURI(raw)
}

func parseVMessURI(raw string) (ParsedShare, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return ParsedShare{}, errParse("vmess")
	}
	id := u.User.Username()
	if id == "" {
		return ParsedShare{}, errParse("vmess")
	}
	port, err := requiredPort(u)
	if err != nil {
		return ParsedShare{}, errParse("vmess")
	}
	q := u.Query()
	fields := queryFieldNames(q, "type", "security", "encryption", "host", "path", "sni", "alpn", "fp", "aid")
	transport := normalizeTransport(first(q.Get("type"), q.Get("network"), q.Get("net")))
	security := normalizeSecurity(first(q.Get("security"), q.Get("tls")))
	remark := fragmentRemark(u)
	hint := countryHint(remark, q.Get("country"))
	return ParsedShare{
		Protocol:    "vmess",
		Host:        u.Hostname(),
		Port:        port,
		Transport:   transport,
		Security:    security,
		Remark:      remark,
		CountryHint: hint,
		StableID:    stableID("vmess", u.Hostname(), port, transport, security, remark),
		FieldNames:  fields,
		secret:      secret(id),
	}, nil
}

type vmessShare struct {
	V    string          `json:"v"`
	PS   string          `json:"ps"`
	Add  string          `json:"add"`
	Port flexPort        `json:"port"`
	ID   string          `json:"id"`
	AID  json.RawMessage `json:"aid"`
	Net  string          `json:"net"`
	Type string          `json:"type"`
	Host string          `json:"host"`
	Path string          `json:"path"`
	TLS  string          `json:"tls"`
	SNI  string          `json:"sni"`
	ALPN string          `json:"alpn"`
	SCY  string          `json:"scy"`
}

func parseVMessJSON(raw []byte, remarkOverride string) (ParsedShare, error) {
	var m vmessShare
	if err := json.Unmarshal(raw, &m); err != nil {
		return ParsedShare{}, errParse("vmess")
	}
	if m.Add == "" || m.ID == "" {
		return ParsedShare{}, errParse("vmess")
	}
	port := m.Port.V
	if port <= 0 || port > 65535 {
		return ParsedShare{}, errParse("vmess")
	}
	remark := strings.TrimSpace(m.PS)
	if remarkOverride != "" {
		remark = remarkOverride
	}
	transport := normalizeTransport(m.Net)
	security := normalizeSecurity(m.TLS)
	fields := []string{"v", "ps", "add", "port", "id", "net", "tls"}
	hint := countryHint(remark, "")
	return ParsedShare{
		Protocol:    "vmess",
		Host:        m.Add,
		Port:        port,
		Transport:   transport,
		Security:    security,
		Remark:      remark,
		CountryHint: hint,
		StableID:    stableID("vmess", m.Add, port, transport, security, remark),
		FieldNames:  fields,
		secret:      secret(m.ID),
	}, nil
}

func parseShadowsocks(raw string) (ParsedShare, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ParsedShare{}, errParse("ss")
	}
	remark := fragmentRemark(u)
	if u.User != nil {
		return parseSIP002(u, remark)
	}
	payload := strings.TrimPrefix(raw, "ss://")
	if i := strings.Index(strings.ToLower(raw), "ss://"); i >= 0 {
		payload = raw[i+len("ss://"):]
	}
	if i := strings.Index(payload, "#"); i >= 0 {
		payload = payload[:i]
	}
	if i := strings.Index(payload, "?"); i >= 0 {
		payload = payload[:i]
	}
	payload = strings.TrimSuffix(payload, "/")
	decoded, err := decodeBase64(payload)
	if err != nil {
		return ParsedShare{}, errParse("ss")
	}
	return parseSSUserHost(string(decoded), remark, nil)
}

func parseSIP002(u *url.URL, remark string) (ParsedShare, error) {
	user := u.User.Username()
	pass, hasPass := u.User.Password()
	q := u.Query()
	fields := queryFieldNames(q, "plugin")
	if !hasPass {
		decoded, err := decodeBase64(user)
		if err != nil {
			return ParsedShare{}, errParse("ss")
		}
		method, password, ok := strings.Cut(string(decoded), ":")
		if !ok || method == "" || password == "" {
			return ParsedShare{}, errParse("ss")
		}
		return finishSS(u.Hostname(), u.Port(), method, password, remark, fields)
	}
	return finishSS(u.Hostname(), u.Port(), user, pass, remark, fields)
}

func parseSSUserHost(decoded, remark string, extraFields []string) (ParsedShare, error) {
	at := strings.LastIndex(decoded, "@")
	if at < 0 {
		return ParsedShare{}, errParse("ss")
	}
	methodPass := decoded[:at]
	hostPort := decoded[at+1:]
	method, password, ok := strings.Cut(methodPass, ":")
	if !ok || method == "" || password == "" {
		return ParsedShare{}, errParse("ss")
	}
	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return ParsedShare{}, errParse("ss")
	}
	return finishSS(host, portStr, method, password, remark, extraFields)
}

func finishSS(host, portStr, method, password, remark string, fields []string) (ParsedShare, error) {
	if host == "" || method == "" || password == "" {
		return ParsedShare{}, errParse("ss")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return ParsedShare{}, errParse("ss")
	}
	fields = append(fields, "method")
	hint := countryHint(remark, "")
	return ParsedShare{
		Protocol:    "shadowsocks",
		Host:        host,
		Port:        port,
		Transport:   "tcp",
		Security:    "none",
		Remark:      remark,
		CountryHint: hint,
		StableID:    stableID("shadowsocks", host, port, "tcp", "none", remark),
		FieldNames:  uniq(fields),
		secret:      secret(method + ":" + password),
	}, nil
}

func requiredPort(u *url.URL) (int, error) {
	if u.Port() == "" {
		return 0, ErrMalformed
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return 0, ErrMalformed
	}
	return port, nil
}

func fragmentRemark(u *url.URL) string {
	if u.Fragment == "" {
		return ""
	}
	s, err := url.PathUnescape(u.Fragment)
	if err != nil {
		return u.Fragment
	}
	return strings.TrimSpace(s)
}

func queryFieldNames(q url.Values, names ...string) []string {
	var out []string
	for _, n := range names {
		if q.Has(n) {
			out = append(out, n)
		}
	}
	return out
}

func first(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func splitHostPort(hostPort string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err == nil {
		return host, port, nil
	}
	if strings.Count(hostPort, ":") == 1 {
		h, p, ok := strings.Cut(hostPort, ":")
		if ok {
			return h, p, nil
		}
	}
	return "", "", ErrMalformed
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, n := range in {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func errParse(scheme string) error {
	return wrapParse(scheme)
}

type parseError struct {
	scheme string
}

func (e parseError) Error() string {
	return "malformed " + e.scheme + " share"
}

func (e parseError) Unwrap() error { return ErrMalformed }

func wrapParse(scheme string) error {
	return parseError{scheme: scheme}
}

func countryHint(remark, explicit string) string {
	if c := normalizeCountry(explicit); c != "" {
		return c
	}
	remark = strings.TrimSpace(remark)
	if remark == "" {
		return ""
	}
	if strings.HasPrefix(remark, "[") {
		if i := strings.Index(remark, "]"); i > 1 {
			return normalizeCountry(remark[1:i])
		}
	}
	if i := strings.IndexByte(remark, '-'); i == 2 {
		return normalizeCountry(remark[:2])
	}
	if len(remark) == 2 {
		return normalizeCountry(remark)
	}
	return ""
}

func normalizeCountry(s string) string {
	s = strings.TrimSpace(s)
	if len(s) != 2 {
		return ""
	}
	s = strings.ToUpper(s)
	for i := 0; i < 2; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return ""
		}
	}
	return s
}
