package remotelists

import (
	"bytes"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// Parse interprets a body according to list type. Line-based types skip
// blanks, comments, duplicates, and invalid rows. Countries, servers,
// provider-routing, and geosite-catalog return ErrProviderFormatNotImplemented
// after a UTF-8/size sanity check (provider payload format is not proven).
func Parse(t ListType, body []byte) (Parsed, error) {
	if !knownType(t) {
		return Parsed{}, ErrUnknownType
	}
	lim := LimitsFor(t)
	if int64(len(body)) > lim.MaxBytes {
		return Parsed{}, ErrTooLarge
	}
	if err := sanity(body); err != nil {
		return Parsed{}, err
	}
	switch t {
	case TypeDomains:
		return parseDomains(body, lim)
	case TypeCIDRs, TypeTelegramIPs, TypeWhatsAppIPs:
		p, err := parseCIDRs(body, lim)
		if err != nil {
			return Parsed{}, err
		}
		p.Type = t
		return p, nil
	default:
		p := Parsed{Type: t, Lines: countLines(body)}
		if p.Lines > lim.MaxLines {
			return Parsed{}, ErrTooManyLines
		}
		return p, ErrProviderFormatNotImplemented
	}
}

func sanity(body []byte) error {
	if bytes.IndexByte(body, 0) >= 0 {
		return ErrInvalidContent
	}
	if !utf8.Valid(body) {
		return ErrInvalidContent
	}
	return nil
}

func parseDomains(body []byte, lim Limits) (Parsed, error) {
	p := Parsed{Type: TypeDomains}
	seen := map[string]struct{}{}
	err := walkLines(body, lim, func(lineNum int, raw string, tooLong bool) {
		p.Lines = lineNum
		if tooLong {
			p.Skipped++
			p.Issues = append(p.Issues, Issue{Line: lineNum, Reason: "line too long"})
			return
		}
		text, skip := normalizeLine(raw)
		if skip {
			return
		}
		text = strings.ToLower(text)
		if !validDomain(text) {
			p.Skipped++
			p.Issues = append(p.Issues, Issue{Line: lineNum, Reason: "invalid domain"})
			return
		}
		if _, ok := seen[text]; ok {
			p.Dupes++
			p.Skipped++
			p.Issues = append(p.Issues, Issue{Line: lineNum, Reason: "duplicate"})
			return
		}
		seen[text] = struct{}{}
		p.Domains = append(p.Domains, DomainEntry{Domain: text, Line: lineNum})
		p.Entries++
	})
	if err != nil {
		return Parsed{}, err
	}
	return p, nil
}

func parseCIDRs(body []byte, lim Limits) (Parsed, error) {
	p := Parsed{Type: TypeCIDRs}
	seen := map[string]struct{}{}
	err := walkLines(body, lim, func(lineNum int, raw string, tooLong bool) {
		p.Lines = lineNum
		if tooLong {
			p.Skipped++
			p.Issues = append(p.Issues, Issue{Line: lineNum, Reason: "line too long"})
			return
		}
		text, skip := normalizeLine(raw)
		if skip {
			return
		}
		prefix, ok := parsePrefix(text)
		if !ok {
			p.Skipped++
			p.Issues = append(p.Issues, Issue{Line: lineNum, Reason: "invalid cidr"})
			return
		}
		key := prefix.String()
		if _, dup := seen[key]; dup {
			p.Dupes++
			p.Skipped++
			p.Issues = append(p.Issues, Issue{Line: lineNum, Reason: "duplicate"})
			return
		}
		seen[key] = struct{}{}
		p.CIDRs = append(p.CIDRs, CIDREntry{Prefix: prefix, Line: lineNum})
		p.Entries++
	})
	if err != nil {
		return Parsed{}, err
	}
	return p, nil
}

func walkLines(body []byte, lim Limits, fn func(lineNum int, raw string, tooLong bool)) error {
	lineNum := 0
	start := 0
	n := len(body)
	for i := 0; i <= n; i++ {
		if i != n && body[i] != '\n' {
			continue
		}
		lineNum++
		if lineNum > lim.MaxLines {
			return ErrTooManyLines
		}
		end := i
		if end > start && body[end-1] == '\r' {
			end--
		}
		if end-start > lim.MaxLine {
			fn(lineNum, "", true)
			start = i + 1
			continue
		}
		fn(lineNum, string(body[start:end]), false)
		start = i + 1
	}
	return nil
}

func normalizeLine(raw string) (text string, skip bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", true
	}
	if s[0] == '#' || strings.HasPrefix(s, "//") {
		return "", true
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "", true
	}
	return s, false
}

func parsePrefix(text string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(text); err == nil {
		return p, true
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	p := netip.PrefixFrom(addr, bits)
	return p, p.IsValid()
}

func validDomain(s string) bool {
	s = strings.ToLower(s)
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, "*.") {
		s = s[2:]
		if s == "" {
			return false
		}
	}
	if strings.Contains(s, "..") || s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	start := 0
	labels := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			continue
		}
		lab := s[start:i]
		if len(lab) == 0 || len(lab) > 63 {
			return false
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		for j := 0; j < len(lab); j++ {
			c := lab[j]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
		labels++
		start = i + 1
	}
	return labels >= 1
}

func countLines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	n := 1
	for i := 0; i < len(body); i++ {
		if body[i] == '\n' {
			n++
		}
	}
	if body[len(body)-1] == '\n' {
		n--
	}
	return n
}

// BuiltInIPHints is always empty: Telegram/WhatsApp IPs are never embedded.
func BuiltInIPHints(listID string) []CIDREntry {
	_ = listID
	return nil
}
