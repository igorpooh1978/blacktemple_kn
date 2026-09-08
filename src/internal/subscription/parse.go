package subscription

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"
)

var (
	ErrEmpty       = errors.New("subscription is empty")
	ErrMalformed   = errors.New("subscription is malformed")
	ErrUnknownJSON = errors.New("unknown JSON subscription shape")
)

const (
	encIdentity = "identity"
	encBase64   = "base64"
)

func Parse(body []byte) (Result, error) {
	return parse(body, false)
}

func parse(body []byte, alreadyDecoded bool) (Result, error) {
	trimmed := bytes.TrimSpace(stripBOM(body))
	if len(trimmed) == 0 {
		return Result{}, ErrEmpty
	}
	if !utf8.Valid(trimmed) {
		if alreadyDecoded {
			return Result{}, ErrMalformed
		}
		decoded, ok := tryBase64(trimmed)
		if !ok {
			return Result{}, ErrMalformed
		}
		out, err := parse(decoded, true)
		if err != nil {
			return Result{}, err
		}
		out.Encoding = encBase64
		return out, nil
	}

	s := string(trimmed)
	if looksLikeJSON(s) {
		out, err := parseJSON(trimmed)
		if err != nil {
			return Result{}, err
		}
		if alreadyDecoded {
			out.Encoding = encBase64
		} else if out.Encoding == "" {
			out.Encoding = encIdentity
		}
		return out, nil
	}

	if onlyCommentsOrEmpty(s) {
		return Result{}, ErrEmpty
	}

	if hasShareScheme(s) {
		out, err := parseURIList(s)
		if err != nil {
			return Result{}, err
		}
		if alreadyDecoded {
			out.Encoding = encBase64
		} else {
			out.Encoding = encIdentity
		}
		out.Format = "uri-list"
		return out, nil
	}

	if alreadyDecoded {
		return Result{}, ErrMalformed
	}
	decoded, ok := tryBase64(trimmed)
	if !ok {
		return Result{}, ErrMalformed
	}
	out, err := parse(decoded, true)
	if err != nil {
		return Result{}, err
	}
	out.Encoding = encBase64
	return out, nil
}

func parseURIList(s string) (Result, error) {
	lines := splitLines(s)
	var entries []ParsedShare
	seen := make(map[string]struct{})
	dupes := 0
	skipped := 0
	fields := map[string]struct{}{}
	var firstErr error
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		scheme := schemeOf(line)
		switch scheme {
		case "vless", "vmess", "trojan", "ss":
			p, err := parseShareURI(line)
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
		case "hysteria2", "hy2", "hysteria", "wireguard", "wg":
			skipped++
		default:
			if scheme == "" {
				skipped++
				if firstErr == nil {
					firstErr = ErrMalformed
				}
				continue
			}
			skipped++
		}
	}
	if len(entries) == 0 {
		if skipped > 0 && firstErr != nil {
			return Result{}, firstErr
		}
		if skipped > 0 {
			return Result{}, ErrMalformed
		}
		return Result{}, ErrEmpty
	}
	return Result{
		Entries:        entries,
		DuplicateCount: dupes,
		Skipped:        skipped,
		FieldNames:     sortedKeys(fields),
	}, nil
}

func parseShareURI(raw string) (ParsedShare, error) {
	scheme := schemeOf(raw)
	switch scheme {
	case "vless":
		return parseVLESS(raw)
	case "vmess":
		return parseVMess(raw)
	case "trojan":
		return parseTrojan(raw)
	case "ss":
		return parseShadowsocks(raw)
	default:
		return ParsedShare{}, ErrMalformed
	}
}

func schemeOf(line string) string {
	i := strings.Index(line, "://")
	if i <= 0 {
		return ""
	}
	return strings.ToLower(line[:i])
}

func hasShareScheme(s string) bool {
	low := strings.ToLower(s)
	for _, p := range []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://"} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

func looksLikeJSON(s string) bool {
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func onlyCommentsOrEmpty(s string) bool {
	for _, line := range splitLines(s) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return false
	}
	return true
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func stripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}

func tryBase64(b []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return nil, false
	}
	decoded, err := decodeBase64(s)
	if err != nil || len(decoded) == 0 {
		return nil, false
	}
	return decoded, true
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var last error
	for _, enc := range encodings {
		out, err := enc.DecodeString(s)
		if err == nil {
			return out, nil
		}
		last = err
	}
	if last == nil {
		last = ErrMalformed
	}
	return nil, last
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
