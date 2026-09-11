package profiles

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

const (
	hmacSecretRel   = "secrets/blackkey-hmac.key"
	providerJSONRel = "provider.json"
)

type providerFile struct {
	AllowedHosts []string `json:"allowedHosts"`
}

// LoadBlackKeyResolver loads HMAC + host allowlist from DataDir.
// Missing or invalid material returns a fail-closed resolver; the daemon still starts.
func LoadBlackKeyResolver(dataDir string, client *http.Client) BlackKeyResolver {
	if strings.TrimSpace(dataDir) == "" {
		return notConfiguredResolver{}
	}
	key, err := readHMACKeyFile(filepath.Join(dataDir, hmacSecretRel))
	if err != nil || len(key) < minHMACKeyBytes {
		return notConfiguredResolver{}
	}
	hosts, err := readAllowedHosts(filepath.Join(dataDir, providerJSONRel))
	if err != nil || len(hosts) == 0 {
		return notConfiguredResolver{}
	}
	return NewHTTPResolver(HTTPResolverConfig{
		Client:       client,
		HMACKey:      key,
		AllowedHosts: hosts,
	})
}

func readHMACKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrResolverNotConfigured
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return nil, ErrResolverNotConfigured
	}
	return []byte(key), nil
}

func readAllowedHosts(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file providerFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	var out []string
	for _, h := range file.AllowedHosts {
		n := canonicalHost(h)
		if n == "" || forbiddenResolverHost(n) {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, ErrResolverNotConfigured
	}
	return out, nil
}

func canonicalHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".")
	h = strings.ToLower(h)
	if h == "" || strings.Contains(h, "/") || strings.Contains(h, "@") || strings.Contains(h, " ") {
		return ""
	}
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		// hostname:port slipped in
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = strings.ToLower(strings.TrimSuffix(host, "."))
		} else {
			return ""
		}
	}
	for _, r := range h {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return h
}

func forbiddenResolverHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}
