package subscription

import (
	"net/url"
	"strings"
)

const redacted = "[redacted]"

// secret never prints or serializes its contents.
type secret string

func (s secret) String() string   { return redacted }
func (s secret) GoString() string { return redacted }
func (s secret) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}
func (s secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}

func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "[invalid-url]"
	}
	// Never include User, Path, RawPath, Opaque, RawQuery, or Fragment.
	// Any path segment may be a BlackKey credential.
	if u.Scheme != "http" && u.Scheme != "https" {
		return u.Scheme + "://[redacted-host]/[redacted]"
	}
	host := u.Host
	if host == "" {
		return u.Scheme + "://[redacted-host]/[redacted]"
	}
	return u.Scheme + "://" + host + "/[redacted]"
}

func containsSecret(haystack string, secrets ...string) bool {
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(haystack, s) {
			return true
		}
	}
	return false
}
