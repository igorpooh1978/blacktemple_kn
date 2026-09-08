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
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	if u.Scheme != "http" && u.Scheme != "https" {
		return u.Scheme + "://[redacted-host]"
	}
	return u.Scheme + "://" + u.Host + u.Path
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
