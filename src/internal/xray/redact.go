package xray

import (
	"regexp"
	"strings"
)

var uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

const redacted = "[REDACTED]"

// Redact removes known secrets and UUID-shaped tokens from log text.
func Redact(text string, secrets ConfigSecrets) string {
	out := text
	for _, s := range []string{secrets.UUID, secrets.Password, secrets.PrivateKey} {
		if s != "" {
			out = strings.ReplaceAll(out, s, redacted)
		}
	}
	out = uuidPattern.ReplaceAllString(out, redacted)
	return out
}

// RedactBytes is Redact for process output.
func RedactBytes(b []byte, secrets ConfigSecrets) string {
	return Redact(string(b), secrets)
}
