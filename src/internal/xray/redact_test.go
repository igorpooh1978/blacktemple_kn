package xray

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	secrets := ConfigSecrets{
		UUID:       fixtureUUID,
		Password:   "super-secret-pass",
		PrivateKey: "TEST_PRIVATE_KEY_VALUE",
	}
	in := "uuid=" + fixtureUUID + " password=super-secret-pass key=TEST_PRIVATE_KEY_VALUE extra=22222222-2222-4222-8222-222222222222"
	out := Redact(in, secrets)
	if out == in {
		t.Fatal("expected redaction")
	}
	for _, leak := range []string{fixtureUUID, "super-secret-pass", "TEST_PRIVATE_KEY_VALUE", "22222222-2222-4222-8222-222222222222"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in %q", leak, out)
		}
	}
}
