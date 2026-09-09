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

func TestRedactTransparentGeneratedConfig(t *testing.T) {
	raw, err := Generate(fixtureProfile("tcp", "tls"), fixtureSecrets(), fixtureParams("tcp"), Options{Transparent: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), fixtureUUID) {
		t.Fatal("fixture uuid must be present in generated config")
	}
	out := Redact(string(raw), fixtureSecrets())
	if strings.Contains(out, fixtureUUID) {
		t.Fatalf("leaked uuid in redacted transparent config: %s", out)
	}
}
