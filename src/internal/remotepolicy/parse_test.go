package remotepolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseUnknownPolicyIgnored(t *testing.T) {
	doc, err := Parse([]byte(`{
		"x-block-quic": true,
		"x-apple-direct": true,
		"x-pokaz-key": "nope",
		"command": "rm -rf /",
		"shell": "/bin/sh"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Settings.BlockQUIC == nil || !*doc.Settings.BlockQUIC {
		t.Fatalf("blockquic=%v", doc.Settings.BlockQUIC)
	}
	if len(doc.Ignored) < 3 {
		t.Fatalf("ignored=%v", doc.Ignored)
	}
	for _, iss := range doc.Ignored {
		if iss.Key == "x-block-quic" {
			t.Fatal("known key reported unknown")
		}
	}
}

func TestParseInvalidKnownPolicyRejected(t *testing.T) {
	cases := []string{
		`{"x-block-quic":"yes"}`,
		`{"x-custom-route-action":"explode"}`,
		`{"x-mtu":"big"}`,
		`{"x-custom-route-domains":"not-array"}`,
		`{"x-telegram-ips":"file:///etc/passwd"}`,
		`{"x-whatsapp-ips":"javascript:alert(1)"}`,
	}
	for _, c := range cases {
		_, err := Parse([]byte(c))
		if !errors.Is(err, ErrInvalidKnownKey) {
			t.Fatalf("%s -> %v", c, err)
		}
	}
}

func TestLocalOverrideBeatsRemotePolicy(t *testing.T) {
	m := NewManager(BuiltInDefaults())
	origin := Origin{Kind: OriginTrustedProvider, URL: "https://203.0.113.10/policy", Trusted: true}
	body := []byte(`{"x-block-quic":true,"x-mtu":1400}`)
	sum := sha256.Sum256(body)
	_, err := m.ApplyRemote(origin, body, IntegrityInput{SHA256Pin: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	f := false
	mtu := 1280
	m.SetLocal(Settings{BlockQUIC: &f, MTU: &mtu})
	eff := m.Effective()
	if eff.BlockQUIC == nil || *eff.BlockQUIC {
		t.Fatalf("local must win, got %v", eff.BlockQUIC)
	}
	if eff.MTU == nil || *eff.MTU != 1280 {
		t.Fatalf("mtu=%v", eff.MTU)
	}
}

func TestRemoteCannotOverwriteExplicitUserOverride(t *testing.T) {
	m := NewManager(BuiltInDefaults())
	f := false
	m.SetLocal(Settings{BlockQUIC: &f})
	origin := Origin{Kind: OriginUserConfigured, URL: "https://203.0.113.20/p", Trusted: true}
	body := []byte(`{"x-block-quic":true}`)
	_, err := m.ApplyRemote(origin, body, IntegrityInput{TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	eff := m.Effective()
	if *eff.BlockQUIC {
		t.Fatal("remote overwrote local")
	}
}

func TestUntrustedOriginRejected(t *testing.T) {
	m := NewManager(BuiltInDefaults())
	_, err := m.ApplyRemote(Origin{Kind: OriginTrustedProvider, Trusted: false}, []byte(`{"x-block-quic":true}`), IntegrityInput{TLS: true})
	if err != ErrUntrustedOrigin {
		t.Fatalf("got %v", err)
	}
}

func TestIntegrityTLSOnlyIsNotSigned(t *testing.T) {
	st, err := ClassifyIntegrity([]byte(`{}`), IntegrityInput{TLS: true})
	if err != nil || st != IntegrityTLSOnly {
		t.Fatalf("st=%s err=%v", st, err)
	}
	if st == IntegritySignatureVerified {
		t.Fatal("https is not a signature")
	}
}

func TestIntegrityChecksumAndSignature(t *testing.T) {
	body := []byte(`{"x-sniffing":true}`)
	sum := sha256.Sum256(body)
	st, err := ClassifyIntegrity(body, IntegrityInput{SHA256Pin: hex.EncodeToString(sum[:])})
	if err != nil || st != IntegrityChecksumPinned {
		t.Fatalf("pin st=%s err=%v", st, err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, body)
	st, err = ClassifyIntegrity(body, IntegrityInput{PublicKey: pub, Signature: sig})
	if err != nil || st != IntegritySignatureVerified {
		t.Fatalf("sig st=%s err=%v", st, err)
	}
	_, err = ClassifyIntegrity(body, IntegrityInput{SHA256Pin: strings.Repeat("ab", 32)})
	if err != ErrChecksumMismatch {
		t.Fatalf("mismatch %v", err)
	}
}

func TestRemotePolicyCannotProduceCommandExecution(t *testing.T) {
	doc, err := Parse([]byte(`{
		"x-block-quic": true,
		"command": "reboot",
		"exec": ["/bin/sh","-c","id"],
		"shell": true,
		"iptables": "-F",
		"install": "opkg install evil",
		"password": "root",
		"wan-ui": true,
		"download": "http://evil/payload"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if acts := doc.Settings.RuntimeActions(); len(acts) != 0 {
		t.Fatalf("actions=%v", acts)
	}
	if fw := doc.Settings.FirewallCommands(); len(fw) != 0 {
		t.Fatalf("firewall=%v", fw)
	}
	rt := reflect.TypeOf(Settings{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		switch {
		case strings.Contains(name, "command"),
			strings.Contains(name, "shell"),
			strings.Contains(name, "exec"),
			strings.Contains(name, "iptables"),
			strings.Contains(name, "script"):
			t.Fatalf("exec surface field %s", rt.Field(i).Name)
		}
	}
	if doc.Settings.BlockQUIC == nil || !*doc.Settings.BlockQUIC {
		t.Fatal("typed field missing")
	}
}

func TestSessionBeatsLocal(t *testing.T) {
	m := NewManager(BuiltInDefaults())
	f := false
	tr := true
	m.SetLocal(Settings{BlockQUIC: &f})
	m.SetSession(Settings{BlockQUIC: &tr})
	if !*m.Effective().BlockQUIC {
		t.Fatal("session should win")
	}
}
