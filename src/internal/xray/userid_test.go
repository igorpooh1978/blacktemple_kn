package xray

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

const shortVLESSID = "test"

func TestShortVLESSUserIDAccepted(t *testing.T) {
	raw, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: shortVLESSID}, fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatalf("4-byte VLESS id must be accepted per Xray mapping; got %v", err)
	}
	if !bytes.Contains(raw, []byte(`"id":"`+shortVLESSID+`"`)) {
		t.Fatalf("generated config missing unchanged short id")
	}
	if strings.Contains(errString(err), "uuid is malformed") {
		t.Fatal("uuid-only validator still rejects Xray short ids")
	}
}

func TestFourByteVLESSUserIDUnchangedInConfig(t *testing.T) {
	raw, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: shortVLESSID}, fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatalf("expected generate, got %v", err)
	}
	var cfg struct {
		Outbounds []struct {
			Settings struct {
				Vnext []struct {
					Users []struct {
						ID string `json:"id"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Outbounds) == 0 || len(cfg.Outbounds[0].Settings.Vnext) == 0 || len(cfg.Outbounds[0].Settings.Vnext[0].Users) == 0 {
		t.Fatal("missing vless user")
	}
	got := cfg.Outbounds[0].Settings.Vnext[0].Users[0].ID
	if got != shortVLESSID {
		t.Fatalf("users.id=%q want %q (must not rewrite to UUID)", got, shortVLESSID)
	}
	if len(got) != 4 {
		t.Fatalf("id byte length %d want 4", len(got))
	}
}

func TestFourByteVLESSUserIDXRayTest(t *testing.T) {
	raw, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: shortVLESSID}, fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	exe := lookupTestXray(t)
	if exe == "" {
		t.Skip("xray executable not found; live xray run -test NOT RUN")
	}
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Runner{Executable: exe}
	if err := r.ValidateConfig(context.Background(), path); err != nil {
		t.Fatalf("xray run -test rejected short VLESS id: %v", err)
	}
}

func TestCanonicalUUIDUnchanged(t *testing.T) {
	raw, err := Generate(fixtureProfile("tcp", "tls"), fixtureSecrets(), fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"id":"`+fixtureUUID+`"`)) {
		t.Fatal("canonical UUID was rewritten")
	}
}

func TestEmptyVLESSUserIDRejected(t *testing.T) {
	_, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: "  "}, fixtureParams("tcp"), Options{})
	if err == nil {
		t.Fatal("expected reject")
	}
	if strings.Contains(err.Error(), "  ") {
		t.Fatalf("error leaked id: %v", err)
	}
}

func TestThirtyByteVLESSUserIDAccepted(t *testing.T) {
	id := strings.Repeat("a", 30)
	raw, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: id}, fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatalf("30-byte id must be accepted: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"id":"`+id+`"`)) {
		t.Fatal("30-byte id was rewritten")
	}
}

func TestThirtyOneByteVLESSUserIDRejected(t *testing.T) {
	id := strings.Repeat("a", 31)
	_, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: id}, fixtureParams("tcp"), Options{})
	if err == nil {
		t.Fatal("31-byte non-UUID id must be rejected")
	}
	if strings.Contains(err.Error(), id) {
		t.Fatalf("error leaked id: %v", err)
	}
}

func TestShortVLESSUserIDNotRegenerated(t *testing.T) {
	raw, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: shortVLESSID}, fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(fixtureUUID)) {
		t.Fatal("short id was replaced with a fixture UUID")
	}
	if !bytes.Contains(raw, []byte(`"id":"test"`)) {
		t.Fatal("short id was not preserved")
	}
}

func TestVLESSUserIDAbsentFromErrors(t *testing.T) {
	id := strings.Repeat("s", 31)
	_, err := Generate(fixtureProfile("tcp", "tls"), ConfigSecrets{UUID: id}, fixtureParams("tcp"), Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), id) {
		t.Fatalf("error leaked vless id: %v", err)
	}
	if utf8.RuneCountInString(id) > 0 && strings.Contains(err.Error(), shortVLESSID) && shortVLESSID != id {
		t.Fatal("unexpected short id in error")
	}
}

func TestValidRealityPublicKeyAccepted(t *testing.T) {
	pub := mustTestRealityPub(t)
	info := InspectRealityPublicKey(pub)
	if !info.Present || !info.Valid || info.DecodedLength != 32 {
		t.Fatalf("test X25519 key not structurally valid: %+v", info)
	}
	_, err := Generate(fixtureProfile("tcp", "reality"), ConfigSecrets{UUID: shortVLESSID}, OutboundParams{
		SNI:         "www.example.com",
		PublicKey:   pub,
		Fingerprint: "chrome",
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMalformedRealityPublicKeyClassified(t *testing.T) {
	dummy := "abcde"
	info := InspectRealityPublicKey(dummy)
	if info.Valid {
		t.Fatal("5-char dummy must not be structurally valid")
	}
	if info.EncodedLength != 5 {
		t.Fatalf("encoded_length=%d want 5", info.EncodedLength)
	}
	if !info.Present {
		t.Fatal("present should be true")
	}
	_, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), OutboundParams{
		SNI:       "www.example.com",
		PublicKey: dummy,
	}, Options{})
	if err == nil {
		t.Fatal("malformed Reality public key must be rejected")
	}
	if !errors.Is(err, ErrInvalidRealityPublicKey) {
		t.Fatalf("want ErrInvalidRealityPublicKey got %v", err)
	}
	if strings.Contains(err.Error(), dummy) {
		t.Fatalf("error leaked public key: %v", err)
	}
}

func TestEmptyRealityShortIDAllowed(t *testing.T) {
	_, err := Generate(fixtureProfile("tcp", "reality"), ConfigSecrets{UUID: shortVLESSID}, OutboundParams{
		SNI:         "www.example.com",
		PublicKey:   fixturePubKey,
		Fingerprint: "chrome",
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInvalidRealityShortIDClassified(t *testing.T) {
	sid := "abc"
	_, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), OutboundParams{
		SNI:       "www.example.com",
		PublicKey: fixturePubKey,
		ShortID:   sid,
	}, Options{})
	if err == nil {
		t.Fatal("odd-length shortId must be rejected")
	}
	if !errors.Is(err, ErrInvalidRealityShortID) {
		t.Fatalf("want ErrInvalidRealityShortID got %v", err)
	}
	if strings.Contains(err.Error(), sid) {
		t.Fatalf("error leaked shortId: %v", err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func lookupTestXray(t *testing.T) string {
	t.Helper()
	if exe := os.Getenv("XRAY_EXECUTABLE"); exe != "" {
		return exe
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	if p, err := exec.LookPath("xray.exe"); err == nil {
		return p
	}
	return ""
}

func mustTestRealityPub(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}
