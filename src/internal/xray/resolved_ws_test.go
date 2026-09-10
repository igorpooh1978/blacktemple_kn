package xray

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvedVLESSWSTLSSocksOnly(t *testing.T) {
	p := Profile{
		ID:        "p1",
		Name:      "lab",
		Protocol:  "vless",
		Server:    "example.com",
		Port:      443,
		Transport: "ws",
		Security:  "tls",
	}
	secrets := ConfigSecrets{UUID: "11111111-1111-4111-8111-111111111111"}
	params := OutboundParams{
		SNI:  "www.example.com",
		Path: "/vless",
		Host: "www.example.com",
	}
	raw, err := Generate(p, secrets, params, Options{ListenHost: "127.0.0.1", ListenPort: 11080})
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "realitySettings") || strings.Contains(text, `"security":"reality"`) {
		t.Fatal("Reality must be absent")
	}
	if !strings.Contains(text, `"network":"ws"`) || !strings.Contains(text, `"security":"tls"`) {
		t.Fatalf("want ws+tls got %s", text)
	}
	if !strings.Contains(text, `"listen":"127.0.0.1"`) || !strings.Contains(text, `"port":11080`) {
		t.Fatal("SOCKS 127.0.0.1:11080 missing")
	}
	for _, bad := range []string{"redirect-in", "tproxy-in", "11820"} {
		if strings.Contains(text, bad) {
			t.Fatalf("SOCKS-only contains %s", bad)
		}
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	bin := os.Getenv("XRAY_EXECUTABLE")
	if bin == "" {
		t.Log("xray run -test: NOT RUN (XRAY_EXECUTABLE unset)")
		return
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-test", "-c", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xray run -test: %v %s", err, out)
	}
}
