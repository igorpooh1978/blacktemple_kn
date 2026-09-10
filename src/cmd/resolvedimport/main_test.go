package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvedImportPrintsCountsNotSecrets(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "android-startloop.json")
	raw := []byte(`{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"www.example.com"},"wsSettings":{"path":"/vless","headers":{"Host":"www.example.com"}}}}]}`)
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	cmd := exec.Command("go", "run", ".", "-in", in, "-data-dir", data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "candidate_count=") || !strings.Contains(text, "ws_tls_count=") {
		t.Fatalf("missing counts: %s", text)
	}
	if strings.Contains(text, "11111111-1111-4111-8111-111111111111") || strings.Contains(text, "example.com") || strings.Contains(text, "/vless") {
		t.Fatal("tool leaked secret or host")
	}
}
