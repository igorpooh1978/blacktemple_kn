package platform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureConfigPathIsConffiles(t *testing.T) {
	p := CaptureConfigPath(PrefixDir)
	n := strings.ReplaceAll(p, `\`, `/`)
	if !strings.HasSuffix(n, "/config/config.json") {
		t.Fatalf("canonical config must be config/config.json, got %s", p)
	}
	if strings.Contains(n, "/data/config.json") {
		t.Fatal("do not store capture.enabled under data/")
	}
}

func TestEnsureCaptureConfigDefaultsDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "config.json")
	if err := EnsureCaptureConfig(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg DaemonCaptureConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Capture.Enabled {
		t.Fatal("fresh install must default capture.enabled=false")
	}
	if cfg.Capture.Engine != CaptureEngineTransparentIptables {
		t.Fatalf("engine %q", cfg.Capture.Engine)
	}
	if LoadCaptureEnabled(path) {
		t.Fatal("LoadCaptureEnabled must be false after Ensure")
	}
	// Second Ensure must not flip enabled.
	if err := os.WriteFile(path, []byte(`{"capture":{"enabled":false,"engine":"transparent-iptables"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureCaptureConfig(path); err != nil {
		t.Fatal(err)
	}
	if LoadCaptureEnabled(path) {
		t.Fatal("Ensure must not enable an existing file")
	}
}

func TestMissingCaptureSettingIsFalse(t *testing.T) {
	if LoadCaptureEnabled(filepath.Join(t.TempDir(), "missing.json")) {
		t.Fatal("missing file must be false")
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"other":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadCaptureEnabled(p) {
		t.Fatal("config without capture.enabled must be false")
	}
	p2 := filepath.Join(t.TempDir(), "empty-capture.json")
	if err := os.WriteFile(p2, []byte(`{"capture":{}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadCaptureEnabled(p2) {
		t.Fatal("empty capture object must be false")
	}
}

func TestCorruptCaptureConfigFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cases := []string{
		`{`,
		`{"capture":{"enabled":"true"}}`,
		`{"capture":{"enabled":1}}`,
		`{"capture":{"enabled":"yes"}}`,
		`not-json`,
		``,
	}
	for i, body := range cases {
		p := filepath.Join(dir, "c"+string(rune('a'+i))+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if LoadCaptureEnabled(p) {
			t.Fatalf("corrupt %q must fail closed to false", body)
		}
	}
}

func TestEnvCannotEnableCapture(t *testing.T) {
	t.Setenv("BTKN_CAPTURE_ENABLED", "true")
	t.Setenv("CAPTURE_ENABLED", "1")
	t.Setenv("BTKN_CAPTURE_ENABLE", "true")
	dir := t.TempDir()
	if LoadCaptureEnabled(filepath.Join(dir, "missing.json")) {
		t.Fatal("env must not enable capture when the file is missing")
	}
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"capture":{"enabled":false}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadCaptureEnabled(p) {
		t.Fatal("env must not override persisted enabled=false")
	}
	src, err := os.ReadFile("capturecfg.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "Getenv") || strings.Contains(text, "os.Getenv") {
		t.Fatal("LoadCaptureEnabled must not read environment variables")
	}
}

func TestJSONBoolTrueOnlyExactTrue(t *testing.T) {
	if jsonBoolTrue(nil) {
		t.Fatal("nil")
	}
	if jsonBoolTrue(json.RawMessage(`false`)) {
		t.Fatal("false")
	}
	if !jsonBoolTrue(json.RawMessage(`true`)) {
		t.Fatal("true")
	}
	p := filepath.Join(t.TempDir(), "on.json")
	if err := os.WriteFile(p, []byte(`{"capture":{"enabled":true,"engine":"transparent-iptables"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !LoadCaptureEnabled(p) {
		t.Fatal("JSON boolean true must enable")
	}
}
