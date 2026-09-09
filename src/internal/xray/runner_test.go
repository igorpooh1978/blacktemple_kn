package xray

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lookupXray(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("XRAY_EXECUTABLE"); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("XRAY_EXECUTABLE=%s: %v", p, err)
		}
		return p
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	if p, err := exec.LookPath("xray.exe"); err == nil {
		return p
	}
	t.Skip("xray executable not found; live xray run -test NOT RUN")
	return ""
}

func TestValidateConfigLive(t *testing.T) {
	exe := lookupXray(t)
	r := &Runner{Executable: exe}

	raw, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.ValidateConfig(ctx, path); err != nil {
		t.Fatal(err)
	}
}

func TestValidateGeneratedTransportsLive(t *testing.T) {
	exe := lookupXray(t)
	r := &Runner{Executable: exe}
	cases := []struct {
		transport string
		security  string
	}{
		{"tcp", "tls"},
		{"ws", "tls"},
		{"grpc", "tls"},
		{"xhttp", "tls"},
		{"tcp", "reality"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, tc := range cases {
		t.Run(tc.transport+"-"+tc.security, func(t *testing.T) {
			raw, err := Generate(fixtureProfile(tc.transport, tc.security), fixtureSecrets(), fixtureParams(tc.transport), Options{})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := r.ValidateConfig(ctx, path); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRunnerVersionLive(t *testing.T) {
	exe := lookupXray(t)
	r := &Runner{Executable: exe}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := r.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "26.7.28") && !strings.Contains(out, "Xray") {
		t.Fatalf("unexpected version output: %q", out)
	}
}

func TestRunnerStartStopLive(t *testing.T) {
	exe := lookupXray(t)
	r := &Runner{Executable: exe}
	raw, err := Generate(fixtureProfile("tcp", "tls"), fixtureSecrets(), fixtureParams("tcp"), Options{ListenPort: 11081})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()
	if err := r.Start(startCtx, path); err != nil {
		t.Fatal(err)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := r.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerRequiresExecutable(t *testing.T) {
	r := &Runner{}
	if _, err := r.Version(context.Background()); err == nil {
		t.Fatal("expected empty executable error")
	}
}

func TestValidateTransparentConfigLive(t *testing.T) {
	exe := lookupXray(t)
	r := &Runner{Executable: exe}

	socks, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), fixtureParams("tcp"), Options{Transparent: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	socksPath := filepath.Join(t.TempDir(), "socks.json")
	if err := os.WriteFile(socksPath, socks, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateConfig(ctx, socksPath); err != nil {
		t.Fatal(err)
	}
	trPath := filepath.Join(t.TempDir(), "transparent.json")
	if err := os.WriteFile(trPath, tr, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateConfig(ctx, trPath); err != nil {
		t.Fatal(err)
	}
}

func TestValidateFreedomTransparentLive(t *testing.T) {
	exe := lookupXray(t)
	r := &Runner{Executable: exe}
	raw, err := os.ReadFile(filepath.Join("testdata", "golden-freedom-transparent.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	s := string(raw)
	s = strings.ReplaceAll(s, "/opt/blacktemple-kn/logs/xray-access.log", filepath.ToSlash(filepath.Join(tmp, "access.log")))
	s = strings.ReplaceAll(s, "/opt/blacktemple-kn/logs/xray-error.log", filepath.ToSlash(filepath.Join(tmp, "error.log")))
	path := filepath.Join(tmp, "freedom.json")
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.ValidateConfig(ctx, path); err != nil {
		t.Fatal(err)
	}
}

func TestFreedomTransparentGoldenShape(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "golden-freedom-transparent.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "1181") {
		t.Fatal("freedom golden must not use XKeen port 1181")
	}
	if !strings.Contains(s, `"port":11820`) {
		t.Fatal("transparent port must be 11820")
	}
	if !strings.Contains(s, `"protocol":"freedom"`) {
		t.Fatal("R6-I harness outbound is freedom")
	}
	if !strings.Contains(s, `"tproxy":"tproxy"`) {
		t.Fatal("UDP inbound must enable tproxy")
	}
	idxTCP := strings.Index(s, `"tag":"redirect-in"`)
	idxUDP := strings.Index(s, `"tag":"tproxy-in"`)
	if idxTCP < 0 || idxUDP < 0 || idxUDP < idxTCP {
		t.Fatal("expected redirect-in then tproxy-in")
	}
	mid := s[idxTCP:idxUDP]
	if strings.Contains(mid, "tproxy") {
		t.Fatal("TCP inbound must not set tproxy sockopt")
	}
}

func TestValidateMalformedConfigLive(t *testing.T) {
	exe := lookupXray(t)
	r := &Runner{Executable: exe}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := r.ValidateConfig(ctx, path)
	if err == nil {
		t.Fatal("expected invalid json to fail xray run -test")
	}
	if strings.Contains(err.Error(), fixtureUUID) {
		t.Fatalf("error leaked uuid: %v", err)
	}
}
