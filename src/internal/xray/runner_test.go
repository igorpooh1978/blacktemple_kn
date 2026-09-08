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
