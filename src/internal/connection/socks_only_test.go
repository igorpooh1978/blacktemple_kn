package connection

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/keys"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/platform"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

func TestSOCKSOnlyConnectOmitsTransparentInbounds(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"tag":"socks-in"`) && !strings.Contains(text, `"tag": "socks-in"`) {
		t.Fatal("missing socks-in")
	}
	if !strings.Contains(text, `"listen":"127.0.0.1"`) && !strings.Contains(text, `"listen": "127.0.0.1"`) {
		t.Fatal("SOCKS must bind 127.0.0.1")
	}
	if !strings.Contains(text, `"port":11080`) && !strings.Contains(text, `"port": 11080`) {
		t.Fatal("SOCKS port 11080")
	}
	for _, bad := range []string{"redirect-in", "tproxy-in", "11820", "transparentListen"} {
		if strings.Contains(text, bad) {
			t.Fatalf("SOCKS-only config contains %s", bad)
		}
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := cfg["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("inbounds=%d want 1", len(inbounds))
	}
}

func TestSOCKSConnectLeavesCaptureDisabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`{"capture":{"enabled":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := &fakeEngine{}
	s := New(Config{
		Profiles:    profiles.NewService(nil, nil),
		Engine:      eng,
		DataDir:     t.TempDir(),
		ListenPort:  11080,
		FastBackoff: true,
	})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"enabled":false`) && !strings.Contains(string(raw), `"enabled": false`) {
		t.Fatalf("capture file mutated")
	}
	if platform.LoadCaptureEnabled(cfgPath) {
		t.Fatal("capture.enabled became true")
	}
	if err := s.Control(context.Background(), "disconnect"); err != nil {
		t.Fatal(err)
	}
	if platform.LoadCaptureEnabled(cfgPath) {
		t.Fatal("capture.enabled true after disconnect")
	}
}

func TestSOCKSConnectSourcesNeverApplyNetfilter(t *testing.T) {
	// go test cwd is the package directory; do not use runtime.Caller (trimpath).
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{
			"ExecuteNetfilterReconcile",
			"S05xkeen",
			"iptables",
			"ipset",
			"Transparent: true",
			"Transparent:true",
		} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %s", e.Name(), bad)
			}
		}
	}
}

func TestSOCKSGeneratedConfigXrayTest(t *testing.T) {
	exe := os.Getenv("XRAY_EXECUTABLE")
	if exe == "" {
		if p, err := exec.LookPath("xray"); err == nil {
			exe = p
		} else if p, err := exec.LookPath("xray.exe"); err == nil {
			exe = p
		}
	}
	if exe == "" {
		t.Skip("xray executable not found; live xray run -test NOT RUN")
	}
	runner := &xray.Runner{Executable: exe}
	s := New(Config{
		Profiles:    profiles.NewService(nil, nil),
		Engine:      NewXrayEngine(runner),
		DataDir:     t.TempDir(),
		ListenPort:  11080,
		FastBackoff: true,
	})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	raw, err := s.generateLocked()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runner.ValidateConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
}

func TestChangeKeyDoesNotStopRunningSOCKS(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	pid := s.Status().Xray.PID
	ks, err := s.Profiles().Keys(s.Profiles().ActiveID())
	if err != nil || len(ks) == 0 {
		t.Fatal(err)
	}
	_, err = s.Profiles().ChangeKey(context.Background(), s.Profiles().ActiveID(), ks[0].ID)
	if !errors.Is(err, keys.ErrProviderNotConfigured) {
		t.Fatalf("unconfigured changer got %v", err)
	}
	st := s.Status()
	if st.Connection != "connected" {
		t.Fatalf("failed ChangeKey broke SOCKS: %+v", st)
	}
	if st.Xray.PID == nil || pid == nil || *st.Xray.PID != *pid {
		t.Fatalf("PID changed pid=%v after=%v", pid, st.Xray.PID)
	}
}

func TestSuccessfulChangeKeyLeavesSOCKSRunning(t *testing.T) {
	eng := &fakeEngine{}
	dir := t.TempDir()
	s := New(Config{
		Profiles: profiles.New(profiles.Config{
			Changer: connFakeChanger{uri: "vless://" + testUUID + "@10.0.0.1:443?type=tcp&security=tls#DE"},
			DataDir: dir,
		}),
		Engine:      eng,
		DataDir:     dir,
		ListenPort:  11080,
		FastBackoff: true,
	})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	pid := s.Status().Xray.PID
	ks, err := s.Profiles().Keys(s.Profiles().ActiveID())
	if err != nil || len(ks) == 0 {
		t.Fatal(err)
	}
	if _, err := s.Profiles().ChangeKey(context.Background(), s.Profiles().ActiveID(), ks[0].ID); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.Connection != "connected" {
		t.Fatalf("ChangeKey stopped SOCKS: %+v", st)
	}
	if st.Xray.PID == nil || pid == nil || *st.Xray.PID != *pid {
		t.Fatalf("PID changed pid=%v after=%v", pid, st.Xray.PID)
	}
}

type connFakeChanger struct {
	uri string
}

func (f connFakeChanger) ChangeKey(context.Context, keys.ChangeKeyRequest) (keys.ChangeKeyResponse, error) {
	return keys.NewChangeKeyResponse(f.uri), nil
}
