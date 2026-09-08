package connection

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("go.mod not found")
	return ""
}

func ensureHostXray(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("XRAY_EXECUTABLE"); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("XRAY_EXECUTABLE: %v", err)
		}
		return p
	}
	if p := os.Getenv("BTKN_XRAY"); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("BTKN_XRAY: %v", err)
		}
		return p
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("host xray test target is amd64")
	}
	target := ""
	bin := "xray"
	switch runtime.GOOS {
	case "windows":
		target = "windows-amd64-test"
		bin = "xray.exe"
	case "linux":
		target = "linux-amd64-test"
	default:
		t.Skip("no host xray lock target for " + runtime.GOOS)
	}
	root := moduleRoot(t)
	out := filepath.Join(root, ".cache", "xray-host", runtime.GOOS+"-"+runtime.GOARCH, bin)
	if _, err := os.Stat(out); err == nil {
		return out
	}
	cmd := exec.Command("go", "run", "./tools/xrayfetch",
		"-lock", "third_party/xray.lock.json",
		"-target", target,
		"-cache", filepath.Join(root, ".cache", "xray"),
		"-out", out,
	)
	cmd.Dir = root
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("host xray fetch NOT RUN: %v %s", err, strings.TrimSpace(string(b)))
	}
	return out
}

func TestHostXrayRestartVPNPidChange(t *testing.T) {
	exe := ensureHostXray(t)
	s := New(Config{
		Engine:     NewXrayEngine(&xray.Runner{Executable: exe}),
		DataDir:    t.TempDir(),
		ListenPort: 11082,
	})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := s.Control(ctx, "connect"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Control(context.Background(), "disconnect") }()
	before := s.Status().Xray.PID
	if before == nil || *before == 0 {
		t.Fatalf("expected host pid, status=%+v", s.Status().Xray)
	}
	if err := s.Control(ctx, "restart-vpn"); err != nil {
		t.Fatal(err)
	}
	after := s.Status().Xray.PID
	if after == nil || *after == 0 || *after == *before {
		t.Fatalf("pid before=%v after=%v", before, after)
	}
}

func TestRealBlackKeySmoke(t *testing.T) {
	raw := optionalBlackKey()
	if raw == "" {
		t.Log("REAL_BLACKKEY_SMOKE: NOT RUN")
		return
	}
	exe := ensureHostXray(t)
	s := New(Config{
		Engine:     NewXrayEngine(&xray.Runner{Executable: exe}),
		DataDir:    t.TempDir(),
		ListenPort: 11083,
	})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: raw, Name: "smoke"}); err != nil {
		t.Fatalf("import failed: %s", publicError(err))
	}
	ks, err := s.Profiles().Keys(s.Profiles().ActiveID())
	if err != nil || len(ks) == 0 {
		t.Fatal("no keys after import")
	}
	var proto, transport, security string
	for _, k := range ks {
		if !strings.EqualFold(k.Protocol, "vless") {
			continue
		}
		proto = k.Protocol
		srvs, _ := s.Profiles().Servers(s.Profiles().ActiveID())
		for _, srv := range srvs {
			if srv.ID == k.ServerID {
				transport = srv.Transport
				security = srv.Security
				break
			}
		}
		break
	}
	if proto == "" {
		t.Fatal("no vless candidate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := s.Control(ctx, "connect"); err != nil {
		t.Fatalf("connect failed: %s", publicError(err))
	}
	defer func() { _ = s.Control(context.Background(), "disconnect") }()

	httpStatus, latency, err := socksHTTPProbe(ctx, "127.0.0.1:11083")
	report := fmt.Sprintf("REAL_BLACKKEY_SMOKE protocol=%s transport=%s security=%s", proto, transport, security)
	if err != nil {
		t.Log(report)
		t.Fatalf("socks probe failed")
	}
	t.Logf("%s HTTP status=%d latency=%s", report, httpStatus, latency)
}

func optionalBlackKey() string {
	if v := strings.TrimSpace(os.Getenv("BTKN_TEST_BLACKKEY")); v != "" {
		return v
	}
	root, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 8; i++ {
		p := filepath.Join(root, ".research-local", "test-blackkey.txt")
		b, err := os.ReadFile(p)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
		parent := filepath.Dir(root)
		if parent == root {
			break
		}
		root = parent
	}
	return ""
}

func socksHTTPProbe(ctx context.Context, proxy string) (int, time.Duration, error) {
	start := time.Now()
	conn, err := dialSOCKS5NoAuth(ctx, proxy, "example.com", 80)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, 0, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, 0, err
	}
	var proto string
	var code int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%s %d", &proto, &code); err != nil {
		return 0, 0, err
	}
	return code, time.Since(start), nil
}
