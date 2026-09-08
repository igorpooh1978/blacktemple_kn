package connection

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/supervisor"
)

const testUUID = "11111111-1111-4111-8111-111111111111"

func vlessShare() string {
	return "vless://" + testUUID + "@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=_Cfwmkcph1k8jGWjfjwGSO33zw40qW0fkNxXOrITeik&sid=aabbccdd&spx=/#NL-1"
}

type fakeEngine struct {
	mu           sync.Mutex
	pid          int
	nextPID      int
	failValidate bool
	failStart    bool
	waitCh       chan error
	started      bool
	version      string
}

func (f *fakeEngine) Start(_ context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStart {
		return errors.New("start exploded")
	}
	if f.started {
		return errors.New("already started")
	}
	f.nextPID++
	f.pid = f.nextPID
	f.started = true
	f.waitCh = make(chan error, 1)
	return nil
}

func (f *fakeEngine) Stop(_ context.Context) error {
	f.mu.Lock()
	ch := f.waitCh
	f.started = false
	f.pid = 0
	f.waitCh = nil
	f.mu.Unlock()
	if ch != nil {
		select {
		case ch <- nil:
		default:
		}
	}
	return nil
}

func (f *fakeEngine) Wait(_ context.Context) error {
	f.mu.Lock()
	ch := f.waitCh
	f.mu.Unlock()
	if ch == nil {
		return errors.New("xray not started")
	}
	return <-ch
}

func (f *fakeEngine) ValidateConfig(_ context.Context, path string) error {
	f.mu.Lock()
	fail := f.failValidate
	f.mu.Unlock()
	if fail {
		return errors.New("xray run -test: invalid")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !json.Valid(b) {
		return errors.New("xray run -test: invalid json")
	}
	return nil
}

func (f *fakeEngine) Version(_ context.Context) (string, error) {
	if f.version != "" {
		return f.version, nil
	}
	return "Xray 26.7.28 (go1.22) 1234567", nil
}

func (f *fakeEngine) PID() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pid
}

func (f *fakeEngine) Path() string { return "fake-xray" }

func (f *fakeEngine) crash() {
	f.mu.Lock()
	ch := f.waitCh
	f.started = false
	f.pid = 0
	f.mu.Unlock()
	if ch != nil {
		select {
		case ch <- errors.New("child crashed"):
		default:
		}
	}
}

func newTestService(t *testing.T, eng Engine) *Service {
	t.Helper()
	dir := t.TempDir()
	return New(Config{
		Profiles:    profiles.NewService(nil, nil),
		Engine:      eng,
		DataDir:     dir,
		ListenPort:  11080,
		FastBackoff: true,
	})
}

func TestConnectFailsWithoutProfile(t *testing.T) {
	s := newTestService(t, &fakeEngine{})
	err := s.Control(context.Background(), "connect")
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("got %v", err)
	}
}

func TestImportAndConnectDisconnect(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	ks, err := s.Profiles().Keys(s.Profiles().ActiveID())
	if err != nil || len(ks) == 0 {
		t.Fatal(err)
	}
	p := ks[0].Params()
	if p.SNI != "www.example.com" || p.RealityPublicKey != "_Cfwmkcph1k8jGWjfjwGSO33zw40qW0fkNxXOrITeik" || p.Flow != "xtls-rprx-vision" {
		t.Fatalf("params lost: %#v", p)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.Connection != "connected" || st.Xray.State != string(supervisor.StateRunning) {
		t.Fatalf("status=%+v", st)
	}
	if st.Xray.PID == nil || *st.Xray.PID == 0 {
		t.Fatalf("expected real pid, got %+v", st.Xray)
	}
	if !strings.Contains(st.Xray.Version, "26.7.28") {
		t.Fatalf("version %q", st.Xray.Version)
	}
	if st.Geodata != "missing" {
		t.Fatalf("geodata %q", st.Geodata)
	}
	if st.Routing != "smart" {
		t.Fatalf("routing %q", st.Routing)
	}
	raw, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testUUID) == false {
		t.Fatal("generated config missing uuid (internal file may contain secret)")
	}
	if err := s.Control(context.Background(), "disconnect"); err != nil {
		t.Fatal(err)
	}
	st = s.Status()
	if st.Connection == "connected" || st.Xray.State != string(supervisor.StateStopped) {
		t.Fatalf("after disconnect %+v", st)
	}
}

func TestUnsupportedProtocol(t *testing.T) {
	s := newTestService(t, &fakeEngine{})
	ss := "ss://YWVzLTEyOC1nY206c3MtcGFzcy10ZXN0@127.0.0.1:8388#lab"
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: ss, Name: "ss"}); err != nil {
		t.Fatal(err)
	}
	err := s.Control(context.Background(), "connect")
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("got %v", err)
	}
}

func TestMissingXray(t *testing.T) {
	s := newTestService(t, NewXrayEngine(nil))
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	err := s.Control(context.Background(), "connect")
	if !errors.Is(err, ErrMissingXray) {
		t.Fatalf("got %v", err)
	}
}

func TestValidationFailureLeavesOldConfig(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "disconnect"); err != nil {
		t.Fatal(err)
	}
	eng.mu.Lock()
	eng.failValidate = true
	eng.mu.Unlock()
	err = s.Control(context.Background(), "connect")
	if !errors.Is(err, ErrValidate) {
		t.Fatalf("got %v", err)
	}
	now, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(old) {
		t.Fatal("validation failure mutated working xray.json")
	}
}

func TestStartFailureRestoresBackup(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "disconnect"); err != nil {
		t.Fatal(err)
	}
	eng.mu.Lock()
	eng.failStart = true
	eng.mu.Unlock()
	err = s.Control(context.Background(), "connect")
	if !errors.Is(err, ErrStart) {
		t.Fatalf("got %v", err)
	}
	now, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(old) {
		t.Fatal("start failure did not restore last-known-good config")
	}
}

func TestRestartVPNChangesPID(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	before := s.Status().Xray.PID
	if before == nil {
		t.Fatal("missing pid")
	}
	if err := s.Control(context.Background(), "restart-vpn"); err != nil {
		t.Fatal(err)
	}
	after := s.Status().Xray.PID
	if after == nil || *after == *before {
		t.Fatalf("pid before=%v after=%v", before, after)
	}
}

func TestManagerRestartUnsupported(t *testing.T) {
	s := newTestService(t, &fakeEngine{})
	err := s.Control(context.Background(), "restart-manager")
	if !errors.Is(err, ErrUnsupportedInEnvironment) {
		t.Fatalf("got %v", err)
	}
	err = s.Control(context.Background(), "full-restart")
	if !errors.Is(err, ErrUnsupportedInEnvironment) {
		t.Fatalf("got %v", err)
	}
}

func TestChildCrashIncrementsRestartCount(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	eng.crash()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st := s.Status()
		if st.Xray.RestartCount >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("restartCount still %d", s.Status().Xray.RestartCount)
}

func TestConfigPathNotHardcodedOpt(t *testing.T) {
	s := newTestService(t, &fakeEngine{})
	if filepath.ToSlash(s.ConfigPath()) == "/opt/blacktemple-kn/run/xray.json" {
		t.Fatal("tests must not use /opt")
	}
	if !strings.Contains(s.ConfigPath(), "run") || !strings.HasSuffix(s.ConfigPath(), "xray.json") {
		t.Fatalf("path %s", s.ConfigPath())
	}
}

func TestSecretNotInStatusOrErrors(t *testing.T) {
	s := newTestService(t, &fakeEngine{})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: vlessShare(), Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), testUUID) {
		t.Fatal("status leaked uuid")
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	err = s.Control(context.Background(), "restart-manager")
	if strings.Contains(err.Error(), testUUID) {
		t.Fatal("error leaked uuid")
	}
}
