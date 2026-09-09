package platform

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/routing"
)

type spyEngine struct {
	reconcile []bool
	err       error
}

func (s *spyEngine) Plan() (routing.CapturePlan, error) { return routing.CapturePlan{}, nil }
func (s *spyEngine) DryRun() (routing.CapturePlan, error) {
	return routing.CapturePlan{}, nil
}
func (s *spyEngine) Preflight(context.Context) (routing.PreflightReport, error) {
	return routing.PreflightReport{OK: true}, nil
}
func (s *spyEngine) Apply(context.Context) error    { return s.err }
func (s *spyEngine) Remove(context.Context) error   { return nil }
func (s *spyEngine) FailOpen(context.Context) error { return nil }
func (s *spyEngine) Reconcile(_ context.Context, desired bool) error {
	s.reconcile = append(s.reconcile, desired)
	if desired {
		return s.err
	}
	return nil
}

func nfWriteExec(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func nfWriteJSON(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNetfilterReconcileCLIWiresHybrid(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"log":{}}`)
	spy := &spyEngine{}
	err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
		Prefix:      dir,
		ManagerPath: mgr,
		XrayPath:    xr,
		ConfigPath:  cfg,
		Client:      "192.168.1.50",
		Alive:       func() bool { return true },
		Network:     &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
		NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
			return spy, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("default capture.enabled=false must Reconcile desired-absent, got %v", spy.reconcile)
	}
}

func TestNetfilterReconcileStopRemoves(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	spy := &spyEngine{}
	err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
		Stop:        true,
		Prefix:      dir,
		ManagerPath: mgr,
		XrayPath:    xr,
		Alive:       func() bool { return false },
		NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
			return spy, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("stop must Reconcile desired-absent, got %v", spy.reconcile)
	}
}

func TestReconcileApplyRefusesXKeenWithZeroMutations(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"inbounds":[]}`)
	spy := &spyEngine{err: routing.ErrExistingCaptureEngine}
	err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
		Prefix:         dir,
		ManagerPath:    mgr,
		XrayPath:       xr,
		ConfigPath:     cfg,
		Client:         "192.168.1.50",
		Alive:          func() bool { return true },
		Network:        &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
		CaptureEnabled: captureOn(),
		NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
			return spy, nil
		},
	})
	if !errors.Is(err, routing.ErrExistingCaptureEngine) {
		t.Fatalf("got %v", err)
	}
	if len(spy.reconcile) != 1 || !spy.reconcile[0] {
		t.Fatalf("Apply path must still be attempted: %v", spy.reconcile)
	}
}

func TestReconcileWithoutClientDoesNotApply(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"inbounds":[]}`)
	spy := &spyEngine{}
	err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
		Prefix:         dir,
		ManagerPath:    mgr,
		XrayPath:       xr,
		ConfigPath:     cfg,
		Alive:          func() bool { return true },
		Network:        &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
		CaptureEnabled: captureOn(),
		NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
			return spy, nil
		},
	})
	if !errors.Is(err, ErrClientRequired) {
		t.Fatalf("got %v", err)
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("missing client must fail-open, got %v", spy.reconcile)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	b, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReconcileDiagDesiredFalseRemove(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	spy := &spyEngine{}
	out := captureStderr(t, func() {
		err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
			Stop:        true,
			Prefix:      dir,
			ManagerPath: mgr,
			XrayPath:    xr,
			Alive:       func() bool { return false },
			NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
				return spy, nil
			},
		})
		if err != nil {
			t.Errorf("stop: %v", err)
		}
	})
	for _, tok := range []string{
		"origin=manual",
		"capture_enabled=false",
		"decision=desired-absent",
		"reason=stop",
		"desired=false",
		"our_xray_alive=false",
		"action=remove",
		"result=success",
	} {
		if !strings.Contains(out, tok) {
			t.Fatalf("missing %s in %q", tok, out)
		}
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("desired false must Remove, got %v", spy.reconcile)
	}
}

func TestReconcileDiagDesiredTrueApply(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"log":{}}`)
	spy := &spyEngine{}
	out := captureStderr(t, func() {
		err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
			Prefix:         dir,
			ManagerPath:    mgr,
			XrayPath:       xr,
			ConfigPath:     cfg,
			Client:         "192.168.1.50",
			Alive:          func() bool { return true },
			Network:        &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
			CaptureEnabled: captureOn(),
			NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
				return spy, nil
			},
		})
		if err != nil {
			t.Errorf("apply: %v", err)
		}
	})
	for _, tok := range []string{
		"origin=manual",
		"capture_enabled=true",
		"decision=desired-present",
		"reason=ready",
		"desired=true",
		"client=192.168.1.50",
		"our_xray_alive=true",
		"action=apply",
		"result=success",
	} {
		if !strings.Contains(out, tok) {
			t.Fatalf("missing %s in %q", tok, out)
		}
	}
	if len(spy.reconcile) != 1 || !spy.reconcile[0] {
		t.Fatalf("desired true must Apply, got %v", spy.reconcile)
	}
}

func TestReconcileOriginManualAndNDM(t *testing.T) {
	if ReconcileOrigin() != "manual" {
		t.Fatalf("default origin=%s", ReconcileOrigin())
	}
	t.Setenv(NDMHookEnv, "1")
	if ReconcileOrigin() != "ndm" {
		t.Fatalf("ndm origin=%s", ReconcileOrigin())
	}
}

func TestDisabledCaptureNeverAppliesWithOurXrayAlive(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"log":{}}`)
	spy := &spyEngine{}
	out := captureStderr(t, func() {
		err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
			Prefix:         dir,
			ManagerPath:    mgr,
			XrayPath:       xr,
			ConfigPath:     cfg,
			Client:         "192.168.1.50",
			Alive:          func() bool { return true },
			Network:        &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
			CaptureEnabled: captureOff(),
			NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
				return spy, nil
			},
		})
		if err != nil {
			t.Errorf("disabled: %v", err)
		}
	})
	for _, tok := range []string{
		"capture_enabled=false",
		"decision=desired-absent",
		"reason=capture-disabled",
		"desired=false",
		"our_xray_alive=true",
		"action=remove",
		"result=success",
	} {
		if !strings.Contains(out, tok) {
			t.Fatalf("missing %s in %q", tok, out)
		}
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("OUR Xray alive must not Apply when capture is disabled: %v", spy.reconcile)
	}
}

func TestDisabledCaptureNeverAppliesWithSelectedClient(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"log":{}}`)
	spy := &spyEngine{}
	err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
		Prefix:         dir,
		ManagerPath:    mgr,
		XrayPath:       xr,
		ConfigPath:     cfg,
		Client:         "172.17.100.50",
		Alive:          func() bool { return true },
		Network:        &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
		CaptureEnabled: captureOff(),
		NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
			return spy, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("selected-client must not Apply when capture is disabled: %v", spy.reconcile)
	}
}

func TestNDMDisabledCaptureNeverApplies(t *testing.T) {
	t.Setenv(NDMHookEnv, "1")
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"log":{}}`)
	spy := &spyEngine{}
	out := captureStderr(t, func() {
		err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
			Prefix:         dir,
			ManagerPath:    mgr,
			XrayPath:       xr,
			ConfigPath:     cfg,
			Client:         "192.168.1.50",
			Alive:          func() bool { return true },
			Network:        &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
			CaptureEnabled: captureOff(),
			NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
				return spy, nil
			},
		})
		if err != nil {
			t.Errorf("ndm disabled: %v", err)
		}
	})
	if !strings.Contains(out, "origin=ndm") || !strings.Contains(out, "reason=capture-disabled") {
		t.Fatalf("ndm disabled diag %q", out)
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("NDM must not Apply when capture is disabled: %v", spy.reconcile)
	}
}

func TestManagerRestartDisabledNeverApplies(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	cfg := filepath.Join(dir, "xray.json")
	nfWriteJSON(t, cfg, `{"log":{}}`)
	spy := &spyEngine{}
	cmd := NFCommand{
		Prefix:         dir,
		ManagerPath:    mgr,
		XrayPath:       xr,
		ConfigPath:     cfg,
		Client:         "192.168.1.50",
		Alive:          func() bool { return true },
		Network:        &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
		CaptureEnabled: captureOff(),
		NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
			return spy, nil
		},
	}
	if err := ExecuteNetfilterReconcile(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteNetfilterReconcile(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if len(spy.reconcile) != 2 {
		t.Fatalf("restart must reconcile twice, got %v", spy.reconcile)
	}
	for i, d := range spy.reconcile {
		if d {
			t.Fatalf("restart %d Applied: %v", i, spy.reconcile)
		}
	}
}

func TestDisabledCaptureRemovesOwnedOnly(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	spy := &spyEngine{}
	out := captureStderr(t, func() {
		err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
			Prefix:         dir,
			ManagerPath:    mgr,
			XrayPath:       xr,
			Alive:          func() bool { return true },
			CaptureEnabled: captureOff(),
			NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
				return spy, nil
			},
		})
		if err != nil {
			t.Errorf("remove-owned: %v", err)
		}
	})
	if !strings.Contains(out, "action=remove") || !strings.Contains(out, "reason=capture-disabled") {
		t.Fatalf("diag %q", out)
	}
	if len(spy.reconcile) != 1 || spy.reconcile[0] {
		t.Fatalf("disabled must RemoveOwned, got %v", spy.reconcile)
	}
}

func TestLockFailureDoesNotCallEngine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run"), []byte("notdir"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	spy := &spyEngine{}
	out := captureStderr(t, func() {
		err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
			Prefix:         dir,
			ManagerPath:    mgr,
			XrayPath:       xr,
			Alive:          func() bool { return true },
			CaptureEnabled: captureOff(),
			NewEngine: func(netip.Addr, routing.Executor) (routing.TrafficCaptureEngine, error) {
				return spy, nil
			},
		})
		if err == nil {
			t.Error("lock failure must return an error")
		}
		if !errors.Is(err, ErrNetfilterLock) {
			t.Errorf("want ErrNetfilterLock, got %v", err)
		}
	})
	if len(spy.reconcile) != 0 {
		t.Fatalf("engine Reconcile must not run without lock, got %v", spy.reconcile)
	}
	for _, tok := range []string{
		"reason=lock-failed",
		"result=failure",
		"action=none",
	} {
		if !strings.Contains(out, tok) {
			t.Fatalf("missing %s in %q", tok, out)
		}
	}
}
