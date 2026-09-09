package platform

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
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
	if len(spy.reconcile) != 1 || !spy.reconcile[0] {
		t.Fatalf("want desired-present Reconcile, got %v", spy.reconcile)
	}
}

func TestNetfilterReconcileStopRemoves(t *testing.T) {
	dir := t.TempDir()
	mgr := nfWriteExec(t, dir, "blacktempled")
	xr := nfWriteExec(t, dir, "xray")
	spy := &spyEngine{}
	err := ExecuteNetfilterReconcile(context.Background(), NFCommand{
		Stop:        true,
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
		ManagerPath: mgr,
		XrayPath:    xr,
		ConfigPath:  cfg,
		Alive:       func() bool { return true },
		Network:     &NetworkStatus{OptMounted: true, DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
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
