package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExec(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func readyNet() NetworkStatus {
	return NetworkStatus{
		OptMounted:     true,
		DefaultRoute:   true,
		LANAvailable:   true,
		XrayExecutable: true,
	}
}

func captureOn() *bool {
	v := true
	return &v
}

func captureOff() *bool {
	v := false
	return &v
}

func TestReconcileManagerMissingNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    filepath.Join(dir, "missing-manager"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
	})
	if r.Decision != DecisionDesiredAbsent {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
	if r.Reason != "manager-missing" {
		t.Fatalf("reason %s", r.Reason)
	}
	if r.CaptureOUTPUT {
		t.Fatal("OUTPUT must not be captured")
	}
}

func TestReconcileXrayMissingNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       filepath.Join(dir, "missing-xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "xray-missing" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileXrayDeadNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return false },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "xray-dead" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileStateCorruptNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{not-json`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "state-corrupt" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileUnknownStateNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"WAT"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "state-corrupt" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileConfigCorruptNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "config-corrupt" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileNetworkNotReadyNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        NetworkStatus{OptMounted: true},
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "network-not-ready" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileReadyDoesNotCaptureOUTPUTOrCallIptables(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{"log":{}}`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
	})
	if r.Decision != DecisionReady {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
	if r.CaptureOUTPUT {
		t.Fatal("router self-generated traffic must stay DIRECT")
	}
	if r.ChainPrefix != ChainPrefix {
		t.Fatalf("prefix %s", r.ChainPrefix)
	}
}

func TestReconcileBackoffDesiredAbsent(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"BACKOFF"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "xray-dead" {
		t.Fatalf("BACKOFF must desire capture absent: %s %s", r.Decision, r.Reason)
	}
}

func TestReconcileStoppedStateNoCapture(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"STOPPED"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "xray-dead" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileStatePathCorruptNoCapture(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, "state.json", `{"state"`)
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StatePath:      p,
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "state-corrupt" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func TestReconcileStopRemovesBTKNContract(t *testing.T) {
	dir := t.TempDir()
	mgr := writeExec(t, dir, "blacktempled")
	r := Reconcile(ReconcileInput{
		Stop:        true,
		ManagerPath: mgr,
	})
	if r.Decision != DecisionRemove {
		t.Fatalf("decision %s", r.Decision)
	}
	if r.ChainPrefix != "BTKN_" {
		t.Fatalf("prefix %s", r.ChainPrefix)
	}
	argv := r.RemoveArgv
	if len(argv) != 3 || argv[1] != NetfilterReconcileArg || argv[2] != NetfilterReconcileStopArg {
		t.Fatalf("RemoveArgv %v", argv)
	}
	if argv[0] != mgr {
		t.Fatalf("manager %s", argv[0])
	}
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "iptables") {
		t.Fatal("F must not return live iptables argv")
	}
	if r.CaptureOUTPUT {
		t.Fatal("stop must not capture OUTPUT")
	}
}

func TestReconcilePolicyGrantDeniedIsFailOpen(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOn(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{}`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
		Policy:         grantDenied{},
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != "keenetic-deny" {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

type grantDenied struct{}

func (grantDenied) CaptureMayGrantDeniedInternet() bool { return true }

func TestReconcileCaptureDisabledWinsOverReady(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		CaptureEnabled: captureOff(),
		ManagerPath:    writeExec(t, dir, "blacktempled"),
		XrayPath:       writeExec(t, dir, "xray"),
		Network:        readyNet(),
		Alive:          func() bool { return true },
		ConfigPath:     writeJSON(t, dir, "cfg.json", `{"log":{}}`),
		StateJSON:      []byte(`{"state":"RUNNING"}`),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != ReasonCaptureDisabled {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
	if r.CaptureOUTPUT {
		t.Fatal("OUTPUT must stay DIRECT")
	}
}

func TestReconcileMissingCaptureConfigIsDisabled(t *testing.T) {
	dir := t.TempDir()
	r := Reconcile(ReconcileInput{
		ManagerPath:       writeExec(t, dir, "blacktempled"),
		XrayPath:          writeExec(t, dir, "xray"),
		Network:           readyNet(),
		Alive:             func() bool { return true },
		ConfigPath:        writeJSON(t, dir, "cfg.json", `{"log":{}}`),
		StateJSON:         []byte(`{"state":"RUNNING"}`),
		CaptureConfigPath: filepath.Join(dir, "no-such-config.json"),
	})
	if r.Decision != DecisionDesiredAbsent || r.Reason != ReasonCaptureDisabled {
		t.Fatalf("decision %s reason %s", r.Decision, r.Reason)
	}
}

func writeJSON(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
