package platform

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/platform/keenetic"
)

// CaptureDecision is the fail-open result of netfilter-reconcile.
// F never executes iptables. D owns Remove()/Apply of BTKN_ rules.
type CaptureDecision string

const (
	// DecisionDesiredAbsent: capture must not be installed. Integrator calls D.Remove().
	DecisionDesiredAbsent CaptureDecision = "desired-absent"
	// DecisionDesiredPresent: conditions OK for D to Apply after Xray owns 11820.
	DecisionDesiredPresent CaptureDecision = "desired-present"

	// Aliases kept for older comments; prefer DesiredAbsent/Present.
	DecisionNoCapture = DecisionDesiredAbsent
	DecisionRemove    = DecisionDesiredAbsent
	DecisionReady     = DecisionDesiredPresent
)

// RuntimeStateRunning matches supervisor.StateRunning. Duplicated so platform
// does not import supervisor (this wave does not edit that package).
const RuntimeStateRunning = "RUNNING"

var _ KeeneticPolicy = keenetic.PolicyGuard{}

// KeeneticPolicy is the R6 invariant stub: BlackTemple must not grant internet
// Keenetic already denied. Implementations must not invent NDM structs.
type KeeneticPolicy interface {
	CaptureMayGrantDeniedInternet() bool
}

// ReconcileInput is the netfilter-reconcile decision input.
type ReconcileInput struct {
	Stop bool

	ManagerPath string
	XrayPath    string
	ConfigPath  string
	StatePath   string
	StateJSON   []byte

	Network NetworkStatus
	Alive   func() bool
	Policy  KeeneticPolicy
}

// ReconcileResult is the documented command contract for A/D.
type ReconcileResult struct {
	Decision      CaptureDecision
	Reason        string
	ChainPrefix   string
	CaptureOUTPUT bool
	RemoveArgv    []string
}

// BTKNRemoveArgv is the documented argv for stop. D.Remove() performs the
// actual BTKN_ deletion. This slice is never executed by F.
func BTKNRemoveArgv(manager string) []string {
	if manager == "" {
		manager = DefaultManagerPath
	}
	return []string{manager, NetfilterReconcileArg, NetfilterReconcileStopArg}
}

// Reconcile decides whether capture may be installed. Default is fail-open.
//
// Fail-open (DecisionDesiredAbsent) when: manager missing, xray missing, xray
// dead, runtime state invalid/corrupt, config corrupt, network not ready, or
// a policy guard would grant Keenetic-denied internet. DesiredAbsent means
// capture must be removed by D; it is not a no-op. Manager-missing cannot
// itself delete stale BTKN (binary gone).
//
// Stop also returns DecisionDesiredAbsent. Existing BTKN_ teardown is
// D.Remove(); F does not call iptables.
//
// CaptureOUTPUT is always false: router self-generated traffic is DIRECT.
func Reconcile(in ReconcileInput) ReconcileResult {
	manager := in.ManagerPath
	if manager == "" {
		manager = DefaultManagerPath
	}
	xrayPath := in.XrayPath
	if xrayPath == "" {
		xrayPath = DefaultXrayPath
	}

	out := ReconcileResult{
		Decision:      DecisionDesiredAbsent,
		ChainPrefix:   ChainPrefix,
		CaptureOUTPUT: false,
		RemoveArgv:    BTKNRemoveArgv(manager),
	}

	if in.Stop {
		out.Decision = DecisionRemove
		out.Reason = "stop"
		return out
	}

	if in.Policy != nil && in.Policy.CaptureMayGrantDeniedInternet() {
		out.Reason = "keenetic-deny"
		return out
	}

	if !fileExecutable(manager) {
		out.Reason = "manager-missing"
		return out
	}
	if !fileExecutable(xrayPath) {
		out.Reason = "xray-missing"
		return out
	}
	if !in.Network.Ready() {
		out.Reason = "network-not-ready"
		return out
	}
	if in.Alive == nil || !in.Alive() {
		out.Reason = "xray-dead"
		return out
	}

	state, stateOK := loadRuntimeState(in)
	if !stateOK {
		out.Reason = "state-corrupt"
		return out
	}
	if state != RuntimeStateRunning {
		out.Reason = "xray-dead"
		return out
	}

	if !configValid(in.ConfigPath) {
		out.Reason = "config-corrupt"
		return out
	}

	out.Decision = DecisionDesiredPresent
	out.Reason = "ready"
	return out
}

type runtimeStateFile struct {
	State string `json:"state"`
}

func loadRuntimeState(in ReconcileInput) (string, bool) {
	raw := in.StateJSON
	if len(bytes.TrimSpace(raw)) == 0 && in.StatePath != "" {
		b, err := os.ReadFile(in.StatePath)
		if err != nil {
			return "", false
		}
		raw = b
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", false
	}
	var s runtimeStateFile
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	st := strings.TrimSpace(s.State)
	if st == "" {
		return "", false
	}
	switch st {
	case "STOPPED", "STARTING", "RUNNING", "RELOADING", "FAILED", "BACKOFF":
		return st, true
	default:
		return "", false
	}
}

func configValid(path string) bool {
	if path == "" {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return false
	}
	var probe any
	return json.Unmarshal(b, &probe) == nil
}
