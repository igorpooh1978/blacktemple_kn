package routing

import (
	"context"
	"errors"
	"net/netip"
)

// BlackTemple iptables/ipset/policy-routing namespace. Do not reuse XKeen
// marks, tables, ports, or chain names (0x111, 0xffffaaa, table 111, table 4096, port 1181).
const (
	ChainPRE = "BTKN_PRE"
	ChainTCP = "BTKN_TCP"
	ChainUDP = "BTKN_UDP"
	// ChainOUT is reserved for a future OUTPUT path. R6 must not attach it.
	ChainOUT = "BTKN_OUT"

	SetClientsV4 = "btkn_clients_v4"
	SetExcludeV4 = "btkn_exclude_v4"

	CapturePort    = 11820
	TProxyMark     = 0x42544b4e
	TProxyMarkMask = 0xffffffff
	ReservedMark   = 0x42544b4f // reserved, unused in R6
	RouteTable     = 4254
	TProxyAddress  = "127.0.0.1"
	RulePreference = 4254

	IPv6CaptureUnverified = "UNVERIFIED"
)

var (
	ErrClientRequired        = errors.New("routing: selected client IPv4 required")
	ErrExistingCaptureEngine = errors.New("routing: existing capture engine")
	ErrCaptureCollision      = errors.New("routing: capture collision")
	ErrNilExecutor           = errors.New("routing: nil executor")
	ErrCleanupIncomplete     = errors.New("routing: BTKN cleanup incomplete")
	ErrPreflightProbe        = errors.New("routing: preflight probe failed")
)

// OurXrayExecutable is the only process allowed to own capture port 11820.
const OurXrayExecutable = "/opt/blacktemple-kn/bin/xray"

// ExpectedListener is the supervisor-known BlackTemple Xray identity.
type ExpectedListener struct {
	Executable string
	PID        int
}

// CaptureRequirements is the single source of required hybrid capabilities.
// Platform Detect/Prepare must use this; do not maintain a second list.
type CaptureRequirements struct {
	UserlandTools     []string
	IptablesTargets   []string
	IptablesMatches   []string
	NeedIPSet         bool
	NeedPolicyRouting bool
}

// HybridRequirements describes what HybridIptablesEngine actually uses.
func HybridRequirements() CaptureRequirements {
	return CaptureRequirements{
		UserlandTools:     []string{"ip", "iptables", "ipset"},
		IptablesTargets:   []string{"REDIRECT", "TPROXY", "MARK", "CONNMARK"},
		IptablesMatches:   []string{"socket", "set", "addrtype", "conntrack"},
		NeedIPSet:         true,
		NeedPolicyRouting: true,
	}
}

// Argv is one exec.Command invocation: name plus args, never a shell line.
type Argv struct {
	Name string
	Args []string
}

// CapturePlan is the deterministic install/uninstall argv sequence.
type CapturePlan struct {
	Install   []Argv
	Uninstall []Argv
}

// CollisionKind is a preflight conflict that must FAIL rather than auto-pick
// another mark, table, or port.
type CollisionKind string

const (
	CollisionMark  CollisionKind = "mark"
	CollisionTable CollisionKind = "table"
	CollisionPort  CollisionKind = "port"
	CollisionChain CollisionKind = "chain"
	CollisionXKeen CollisionKind = "xkeen"
)

// Collision is one preflight finding.
type Collision struct {
	Kind   CollisionKind
	Detail string
}

// PreflightReport is a read-only capability/collision check.
// Plan/DryRun/Preflight must still succeed as calls when XKeen is present;
// Apply is what returns ErrExistingCaptureEngine.
type PreflightReport struct {
	OK          bool
	Collisions  []Collision
	XKeenActive bool
	IPv6Capture string
}

// TrafficCaptureEngine is the production capture abstraction (ADR-009).
type TrafficCaptureEngine interface {
	Plan() (CapturePlan, error)
	DryRun() (CapturePlan, error)
	Preflight(ctx context.Context) (PreflightReport, error)
	Apply(ctx context.Context) error
	Remove(ctx context.Context) error
	Reconcile(ctx context.Context, desired bool) error
	FailOpen(ctx context.Context) error
}

// Executor runs a fixed argv. Implementations must not invoke a shell.
type Executor interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

// KeeneticPolicyGuard is a stub for future NDM policy checks.
// NDM internals are not implemented in this wave. First smoke assumes a
// normal allowed test client.
type KeeneticPolicyGuard interface {
	Allow(client netip.Addr) error
}

// PermitAllGuard allows any client (stub until NDM policy exists).
type PermitAllGuard struct{}

func (PermitAllGuard) Allow(netip.Addr) error { return nil }
