package routing

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

var _ TrafficCaptureEngine = (*HybridIptablesEngine)(nil)

// HybridIptablesEngine is the IPv4 production TrafficCaptureEngine.
//
// KN-1011 evidence (PRESENT, not a SUPPORTED label): TPROXY, REDIRECT, MARK,
// CONNMARK, xt_socket. R6 mirrors the observed TCP REDIRECT / UDP TPROXY split
// using only the BlackTemple namespace (port 11820, mark 0x42544b4e, table 4254,
// BTKN_ chains).
//
// Anti-recapture: R6 is PREROUTING-only. Locally generated Xray outbound is an
// OUTPUT-path flow and is never jumped into BTKN_OUT. BTKN_OUT is created as
// a reserved empty chain and is not attached. Marked TPROXY replies to
// RFC1918 use ip rule pref 4253 lookup main so they are not blackholed by
// table 4254 local default lo.
//
// IPv6 capture is UNVERIFIED and is not enabled.
type HybridIptablesEngine struct {
	mu            sync.Mutex
	client        netip.Addr
	exec          Executor
	guard         KeeneticPolicyGuard
	applied       bool
	expected      ExpectedListener
	ipPath        string
	ipConfigured  string
	policyRouting bool
	addrtype      bool
	capsKnown     bool
}

// NewHybridIptablesEngine builds an IPv4 hybrid engine. exec must be non-nil.
// A nil guard becomes PermitAllGuard. An empty/non-IPv4 client is rejected by
// Plan/DryRun/Apply (never whole-LAN capture).
func NewHybridIptablesEngine(client netip.Addr, exec Executor, guard KeeneticPolicyGuard) (*HybridIptablesEngine, error) {
	if exec == nil {
		return nil, ErrNilExecutor
	}
	if guard == nil {
		guard = PermitAllGuard{}
	}
	return &HybridIptablesEngine{
		client: client,
		exec:   exec,
		guard:  guard,
		expected: ExpectedListener{
			Executable: OurXrayExecutable,
		},
	}, nil
}

// SetExpectedListener records the supervisor-owned Xray identity.
// Port 11820 belonging to this executable is not a capture collision.
func (e *HybridIptablesEngine) SetExpectedListener(l ExpectedListener) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if l.Executable == "" {
		l.Executable = OurXrayExecutable
	}
	e.expected = l
}

// SetRoutingCaps records probed or test-injected routing capabilities.
// Plan/Apply then omit unsupported addrtype and UDP policy-routing argv.
func (e *HybridIptablesEngine) SetRoutingCaps(ipPath string, policyRouting, addrtype bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ipPath = ipPath
	e.policyRouting = policyRouting
	e.addrtype = addrtype
	e.capsKnown = true
}

// SetIPRoute2Configured sets the explicit production path (init env / package).
func (e *HybridIptablesEngine) SetIPRoute2Configured(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ipConfigured = path
}

const capAddrtypeChain = "BTKN_CAP_AT"

// ProbeCapabilities resolves full iproute2 and addrtype without relying on PATH.
func (e *HybridIptablesEngine) ProbeCapabilities(ctx context.Context) {
	e.mu.Lock()
	configured := e.ipConfigured
	exec := e.exec
	e.mu.Unlock()
	path, ok := ResolveIPRoute2(ctx, exec, configured)
	addr := probeAddrtype(ctx, exec)
	e.mu.Lock()
	e.ipPath = path
	e.policyRouting = ok
	e.addrtype = addr
	e.capsKnown = true
	e.mu.Unlock()
}

func probeAddrtype(ctx context.Context, exec Executor) bool {
	if exec == nil {
		return false
	}
	_, _ = exec.Run(ctx, "iptables", "-t", "nat", "-F", capAddrtypeChain)
	_, _ = exec.Run(ctx, "iptables", "-t", "nat", "-X", capAddrtypeChain)
	if _, err := exec.Run(ctx, "iptables", "-t", "nat", "-N", capAddrtypeChain); err != nil {
		_, _ = exec.Run(ctx, "iptables", "-t", "nat", "-F", capAddrtypeChain)
		_, _ = exec.Run(ctx, "iptables", "-t", "nat", "-X", capAddrtypeChain)
		return false
	}
	_, err := exec.Run(ctx, "iptables", "-t", "nat", "-A", capAddrtypeChain, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN")
	_, _ = exec.Run(ctx, "iptables", "-t", "nat", "-F", capAddrtypeChain)
	_, _ = exec.Run(ctx, "iptables", "-t", "nat", "-X", capAddrtypeChain)
	if err != nil {
		return false
	}
	return true
}

func (e *HybridIptablesEngine) validateClient() error {
	if !e.client.IsValid() || !e.client.Is4() || e.client.IsUnspecified() {
		return ErrClientRequired
	}
	return nil
}

// Plan returns the deterministic install/uninstall argv. It does not
// execute anything and works even when XKeen is present on the box.
func (e *HybridIptablesEngine) Plan() (CapturePlan, error) {
	if err := e.validateClient(); err != nil {
		return CapturePlan{}, err
	}
	return CapturePlan{
		Install:   e.installCommands(),
		Uninstall: e.removeCommands(),
	}, nil
}

// DryRun is Plan without execution.
func (e *HybridIptablesEngine) DryRun() (CapturePlan, error) {
	return e.Plan()
}

// Apply installs BTKN hooks. Empty client and BTKN-namespace collisions fail.
// Live XKeen (1181 / mark 0x111 / table 111) is coexistence and does not block.
// Residual XKeen capture returns ErrExistingCaptureEngine. Idempotent if this
// instance already applied. Partial failure rolls back via Remove.
func (e *HybridIptablesEngine) Apply(ctx context.Context) error {
	if err := e.validateClient(); err != nil {
		return err
	}
	if e.guard != nil {
		if err := e.guard.Allow(e.client); err != nil {
			return err
		}
	}

	e.mu.Lock()
	already := e.applied
	e.mu.Unlock()
	if already {
		return nil
	}

	e.mu.Lock()
	known := e.capsKnown
	e.mu.Unlock()
	if !known {
		e.ProbeCapabilities(ctx)
	}

	report, err := e.Preflight(ctx)
	if err != nil {
		return err
	}
	if report.XKeenState == XKeenResidual {
		return ErrExistingCaptureEngine
	}
	if !report.OK {
		return fmt.Errorf("%w", ErrCaptureCollision)
	}

	for _, c := range e.installCommands() {
		out, err := e.exec.Run(ctx, c.Name, c.Args...)
		if err != nil {
			if isExistingObjectFailure(out, err) {
				continue
			}
			if rbErr := e.Remove(ctx); rbErr != nil {
				return errors.Join(err, rbErr)
			}
			return err
		}
	}

	if err := e.ensureMangleJump(ctx); err != nil {
		if rbErr := e.Remove(ctx); rbErr != nil {
			return errors.Join(err, rbErr)
		}
		return err
	}

	e.mu.Lock()
	e.applied = true
	e.mu.Unlock()
	return nil
}

// Remove uninstalls owned BTKN hooks and verifies capture is detached.
// Missing owned objects are OK. Residual capture hooks return ErrCleanupIncomplete.
func (e *HybridIptablesEngine) Remove(ctx context.Context) error {
	var first error
	for _, c := range e.removeCommands() {
		out, err := e.exec.Run(ctx, c.Name, c.Args...)
		if err != nil {
			if isAbsentObjectFailure(out, err) {
				continue
			}
			if first == nil {
				first = err
			} else {
				first = errors.Join(first, err)
			}
		}
	}
	if err := e.verifyRemoved(ctx); err != nil {
		e.mu.Lock()
		e.applied = false
		e.mu.Unlock()
		if first != nil {
			return errors.Join(fmt.Errorf("%w", ErrCleanupIncomplete), first, err)
		}
		return err
	}
	e.mu.Lock()
	e.applied = false
	e.mu.Unlock()
	if first != nil {
		return fmt.Errorf("%w: %v", ErrCleanupIncomplete, first)
	}
	return nil
}

// Reconcile is the manager-restart path: never adopt unknown partial BTKN.
// Always RemoveOwned then Apply fresh if desired. Fail-open DIRECT gap is OK.
func (e *HybridIptablesEngine) Reconcile(ctx context.Context, desired bool) error {
	e.mu.Lock()
	e.applied = false
	e.mu.Unlock()
	if err := e.Remove(ctx); err != nil {
		return err
	}
	if !desired {
		return nil
	}
	return e.Apply(ctx)
}

// FailOpen uninstalls BTKN hooks so the selected client returns DIRECT.
func (e *HybridIptablesEngine) FailOpen(ctx context.Context) error {
	return e.Remove(ctx)
}

func (e *HybridIptablesEngine) ensureMangleJump(ctx context.Context) error {
	if !e.usePolicyRouting() {
		return nil
	}
	mangleS, err := e.exec.Run(ctx, "iptables", "-t", "mangle", "-S")
	if err != nil {
		return err
	}
	if jumpPresent(mangleS, "PREROUTING", ChainPRE) {
		return nil
	}
	_, err = e.exec.Run(ctx, "iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-j", ChainPRE)
	return err
}

func (e *HybridIptablesEngine) verifyRemoved(ctx context.Context) error {
	natS, err := e.exec.Run(ctx, "iptables", "-t", "nat", "-S")
	if err != nil {
		return fmt.Errorf("%w: verify nat -S: %v", ErrCleanupIncomplete, err)
	}
	mangleS, err := e.exec.Run(ctx, "iptables", "-t", "mangle", "-S")
	if err != nil {
		return fmt.Errorf("%w: verify mangle -S: %v", ErrCleanupIncomplete, err)
	}
	ip := e.ipBin()
	rules, err := e.exec.Run(ctx, ip, "-4", "rule", "show")
	if err != nil {
		return fmt.Errorf("%w: verify ip rule: %v", ErrCleanupIncomplete, err)
	}
	tableOut, tableErr := e.exec.Run(ctx, ip, "-4", "route", "show", "table", fmt.Sprintf("%d", RouteTable))
	if jumpPresent(natS, "PREROUTING", ChainPRE) || jumpPresent(mangleS, "PREROUTING", ChainPRE) {
		return fmt.Errorf("%w: PREROUTING still jumps to %s", ErrCleanupIncomplete, ChainPRE)
	}
	if ownedMarkRulePresent(rules) {
		return fmt.Errorf("%w: fwmark 0x42544b4e -> table 4254 still present", ErrCleanupIncomplete)
	}
	if tableStillPresent(tableOut, tableErr) {
		return fmt.Errorf("%w: table 4254 local default still present", ErrCleanupIncomplete)
	}
	return nil
}

func jumpPresent(tableS, chain, jump string) bool {
	for _, line := range strings.Split(tableS, "\n") {
		fields := strings.Fields(line)
		if hasSeq(fields, "-A", chain, "-j", jump) {
			return true
		}
	}
	return false
}

func ownedMarkRulePresent(rules string) bool {
	return strings.Contains(strings.ToLower(rules), "0x42544b4e")
}

func tableStillPresent(out string, err error) bool {
	if isTableAbsent(out, err) {
		return false
	}
	if err != nil {
		return true
	}
	return strings.TrimSpace(out) != ""
}

func isTableAbsent(out string, err error) bool {
	msg := strings.ToLower(strings.TrimSpace(out))
	if err != nil {
		msg = strings.ToLower(err.Error() + " " + msg)
	}
	if isBusyBoxHighTableID(msg) {
		return true
	}
	for _, tok := range []string{
		"does not exist",
		"no such file",
		"fib table does not exist",
		"no such process",
		"can't find table",
		"cannot find device",
	} {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

func isBusyBoxHighTableID(msg string) bool {
	table := strconv.Itoa(RouteTable)
	return strings.Contains(msg, "invalid argument") && strings.Contains(msg, table)
}

// isAbsentObjectFailure reports idempotent absence of an owned object.
// CommandExecutor returns CombinedOutput in output and often only
// "exit status 1" in err, so both must be inspected. A bare exit status
// is never treated as success.
func isAbsentObjectFailure(output string, err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(output + "\n" + err.Error()))
	if isBusyBoxHighTableID(msg) {
		return true
	}
	for _, tok := range []string{
		"bad rule",
		"no chain/target/match",
		"no matching rule",
		"does not exist",
		"set not found",
		"no such file or directory",
		"no such file",
		"fib table does not exist",
		"no such process",
	} {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

// isExistingObjectFailure reports idempotent create of an owned object.
func isExistingObjectFailure(output string, err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(output + "\n" + err.Error()))
	for _, tok := range []string{
		"chain already exists",
		"file exists",
		"rtnetlink answers: file exists",
	} {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

func hasToken(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}

func hasSeq(args []string, seq ...string) bool {
	if len(seq) == 0 || len(args) < len(seq) {
		return false
	}
	for i := 0; i <= len(args)-len(seq); i++ {
		ok := true
		for j := range seq {
			if args[i+j] != seq[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
