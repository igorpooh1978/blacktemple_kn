package routing

import (
	"context"
	"fmt"
	"net/netip"
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
// a reserved empty chain and is not attached.
//
// IPv6 capture is UNVERIFIED and is not enabled.
type HybridIptablesEngine struct {
	mu      sync.Mutex
	client  netip.Addr
	exec    Executor
	guard   KeeneticPolicyGuard
	applied bool
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
	}, nil
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

// Apply installs BTKN hooks. Empty client, collisions, and an active XKeen
// capture fail. Idempotent if this instance already applied. Partial failure
// rolls back via Remove.
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

	report, err := e.Preflight(ctx)
	if err != nil {
		return err
	}
	if report.XKeenActive {
		return ErrExistingCaptureEngine
	}
	if !report.OK {
		return fmt.Errorf("%w", ErrCaptureCollision)
	}

	for _, c := range e.installCommands() {
		if _, err := e.exec.Run(ctx, c.Name, c.Args...); err != nil {
			_ = e.Remove(ctx)
			return err
		}
	}

	e.mu.Lock()
	e.applied = true
	e.mu.Unlock()
	return nil
}

// Remove uninstalls BTKN hooks so selected clients return DIRECT.
// Missing objects are ignored; calling twice is safe.
func (e *HybridIptablesEngine) Remove(ctx context.Context) error {
	for _, c := range e.removeCommands() {
		_, _ = e.exec.Run(ctx, c.Name, c.Args...)
	}
	e.mu.Lock()
	e.applied = false
	e.mu.Unlock()
	return nil
}

// FailOpen uninstalls BTKN hooks so the selected client returns DIRECT.
// Call this when Xray would crash or BACKOFF. This package must not import
// supervisor or src/internal/xray; those layers invoke this method.
func (e *HybridIptablesEngine) FailOpen(ctx context.Context) error {
	return e.Remove(ctx)
}
