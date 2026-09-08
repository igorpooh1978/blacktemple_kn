package supervisor

import "context"

// ProcessRunner is the consumer-side seam for the Xray child.
// Package C should implement the same method set; do not import internal/xray here.
type ProcessRunner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Wait() error
}

// ProcessAdopter is optional. Used on Recover when a live child can be reattached.
type ProcessAdopter interface {
	Adopt(ctx context.Context, pid int) error
}

// Identity is executable/process metadata used for persist + reconcile.
type Identity struct {
	PID        int
	Executable string
	Version    string
}

// HasIdentity is optional on a ProcessRunner.
type HasIdentity interface {
	Identity() Identity
}

// IdentityChecker answers pid liveness and executable identity.
// Never treat a pid file as sufficient evidence that our child is running.
type IdentityChecker interface {
	Alive(pid int) bool
	// Executable returns ok=false when identity cannot be determined
	// (typical on Windows without a fake checker).
	Executable(pid int) (path string, ok bool)
}

type rejectIdentity struct{}

func (rejectIdentity) Alive(int) bool { return false }

func (rejectIdentity) Executable(int) (string, bool) { return "", false }
