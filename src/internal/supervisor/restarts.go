package supervisor

import (
	"context"
	"errors"
)

// RestartVPN restarts only the child process (Stop + Start of ProcessRunner).
// This is not a manager (blacktempled) restart.
func (s *Supervisor) RestartVPN(ctx context.Context) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}
	return s.Start(ctx)
}

// RestartManager is the ADR-004 "restart manager" hook.
// The detached CLI (`blacktempled restart-helper`) is owned by src/cmd (stream A).
// Callers may inject WithManagerRestart; otherwise this returns not-implemented.
func (s *Supervisor) RestartManager(ctx context.Context) error {
	s.mu.Lock()
	hook := s.managerHook
	s.mu.Unlock()
	if hook == nil {
		return ErrManagerRestartNotImplemented
	}
	return hook(ctx)
}

// RestartFull is a placeholder for manager + child (ADR-004 full restart).
func (s *Supervisor) RestartFull(ctx context.Context) error {
	vpnErr := s.RestartVPN(ctx)
	mgrErr := s.RestartManager(ctx)
	if vpnErr != nil {
		return vpnErr
	}
	if mgrErr != nil {
		if errors.Is(mgrErr, ErrManagerRestartNotImplemented) {
			return ErrFullRestartIncomplete
		}
		return mgrErr
	}
	return nil
}
