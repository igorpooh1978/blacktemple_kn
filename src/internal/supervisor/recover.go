package supervisor

import (
	"context"
	"errors"
)

// Recover reconciles persisted pid/state with live process identity.
// A pid file or snapshot pid is never trusted on its own.
func (s *Supervisor) Recover(ctx context.Context) error {
	if s.store == nil {
		s.mu.Lock()
		s.transitionLocked(StateStopped)
		s.mu.Unlock()
		return nil
	}
	snap, err := s.store.Load()
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.mu.Lock()
			s.state = StateStopped
			s.snap = Snapshot{State: StateStopped}
			s.mu.Unlock()
			return nil
		}
		return err
	}

	s.mu.Lock()
	s.snap = snap.clone()
	if s.snap.State == "" {
		s.snap.State = StateStopped
	}
	s.state = StateStopped
	s.mu.Unlock()

	if snap.PID == nil || *snap.PID <= 0 {
		s.mu.Lock()
		s.snap.PID = nil
		s.snap.StartedAt = nil
		if snap.State == StateFailed {
			s.state = StateFailed
			s.snap.State = StateFailed
		} else {
			s.state = StateStopped
			s.snap.State = StateStopped
		}
		s.persistLocked()
		s.mu.Unlock()
		return nil
	}

	pid := *snap.PID
	if s.ident == nil || !s.ident.Alive(pid) {
		return s.markStale("stale pid: process not running")
	}

	if snap.Executable == "" {
		return s.markStale("stale pid: missing executable identity")
	}
	exe, ok := s.ident.Executable(pid)
	if !ok {
		return s.markStale("stale pid: executable identity unknown")
	}
	if !sameExecutable(exe, snap.Executable) {
		return s.markStale("stale pid: executable identity mismatch")
	}

	adopter, ok := s.runner.(ProcessAdopter)
	if !ok {
		return s.markStale("live pid not adopted: runner does not support Adopt")
	}
	if err := adopter.Adopt(ctx, pid); err != nil {
		s.mu.Lock()
		s.snap.LastError = err.Error()
		s.snap.PID = nil
		s.transitionLocked(StateStopped)
		s.persistLocked()
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopRequested = false
	s.snap.LastError = ""
	s.state = StateStopped
	s.snap.State = StateStopped
	s.transitionLocked(StateStarting)
	s.applyIdentityLocked()
	if s.snap.PID == nil {
		p := pid
		s.snap.PID = &p
	}
	s.transitionLocked(StateRunning)
	s.persistLocked()
	s.spawnWatchLocked()
	return nil
}

func (s *Supervisor) markStale(reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap.PID = nil
	s.snap.StartedAt = nil
	s.snap.LastError = reason
	s.state = StateStopped
	s.snap.State = StateStopped
	s.persistLocked()
	return nil
}
