package supervisor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrNilRunner                    = errors.New("supervisor: nil ProcessRunner")
	ErrAlreadyRunning               = errors.New("supervisor: already running")
	ErrNotRunning                   = errors.New("supervisor: not running")
	ErrManagerRestartNotImplemented = errors.New("supervisor: manager restart helper is owned by cmd")
	ErrFullRestartIncomplete        = errors.New("supervisor: full restart requires manager helper")
)

// Supervisor is the Xray child state machine.
type Supervisor struct {
	mu sync.Mutex

	runner      ProcessRunner
	store       RuntimeStore
	ident       IdentityChecker
	policy      RestartPolicy
	managerHook func(context.Context) error

	now   func() time.Time
	after func(time.Duration) <-chan time.Time

	state         State
	stopRequested bool
	gen           uint64
	crashes       []time.Time
	backoffCancel context.CancelFunc
	watchDone     chan struct{}
	snap          Snapshot
}

// Option configures Supervisor.
type Option func(*Supervisor)

func WithStore(store RuntimeStore) Option {
	return func(s *Supervisor) {
		if store != nil {
			s.store = store
		}
	}
}

func WithIdentity(c IdentityChecker) Option {
	return func(s *Supervisor) {
		if c != nil {
			s.ident = c
		}
	}
}

func WithPolicy(p RestartPolicy) Option {
	return func(s *Supervisor) { s.policy = p }
}

func WithNow(now func() time.Time) Option {
	return func(s *Supervisor) {
		if now != nil {
			s.now = now
		}
	}
}

func WithAfter(after func(time.Duration) <-chan time.Time) Option {
	return func(s *Supervisor) {
		if after != nil {
			s.after = after
		}
	}
}

func WithManagerRestart(hook func(context.Context) error) Option {
	return func(s *Supervisor) { s.managerHook = hook }
}

// New creates a supervisor in STOPPED. runner must be non-nil.
func New(runner ProcessRunner, opts ...Option) *Supervisor {
	if runner == nil {
		panic(ErrNilRunner)
	}
	s := &Supervisor{
		runner: runner,
		store:  NewMemoryStore(),
		ident:  rejectIdentity{},
		policy: DefaultRestartPolicy(),
		now:    time.Now,
		after:  time.After,
		state:  StateStopped,
		snap:   Snapshot{State: StateStopped},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Supervisor) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Supervisor) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap.clone()
}

func (s *Supervisor) RestartCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap.RestartCount
}

// Start launches the child. No-op error if already running.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	switch s.state {
	case StateRunning, StateStarting, StateReloading:
		s.mu.Unlock()
		return ErrAlreadyRunning
	case StateBackoff:
		s.cancelBackoffLocked()
	}
	s.stopRequested = false
	s.transitionLocked(StateStarting)
	s.persistLocked()
	s.mu.Unlock()

	if err := s.runner.Start(ctx); err != nil {
		s.mu.Lock()
		s.snap.LastError = err.Error()
		s.transitionLocked(StateFailed)
		s.persistLocked()
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	if s.stopRequested {
		s.mu.Unlock()
		_ = s.runner.Stop(ctx)
		s.mu.Lock()
		s.transitionLocked(StateStopped)
		s.persistLocked()
		s.mu.Unlock()
		return nil
	}
	s.applyIdentityLocked()
	s.snap.LastError = ""
	s.transitionLocked(StateRunning)
	s.persistLocked()
	s.spawnWatchLocked()
	s.mu.Unlock()
	return nil
}

// Stop requests a manual stop. The child is not auto-restarted.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.state == StateStopped {
		s.mu.Unlock()
		return nil
	}
	s.stopRequested = true
	s.gen++
	s.cancelBackoffLocked()
	done := s.watchDone
	st := s.state
	s.mu.Unlock()

	var err error
	if st == StateRunning || st == StateStarting || st == StateReloading {
		err = s.runner.Stop(ctx)
		if done != nil {
			select {
			case <-done:
			case <-ctx.Done():
			}
		}
	}

	s.mu.Lock()
	s.transitionLocked(StateStopped)
	s.snap.PID = nil
	s.snap.StartedAt = nil
	s.persistLocked()
	s.mu.Unlock()
	return err
}

// Reload bounces the child while advertising RELOADING. Crashes during
// the stop/start sequence are not counted as auto-restarts.
func (s *Supervisor) Reload(ctx context.Context) error {
	s.mu.Lock()
	if s.state != StateRunning {
		s.mu.Unlock()
		return ErrNotRunning
	}
	s.transitionLocked(StateReloading)
	s.persistLocked()
	done := s.watchDone
	s.mu.Unlock()

	if err := s.runner.Stop(ctx); err != nil {
		s.mu.Lock()
		s.snap.LastError = err.Error()
		s.transitionLocked(StateFailed)
		s.persistLocked()
		s.mu.Unlock()
		return err
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			s.mu.Lock()
			s.transitionLocked(StateFailed)
			s.persistLocked()
			s.mu.Unlock()
			return ctx.Err()
		}
	}
	if err := s.runner.Start(ctx); err != nil {
		s.mu.Lock()
		s.snap.LastError = err.Error()
		s.transitionLocked(StateFailed)
		s.persistLocked()
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	if s.stopRequested {
		s.mu.Unlock()
		_ = s.runner.Stop(ctx)
		s.mu.Lock()
		s.transitionLocked(StateStopped)
		s.persistLocked()
		s.mu.Unlock()
		return nil
	}
	s.applyIdentityLocked()
	s.snap.LastError = ""
	s.transitionLocked(StateRunning)
	s.persistLocked()
	s.spawnWatchLocked()
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) spawnWatchLocked() {
	s.gen++
	gen := s.gen
	done := make(chan struct{})
	s.watchDone = done
	go func() {
		defer close(done)
		err := s.runner.Wait()
		s.onChildExit(gen, err)
	}()
}

func (s *Supervisor) onChildExit(gen uint64, waitErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	code := 0
	if waitErr != nil {
		code = 1
		s.snap.LastError = waitErr.Error()
	} else {
		s.snap.LastError = ""
	}
	s.snap.LastExit = &code
	s.snap.PID = nil

	if s.stopRequested {
		s.transitionLocked(StateStopped)
		s.persistLocked()
		return
	}
	if s.state == StateReloading {
		s.persistLocked()
		return
	}

	now := s.now()
	s.crashes = append(s.crashes, now)
	s.trimCrashesLocked(now)
	s.snap.RestartCount++

	if s.policy.MaxRestarts >= 0 && len(s.crashes) > s.policy.MaxRestarts {
		s.transitionLocked(StateFailed)
		s.persistLocked()
		return
	}

	delay := s.policy.Backoff(len(s.crashes) - 1)
	s.transitionLocked(StateBackoff)
	s.persistLocked()
	ctx, cancel := context.WithCancel(context.Background())
	s.backoffCancel = cancel
	go s.runBackoff(gen, ctx, delay)
}

func (s *Supervisor) runBackoff(gen uint64, ctx context.Context, delay time.Duration) {
	select {
	case <-ctx.Done():
		return
	case <-s.after(delay):
	}

	s.mu.Lock()
	if gen != s.gen || s.stopRequested || s.state != StateBackoff {
		s.mu.Unlock()
		return
	}
	s.transitionLocked(StateStarting)
	s.persistLocked()
	s.mu.Unlock()

	if err := s.runner.Start(context.Background()); err != nil {
		s.mu.Lock()
		s.snap.LastError = err.Error()
		s.transitionLocked(StateFailed)
		s.persistLocked()
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	if s.stopRequested || s.gen != gen {
		s.mu.Unlock()
		_ = s.runner.Stop(context.Background())
		return
	}
	s.applyIdentityLocked()
	s.snap.LastError = ""
	s.transitionLocked(StateRunning)
	s.persistLocked()
	s.spawnWatchLocked()
	s.mu.Unlock()
}

func (s *Supervisor) trimCrashesLocked(now time.Time) {
	w := s.policy.Window
	if w <= 0 {
		return
	}
	n := 0
	for _, t := range s.crashes {
		if now.Sub(t) <= w {
			s.crashes[n] = t
			n++
		}
	}
	s.crashes = s.crashes[:n]
}

func (s *Supervisor) cancelBackoffLocked() {
	if s.backoffCancel != nil {
		s.backoffCancel()
		s.backoffCancel = nil
	}
}

func (s *Supervisor) applyIdentityLocked() {
	id, ok := s.runner.(HasIdentity)
	if !ok {
		return
	}
	info := id.Identity()
	if info.PID > 0 {
		pid := info.PID
		s.snap.PID = &pid
	}
	s.snap.Executable = info.Executable
	s.snap.Version = info.Version
}

func (s *Supervisor) transitionLocked(to State) {
	from := s.state
	if from != to && !CanTransition(from, to) {
		s.snap.LastError = "invalid transition " + string(from) + " -> " + string(to)
	}
	s.state = to
	s.snap.State = to
	switch to {
	case StateRunning:
		ts := s.now()
		s.snap.StartedAt = &ts
	case StateStopped, StateFailed:
		s.snap.PID = nil
		s.snap.StartedAt = nil
	}
}

func (s *Supervisor) persistLocked() {
	if s.store == nil {
		return
	}
	_ = s.store.Save(s.snap.clone())
}

func sameExecutable(a, b string) bool {
	return strings.EqualFold(filepathBase(a), filepathBase(b)) || strings.EqualFold(a, b)
}

func filepathBase(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
