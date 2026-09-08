package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCanTransition(t *testing.T) {
	cases := []struct {
		from, to State
		ok       bool
	}{
		{StateStopped, StateStarting, true},
		{StateStopped, StateRunning, false},
		{StateStopped, StateFailed, false},
		{StateStarting, StateRunning, true},
		{StateStarting, StateFailed, true},
		{StateStarting, StateStopped, true},
		{StateStarting, StateBackoff, false},
		{StateRunning, StateStopped, true},
		{StateRunning, StateReloading, true},
		{StateRunning, StateBackoff, true},
		{StateRunning, StateFailed, true},
		{StateRunning, StateStarting, false},
		{StateReloading, StateRunning, true},
		{StateReloading, StateFailed, true},
		{StateReloading, StateStopped, true},
		{StateBackoff, StateStarting, true},
		{StateBackoff, StateStopped, true},
		{StateBackoff, StateFailed, true},
		{StateBackoff, StateRunning, false},
		{StateFailed, StateStarting, true},
		{StateFailed, StateStopped, true},
		{StateFailed, StateRunning, false},
		{StateStopped, StateStopped, true},
	}
	for _, tc := range cases {
		if got := CanTransition(tc.from, tc.to); got != tc.ok {
			t.Fatalf("%s -> %s: got %v want %v", tc.from, tc.to, got, tc.ok)
		}
	}
	for _, st := range []State{StateStopped, StateStarting, StateRunning, StateReloading, StateFailed, StateBackoff} {
		if !st.Valid() {
			t.Fatalf("%s should be valid", st)
		}
	}
	if State("nope").Valid() {
		t.Fatal("invalid state marked valid")
	}
}

func TestBackoffExponential(t *testing.T) {
	p := RestartPolicy{InitialBackoff: time.Second, MaxBackoff: 8 * time.Second, Multiplier: 2}
	if p.Backoff(0) != time.Second {
		t.Fatalf("got %s", p.Backoff(0))
	}
	if p.Backoff(1) != 2*time.Second {
		t.Fatalf("got %s", p.Backoff(1))
	}
	if p.Backoff(3) != 8*time.Second {
		t.Fatalf("got %s", p.Backoff(3))
	}
	if p.Backoff(20) != 8*time.Second {
		t.Fatalf("got %s", p.Backoff(20))
	}
}

func fastPolicy() RestartPolicy {
	return RestartPolicy{
		MaxRestarts:    5,
		Window:         time.Second,
		InitialBackoff: 20 * time.Millisecond,
		MaxBackoff:     40 * time.Millisecond,
		Multiplier:     2,
	}
}

func waitState(t *testing.T, s *Supervisor, want State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.State() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s, have %s (err=%q)", want, s.State(), s.Snapshot().LastError)
}

func crashAndObserve(t *testing.T, s *Supervisor, r *FakeRunner, crash error) {
	t.Helper()
	before := s.RestartCount()
	r.Crash(crash)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if s.RestartCount() > before || s.State() == StateFailed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("crash not observed, state=%s count=%d", s.State(), s.RestartCount())
}

func TestManualStopDoesNotAutoRestart(t *testing.T) {
	r := NewFakeRunner()
	s := New(r, WithPolicy(fastPolicy()))
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateRunning {
		t.Fatalf("state %s", s.State())
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateStopped {
		t.Fatalf("state %s", s.State())
	}
	starts := r.Starts()
	r.Crash(errors.New("late crash"))
	time.Sleep(80 * time.Millisecond)
	if r.Starts() != starts {
		t.Fatalf("auto-restart after explicit Stop: starts %d -> %d", starts, r.Starts())
	}
	if s.State() != StateStopped {
		t.Fatalf("state after wait %s", s.State())
	}
}

func TestCrashAutoRestart(t *testing.T) {
	r := NewFakeRunner()
	s := New(r, WithPolicy(fastPolicy()))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	crashAndObserve(t, s, r, errors.New("exit 1"))
	waitState(t, s, StateRunning, 500*time.Millisecond)
	if r.Starts() < 2 {
		t.Fatalf("want auto-restart, starts=%d", r.Starts())
	}
	if s.RestartCount() < 1 {
		t.Fatalf("restartCount=%d", s.RestartCount())
	}
}

func TestBackoffState(t *testing.T) {
	r := NewFakeRunner()
	fire := make(chan time.Time)
	s := New(r, WithPolicy(fastPolicy()), WithAfter(func(time.Duration) <-chan time.Time {
		return fire
	}))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Crash(errors.New("boom"))
	waitState(t, s, StateBackoff, 200*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if s.State() != StateBackoff {
		t.Fatalf("left BACKOFF too early: %s", s.State())
	}
	fire <- time.Now()
	waitState(t, s, StateRunning, 500*time.Millisecond)
}

func TestRestartLimitGoesFailed(t *testing.T) {
	r := NewFakeRunner()
	p := RestartPolicy{
		MaxRestarts:    2,
		Window:         time.Second,
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		Multiplier:     2,
	}
	s := New(r, WithPolicy(p))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if s.State() == StateFailed {
			break
		}
		waitState(t, s, StateRunning, 400*time.Millisecond)
		crashAndObserve(t, s, r, errors.New("loop crash"))
	}
	waitState(t, s, StateFailed, 400*time.Millisecond)
	starts := r.Starts()
	time.Sleep(50 * time.Millisecond)
	if r.Starts() != starts {
		t.Fatalf("restart storm after FAILED: %d -> %d", starts, r.Starts())
	}
	if s.State() != StateFailed {
		t.Fatalf("state %s", s.State())
	}
}

func TestRestartVPNStopStart(t *testing.T) {
	r := NewFakeRunner()
	s := New(r, WithPolicy(fastPolicy()))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.RestartVPN(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateRunning {
		t.Fatalf("state %s", s.State())
	}
	if r.Starts() < 2 {
		t.Fatalf("starts=%d", r.Starts())
	}
	if r.Stops() < 1 {
		t.Fatalf("stops=%d", r.Stops())
	}
}

func TestRestartManagerNotImplemented(t *testing.T) {
	s := New(NewFakeRunner())
	err := s.RestartManager(context.Background())
	if !errors.Is(err, ErrManagerRestartNotImplemented) {
		t.Fatalf("got %v", err)
	}
	err = s.RestartFull(context.Background())
	if !errors.Is(err, ErrFullRestartIncomplete) {
		t.Fatalf("got %v", err)
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := &FileStore{Path: dir + "/xray-state.json"}
	pid := 7
	in := Snapshot{State: StateRunning, PID: &pid, Executable: "xray", RestartCount: 3}
	if err := st.Save(in); err != nil {
		t.Fatal(err)
	}
	out, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if out.State != StateRunning || out.RestartCount != 3 || out.PID == nil || *out.PID != 7 {
		t.Fatalf("%+v", out)
	}
}
