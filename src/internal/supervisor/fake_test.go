package supervisor

import (
	"context"
	"errors"
	"sync"
)

var (
	_ ProcessRunner  = (*FakeRunner)(nil)
	_ ProcessAdopter = (*FakeRunner)(nil)
	_ HasIdentity    = (*FakeRunner)(nil)

	errFakeWait = errors.New("fake runner: wait without start")
)

// FakeRunner is a ProcessRunner for tests (including Windows, where OS identity is unreliable).
type FakeRunner struct {
	mu         sync.Mutex
	startErr   error
	stopErr    error
	pid        int
	exe        string
	version    string
	starts     int
	stops      int
	adopts     int
	running    bool
	waitCh     chan struct{}
	waitErr    error
	waitClosed bool
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{
		pid:     4242,
		exe:     "/opt/blacktemple-kn/bin/xray",
		version: "test",
	}
}

func (f *FakeRunner) SetStartError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startErr = err
}

func (f *FakeRunner) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.starts++
	f.running = true
	f.waitCh = make(chan struct{})
	f.waitErr = nil
	f.waitClosed = false
	if f.pid <= 0 {
		f.pid = 4242
	}
	return nil
}

func (f *FakeRunner) Stop(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	if f.stopErr != nil {
		return f.stopErr
	}
	f.signalLocked(nil)
	f.running = false
	return nil
}

func (f *FakeRunner) Wait() error {
	f.mu.Lock()
	ch := f.waitCh
	f.mu.Unlock()
	if ch == nil {
		return errFakeWait
	}
	<-ch
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.waitErr
}

func (f *FakeRunner) Crash(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		err = errors.New("crash")
	}
	f.signalLocked(err)
	f.running = false
}

func (f *FakeRunner) signalLocked(err error) {
	if f.waitCh != nil && !f.waitClosed {
		f.waitErr = err
		close(f.waitCh)
		f.waitClosed = true
	}
}

func (f *FakeRunner) Adopt(ctx context.Context, pid int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adopts++
	f.pid = pid
	f.running = true
	f.waitCh = make(chan struct{})
	f.waitErr = nil
	f.waitClosed = false
	return nil
}

func (f *FakeRunner) Identity() Identity {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Identity{PID: f.pid, Executable: f.exe, Version: f.version}
}

func (f *FakeRunner) Starts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

func (f *FakeRunner) Stops() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stops
}

func (f *FakeRunner) Adopts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adopts
}

func (f *FakeRunner) Running() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

type fakeIdent struct {
	mu    sync.Mutex
	alive map[int]bool
	exe   map[int]string
}

func newFakeIdent() *fakeIdent {
	return &fakeIdent{
		alive: map[int]bool{},
		exe:   map[int]string{},
	}
}

func (f *fakeIdent) Alive(pid int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive[pid]
}

func (f *fakeIdent) Executable(pid int) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.exe[pid]
	return p, ok
}

func (f *fakeIdent) set(pid int, alive bool, exe string, known bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alive[pid] = alive
	if known {
		f.exe[pid] = exe
	} else {
		delete(f.exe, pid)
	}
}
