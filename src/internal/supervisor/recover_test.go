package supervisor

import (
	"context"
	"testing"
)

func TestRecoverStalePID(t *testing.T) {
	r := NewFakeRunner()
	store := NewMemoryStore()
	ident := newFakeIdent()
	pid := 99999
	if err := store.Save(Snapshot{
		State:      StateRunning,
		PID:        &pid,
		Executable: r.exe,
	}); err != nil {
		t.Fatal(err)
	}
	ident.set(pid, false, r.exe, true)

	s := New(r, WithStore(store), WithIdentity(ident), WithPolicy(fastPolicy()))
	if err := s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateStopped {
		t.Fatalf("state %s", s.State())
	}
	if s.Snapshot().PID != nil {
		t.Fatalf("pid should be cleared, have %v", *s.Snapshot().PID)
	}
	if r.Adopts() != 0 {
		t.Fatalf("must not adopt stale pid, adopts=%d", r.Adopts())
	}
	if r.Starts() != 0 {
		t.Fatalf("must not start on stale recover, starts=%d", r.Starts())
	}
}

func TestRecoverIdentityMismatch(t *testing.T) {
	r := NewFakeRunner()
	store := NewMemoryStore()
	ident := newFakeIdent()
	pid := 100
	if err := store.Save(Snapshot{
		State:      StateRunning,
		PID:        &pid,
		Executable: "/opt/blacktemple-kn/bin/xray",
	}); err != nil {
		t.Fatal(err)
	}
	ident.set(pid, true, "/usr/bin/unrelated", true)

	s := New(r, WithStore(store), WithIdentity(ident), WithPolicy(fastPolicy()))
	if err := s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateStopped {
		t.Fatalf("state %s", s.State())
	}
	if r.Adopts() != 0 {
		t.Fatal("must not adopt mismatched executable")
	}
}

func TestRecoverUnknownIdentityNotTrusted(t *testing.T) {
	r := NewFakeRunner()
	store := NewMemoryStore()
	ident := newFakeIdent()
	pid := 100
	if err := store.Save(Snapshot{
		State:      StateRunning,
		PID:        &pid,
		Executable: "/opt/blacktemple-kn/bin/xray",
	}); err != nil {
		t.Fatal(err)
	}
	ident.set(pid, true, "", false)

	s := New(r, WithStore(store), WithIdentity(ident), WithPolicy(fastPolicy()))
	if err := s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateStopped {
		t.Fatalf("state %s", s.State())
	}
	if r.Adopts() != 0 {
		t.Fatal("must not adopt when identity unknown")
	}
}

func TestRecoverLiveMatchingIdentity(t *testing.T) {
	r := NewFakeRunner()
	store := NewMemoryStore()
	ident := newFakeIdent()
	pid := 4242
	if err := store.Save(Snapshot{
		State:      StateRunning,
		PID:        &pid,
		Executable: r.exe,
	}); err != nil {
		t.Fatal(err)
	}
	ident.set(pid, true, r.exe, true)

	s := New(r, WithStore(store), WithIdentity(ident), WithPolicy(fastPolicy()))
	if err := s.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateRunning {
		t.Fatalf("state %s err=%q", s.State(), s.Snapshot().LastError)
	}
	if r.Adopts() != 1 {
		t.Fatalf("adopts=%d", r.Adopts())
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State() != StateStopped {
		t.Fatalf("state %s", s.State())
	}
}
