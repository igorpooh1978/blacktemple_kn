package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetfilterLockPathUsesRunDir(t *testing.T) {
	p := netfilterLockPath(PrefixDir)
	if !strings.HasSuffix(strings.ReplaceAll(p, `\`, `/`), "/run/netfilter-reconcile.lock") {
		t.Fatalf("lock path %q must be run/netfilter-reconcile.lock", p)
	}
	if strings.Contains(p, "/data/netfilter.lock") {
		t.Fatal("WIP data/netfilter.lock is not accepted")
	}
}

func TestLockAcquireSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "netfilter-reconcile.lock")
	unlock, err := acquireNFLock(context.Background(), path)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if unlock == nil {
		t.Fatal("success must return unlock")
	}
	unlock()
}

func TestLockCreationFailureReturnsError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "run")
	if err := os.WriteFile(blocker, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "netfilter-reconcile.lock")
	unlock, err := acquireNFLock(context.Background(), path)
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("mkdir/open failure must return an error, not fail-open")
	}
	if !errors.Is(err, ErrNetfilterLock) {
		t.Fatalf("want ErrNetfilterLock, got %v", err)
	}
}

func TestLockEmptyPathReturnsError(t *testing.T) {
	unlock, err := acquireNFLock(context.Background(), "")
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("empty lock path must not fail-open")
	}
}

func TestLockTimeoutSecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "netfilter-reconcile.lock")
	hold, err := acquireNFLock(context.Background(), path)
	if err != nil {
		t.Fatalf("first holder: %v", err)
	}
	defer hold()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	unlock, err := acquireNFLock(ctx, path)
	if err == nil {
		if unlock != nil {
			unlock()
		}
		t.Fatal("second holder must fail bounded, not share the lock")
	}
	if !errors.Is(err, ErrNetfilterLock) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want lock/timeout error, got %v", err)
	}
}
