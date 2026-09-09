//go:build unix

package platform

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func getenv(key string) string { return os.Getenv(key) }

// acquireNFLock takes an exclusive flock with a bounded wait (context
// deadline or NetfilterReconcileTimeout). It is released on unlock or
// process exit. Failure to create the lock file is fail-open so unit tests
// without /opt still run.
func acquireNFLock(ctx context.Context, path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, NetfilterReconcileTimeout)
		defer cancel()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, nil
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return func() {}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
