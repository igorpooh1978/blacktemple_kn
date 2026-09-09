//go:build unix

package platform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func getenv(key string) string { return os.Getenv(key) }

func acquireNFLock(ctx context.Context, path string) (func(), error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrNetfilterLock)
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
		return nil, fmt.Errorf("%w: mkdir: %v", ErrNetfilterLock, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrNetfilterLock, err)
	}
	mu := pathMutex(path)
	for {
		if mu.TryLock() {
			err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				return func() {
					_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
					mu.Unlock()
					_ = f.Close()
				}, nil
			}
			mu.Unlock()
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("%w: %w", ErrNetfilterLock, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
