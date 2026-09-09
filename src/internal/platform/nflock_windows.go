//go:build windows

package platform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

func getenv(key string) string { return os.Getenv(key) }

const (
	lockfileExclusiveLock   = 2
	lockfileFailImmediately = 1
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

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
	h := syscall.Handle(f.Fd())
	mu := pathMutex(path)
	for {
		if mu.TryLock() {
			if err := lockFileExclusive(h); err == nil {
				return func() {
					_ = unlockFileExclusive(h)
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

func lockFileExclusive(h syscall.Handle) error {
	var ol syscall.Overlapped
	r1, _, err := procLockFileEx.Call(
		uintptr(h),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		if err == nil {
			return syscall.EINVAL
		}
		return err
	}
	return nil
}

func unlockFileExclusive(h syscall.Handle) error {
	var ol syscall.Overlapped
	r1, _, err := procUnlockFileEx.Call(uintptr(h), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r1 == 0 {
		return err
	}
	return nil
}
