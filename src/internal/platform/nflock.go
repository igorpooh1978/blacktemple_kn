package platform

import (
	"errors"
	"path/filepath"
	"sync"
	"time"
)

// NetfilterReconcileTimeout bounds iptables/ip probes so a wedged xtables
// lock cannot hang the manager or NDM hook forever.
const NetfilterReconcileTimeout = 30 * time.Second

// ReasonLockFailed is emitted when netfilter-reconcile cannot take the lock.
const ReasonLockFailed = "lock-failed"

// ErrNetfilterLock is returned when exclusive reconcile serialization fails.
var ErrNetfilterLock = errors.New("platform: netfilter reconcile lock")

var nfPathMutexes sync.Map

func pathMutex(path string) *sync.Mutex {
	v, _ := nfPathMutexes.LoadOrStore(filepath.Clean(path), &sync.Mutex{})
	return v.(*sync.Mutex)
}

func netfilterLockPath(prefix string) string {
	if prefix == "" {
		prefix = PrefixDir
	}
	return filepath.Join(prefix, "run", "netfilter-reconcile.lock")
}
