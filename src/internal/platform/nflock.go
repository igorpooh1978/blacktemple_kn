package platform

import (
	"path/filepath"
	"time"
)

// NetfilterReconcileTimeout bounds iptables/ip probes so a wedged xtables
// lock cannot hang the manager or NDM hook forever.
const NetfilterReconcileTimeout = 30 * time.Second

func netfilterLockPath(prefix string) string {
	if prefix == "" {
		prefix = PrefixDir
	}
	return filepath.Join(prefix, "run", "netfilter-reconcile.lock")
}
