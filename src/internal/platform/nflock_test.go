package platform

import (
	"strings"
	"testing"
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
