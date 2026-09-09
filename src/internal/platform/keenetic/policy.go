package keenetic

// PolicyGuard is a stub. The KN-1011 read-only probe evidenced iptables,
// ip rule fwmark 0xffffaaa, and /opt/etc/ndm/netfilter.d — not an NDM RPC
// schema. Do not invent NDM structs here.
//
// POLICY PRESERVATION: DESIGN INVARIANT / NOT VERIFIED
// No NDM policy lookup is implemented. First smoke uses an allowed client.
type PolicyGuard struct{}

// CaptureMayGrantDeniedInternet is always false. A true value would mean
// capture would bypass Keenetic's deny path (observed DenyFwmark / table
// 4096 blackhole). Callers must fail-open instead of installing such rules.
func (PolicyGuard) CaptureMayGrantDeniedInternet() bool {
	return false
}

// DenyFwmark is the Keenetic policy mark observed on KN-1011
// (docs/hardware/kn-1011-capabilities.md). Same token as
// platform.KeeneticDenyFwmark.
const DenyFwmark = "0xffffaaa"

// HonorDeny reports that capture/apply must keep Keenetic deny in force.
func (PolicyGuard) HonorDeny() bool {
	return true
}
