package keenetic

// Keenetic adapters for KN-1011. No systemd. No invented NDM RPC structs.
//
// Detect/Prepare/Verify: bare bootstrap. Prepare may modprobe allowlisted
// existing modules. Without modprobe, Prepare fails with
// DEPENDENCY_ORDER_UNVERIFIED rather than guessing insmod order.
// Prepare does not apply BTKN capture, does not opkg install, does not
// sysctl, and never unloads modules.
// POLICY PRESERVATION: DESIGN INVARIANT / NOT VERIFIED.
//
// NDM netfilter.d is evidenced (XKeen proxy.sh lives there). Our hook is
// packaging/keenetic/netfilter.d/blacktemple-kn.sh →
// /opt/etc/ndm/netfilter.d/blacktemple-kn.sh, plus zz-blacktemple-kn.sh after
// XKeen proxy.sh. Do not name or generate proxy.sh.
