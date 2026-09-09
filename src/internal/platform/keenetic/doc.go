package keenetic

// Keenetic adapters for KN-1011. No systemd. No invented NDM RPC structs.
//
// Detect/Prepare/Verify: bare bootstrap. Prepare may load allowlisted existing
// .ko under known module roots. Prepare does not apply BTKN capture, does not
// opkg install, does not sysctl, and never unloads modules.
// POLICY PRESERVATION: DESIGN INVARIANT / NOT VERIFIED.
//
// NDM netfilter.d is evidenced (XKeen proxy.sh lives there). Our hook is
// packaging/keenetic/netfilter.d/blacktemple-kn.sh →
// /opt/etc/ndm/netfilter.d/blacktemple-kn.sh. Do not name or generate proxy.sh.
