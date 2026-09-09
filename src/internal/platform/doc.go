package platform

// Package platform holds Entware/Keenetic adapters. No systemd.
// Detached manager restart is documented here; src/cmd owns the helper binary entrypoint.
//
// NDM hook source: packaging/keenetic/netfilter.d/blacktemple-kn.sh
// Installed: /opt/etc/ndm/netfilter.d/blacktemple-kn.sh
// CLI argv for stream A: blacktempled netfilter-reconcile [stop]
//
// FAIL OPEN: Reconcile no-ops (DecisionNoCapture) when the manager is missing,
// xray is missing/dead, runtime state is invalid, config is corrupt, or the
// network is not ready. D owns BTKN_ Remove(); F does not call iptables.
// Router self-generated traffic stays DIRECT: CaptureOUTPUT is always false.
