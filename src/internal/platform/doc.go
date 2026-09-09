package platform

// Package platform holds Entware/Keenetic adapters. No systemd.
// Detached manager restart is documented here; src/cmd owns the helper binary entrypoint.
//
// NDM hook source: packaging/keenetic/netfilter.d/blacktemple-kn.sh
// Installed: /opt/etc/ndm/netfilter.d/blacktemple-kn.sh
// CLI argv for stream A: blacktempled netfilter-reconcile [stop]
//
// FAIL OPEN: capture.enabled defaults to false. Reconcile returns
// DecisionDesiredAbsent with reason capture-disabled unless the persisted
// JSON boolean is true. After that, DesiredAbsent also when the manager is
// missing, xray is missing/dead, runtime state is invalid, config is corrupt,
// or the network is not ready. DesiredAbsent means capture MUST BE ABSENT: the
// integrator must call D.Remove(). Manager-missing does not by itself delete
// stale BTKN rules (the binary is gone). D owns BTKN_ Remove(); F does not
// call iptables. Router self-generated traffic stays DIRECT: CaptureOUTPUT is
// always false. Environment variables cannot enable capture.
