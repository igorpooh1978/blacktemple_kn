#!/bin/sh
# Keenetic NDM netfilter.d hook for blacktemple-kn.
# Installed path: /opt/etc/ndm/netfilter.d/blacktemple-kn.sh
#
# Minimal fixed wrapper. No user strings. No env blobs.
# FAIL-OPEN: if the manager is missing, exit 0 and do not install capture.
# This does NOT delete stale BTKN rules. Package uninstall must clean owned
# BTKN before removing the manager binary. CLI netfilter-reconcile is not
# wired in this wave.
# Absence of VPN is better than absence of internet.
#
# Router self-generated traffic stays DIRECT.
# Capture apply/remove is owned by blacktempled netfilter-reconcile
# (stream A wires the argv; stream D owns BTKN_ Remove/Apply).
# When xray is dead the helper no-ops.
#
BIN=/opt/blacktemple-kn/bin/blacktempled
[ -x "$BIN" ] || exit 0
exec "$BIN" netfilter-reconcile
