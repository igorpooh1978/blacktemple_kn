#!/bin/sh
# Keenetic NDM netfilter.d hook for blacktemple-kn.
# Installed path: /opt/etc/ndm/netfilter.d/blacktemple-kn.sh
#
# Minimal fixed wrapper. No user strings. No env blobs.
# FAIL-OPEN: if the manager is missing, exit 0 and do not install capture.
# Package uninstall/stop must run blacktempled netfilter-reconcile stop
# before removing the manager binary.
# Absence of VPN is better than absence of internet.
#
# Router self-generated traffic stays DIRECT.
# Capture apply/remove is owned by blacktempled netfilter-reconcile
# (HybridIptablesEngine). This hook contains no firewall policy.
# Production daemon never stops XKeen.
#
BIN=/opt/blacktemple-kn/bin/blacktempled
[ -x "$BIN" ] || exit 0
exec "$BIN" netfilter-reconcile
