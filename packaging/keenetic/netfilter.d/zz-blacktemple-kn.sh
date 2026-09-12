#!/bin/sh
# Keenetic NDM netfilter.d late hook for blacktemple-kn.
# Installed path: /opt/etc/ndm/netfilter.d/zz-blacktemple-kn.sh
#
# Filename sorts after XKeen (zz- prefix) so BTKN mangle is re-attached after
# a foreign mangle PREROUTING rewrite. Same manager, no firewall policy.
# FAIL-OPEN: if the manager is missing, exit 0 and do not install capture.
# Production daemon never stops XKeen.
# This hook does not enable capture.enabled and contains no firewall policy.
#
BIN=/opt/blacktemple-kn/bin/blacktempled
[ -x "$BIN" ] || exit 0
BTKN_NDM_HOOK=1
export BTKN_NDM_HOOK
if [ -x /opt/libexec/ip-full ]; then
	BTKN_IPROUTE2=/opt/libexec/ip-full
	export BTKN_IPROUTE2
fi
exec "$BIN" netfilter-reconcile
