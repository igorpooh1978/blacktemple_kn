#!/bin/sh
# Gated KN-1011 IPv4 hybrid routing smoke (mutating). Not the production daemon.
# Production blacktempled never stops XKeen. Only this harness may, and only when
# both BTKN_ALLOW_ROUTING_MUTATION=1 and BTKN_ALLOW_XKEEN_STOP=1 are set.
#
# Without both gates: print LIVE ROUTING SMOKE: NOT RUN and exit 0.
# Does not change IPv6. Does not flush foreign iptables tables. BTKN_ cleanup only.
# Does not claim TPROXY SUPPORTED or all-traffic-through-VPN.
# Does not use xkeen -dns/-pbr/-pr/-ipv6.

SNAP_FILE="${BTKN_SMOKE_SNAP:-/tmp/btkn-r6-smoke-snapshot.txt}"
BTKN_PORT="${BTKN_SMOKE_PORT:-1182}"
BTKN_MARK="${BTKN_SMOKE_MARK:-0xb101}"
BTKN_TABLE="${BTKN_SMOKE_TABLE:-1011}"
# TEST-NET-1 only — not a default-route VPN divert.
BTKN_TEST_DST="${BTKN_SMOKE_TEST_DST:-192.0.2.0/24}"
XKEEN_INIT="/opt/etc/init.d/S05xkeen"
BT_INIT="/opt/etc/init.d/S99blacktemple-kn"

require_gates() {
	if [ "${BTKN_ALLOW_ROUTING_MUTATION}" != "1" ] || [ "${BTKN_ALLOW_XKEEN_STOP}" != "1" ]; then
		echo "LIVE ROUTING SMOKE: NOT RUN"
		echo "reason: requires BTKN_ALLOW_ROUTING_MUTATION=1 and BTKN_ALLOW_XKEEN_STOP=1"
		exit 0
	fi
}

have() {
	command -v "$1" >/dev/null 2>&1
}

record_xray() {
	_pid=""
	_path="UNKNOWN"
	_ver="UNKNOWN"
	for _d in /proc/[0-9]*; do
		[ -d "$_d" ] || continue
		_name=""
		[ -r "${_d}/comm" ] && _name=$(cat "${_d}/comm" 2>/dev/null)
		case "$_name" in
			xray|Xray)
				_pid=${_d#/proc/}
				if [ -L "${_d}/exe" ]; then
					_path=$(readlink "${_d}/exe" 2>/dev/null) || _path="UNKNOWN"
				fi
				break
				;;
		esac
	done
	if have xray; then
		_ver=$(xray version 2>/dev/null | head -n 1)
	elif [ -x /opt/sbin/xray ]; then
		_ver=$(/opt/sbin/xray version 2>/dev/null | head -n 1)
	fi
	echo "xray_pid=${_pid:-NONE}"
	echo "xray_path=${_path}"
	echo "xray_version=${_ver}"
}

chain_present() {
	_fam=$1
	_table=$2
	_token=$3
	if [ "$_fam" = "ip6" ]; then
		if have ip6tables && ip6tables -t "$_table" -S 2>/dev/null | grep -i -e "$_token" >/dev/null; then
			echo "PRESENT"
			return 0
		fi
	else
		if have iptables && iptables -t "$_table" -S 2>/dev/null | grep -i -e "$_token" >/dev/null; then
			echo "PRESENT"
			return 0
		fi
	fi
	echo "NOT OBSERVED"
}

cmd_snapshot() {
	echo "===== SNAPSHOT ====="
	_running=0
	_init_status="NOT AVAILABLE"
	if [ -x "$XKEEN_INIT" ]; then
		_init_status=$("$XKEEN_INIT" status 2>&1) || true
		echo "$_init_status" | grep -qi -e run -e start && _running=1
	fi
	if [ "$_running" -eq 0 ]; then
		for _d in /proc/[0-9]*; do
			[ -d "$_d" ] || continue
			_cmd=""
			[ -r "${_d}/cmdline" ] && _cmd=$(tr '\0' ' ' < "${_d}/cmdline" 2>/dev/null)
			_exe=""
			[ -L "${_d}/exe" ] && _exe=$(readlink "${_d}/exe" 2>/dev/null)
			case "${_cmd} ${_exe}" in
				*/opt/sbin/xray*|*/opt/etc/xray*) _running=1 ;;
			esac
		done
	fi
	{
		echo "xkeen_init=${XKEEN_INIT}"
		echo "xkeen_was_running=${_running}"
		echo "xkeen_init_status=${_init_status}"
		record_xray
		if have ip; then
			echo "--- ip rule ---"
			ip rule 2>/dev/null || true
			if ip rule 2>/dev/null | grep -q 'fwmark 0x111'; then
				echo "ip_rule_fwmark_111=PRESENT"
			else
				echo "ip_rule_fwmark_111=NOT OBSERVED"
			fi
		else
			echo "ip_rule_fwmark_111=NOT AVAILABLE"
		fi
		echo "xkeen_nat=$(chain_present ip nat xkeen)"
		echo "xkeen_mangle=$(chain_present ip mangle xkeen)"
		echo "xkeen_filter=$(chain_present ip filter xkeen)"
	} | tee "$SNAP_FILE"
	echo "snapshot_file=${SNAP_FILE}"
}

stop_xkeen_temp() {
	echo "===== STOP XKEEN (harness only) ====="
	if [ ! -x "$XKEEN_INIT" ]; then
		echo "NOT AVAILABLE: ${XKEEN_INIT}"
		return 0
	fi
	"$XKEEN_INIT" stop 2>&1 || true
}

cmd_apply() {
	echo "===== APPLY BTKN IPv4 HYBRID (limited TEST-NET) ====="
	echo "scope: ${BTKN_TEST_DST} only; not all traffic through VPN"
	echo "IPv4 hybrid: TCP REDIRECT + UDP TPROXY (orchestrator SELECTED; not TPROXY SUPPORTED)"
	echo "IPv6: unchanged"
	if ! have iptables; then
		echo "NOT AVAILABLE: iptables"
		return 1
	fi
	iptables -t nat -N BTKN_NAT 2>/dev/null || true
	iptables -t mangle -N BTKN_MANGLE 2>/dev/null || true
	iptables -t nat -A BTKN_NAT -p tcp -d "$BTKN_TEST_DST" -m comment --comment BTKN_smoke -j REDIRECT --to-ports "$BTKN_PORT"
	if have iptables; then
		iptables -t mangle -A BTKN_MANGLE -p udp -d "$BTKN_TEST_DST" -m comment --comment BTKN_smoke -j TPROXY --on-port "$BTKN_PORT" --on-ip 127.0.0.1 --tproxy-mark "${BTKN_MARK}/0xffffffff" 2>/dev/null \
			|| echo "TPROXY apply: NOT OBSERVED (not SUPPORTED)"
	fi
	iptables -t nat -C PREROUTING -j BTKN_NAT 2>/dev/null || iptables -t nat -A PREROUTING -j BTKN_NAT
	iptables -t mangle -C PREROUTING -j BTKN_MANGLE 2>/dev/null || iptables -t mangle -A PREROUTING -j BTKN_MANGLE
	if have ip; then
		ip rule add fwmark "$BTKN_MARK" lookup "$BTKN_TABLE" 2>/dev/null || true
		ip route add local default dev lo table "$BTKN_TABLE" 2>/dev/null || true
	fi
	echo "apply: BTKN_ limited hybrid installed (IPv4 TEST-NET only)"
}

delete_jumps_to_btkn() {
	_table=$1
	have iptables || return 0
	iptables -t "$_table" -S 2>/dev/null | awk '
		$1 == "-A" && $2 !~ /^BTKN_/ {
			for (i = 1; i <= NF; i++) {
				if ($i == "-j" && $(i + 1) ~ /^BTKN_/) print
			}
		}
	' | while IFS= read -r _rule; do
		[ -n "$_rule" ] || continue
		_del=$(echo "$_rule" | sed 's/^-A /-D /')
		# shellcheck disable=SC2086
		iptables -t "$_table" $_del 2>/dev/null || true
	done
}

flush_btkn_chains() {
	_table=$1
	have iptables || return 0
	iptables -t "$_table" -S 2>/dev/null | awk '$1 == "-N" && $2 ~ /^BTKN_/ { print $2 }' | while IFS= read -r _ch; do
		[ -n "$_ch" ] || continue
		iptables -t "$_table" -F "$_ch" 2>/dev/null || true
		iptables -t "$_table" -X "$_ch" 2>/dev/null || true
	done
}

cmd_cleanup_btkn() {
	echo "===== CLEANUP BTKN ONLY ====="
	echo "never iptables global flush"
	for _table in nat mangle filter; do
		delete_jumps_to_btkn "$_table"
		flush_btkn_chains "$_table"
	done
	if have ip; then
		ip rule del fwmark "$BTKN_MARK" lookup "$BTKN_TABLE" 2>/dev/null || true
		ip route del local default dev lo table "$BTKN_TABLE" 2>/dev/null || true
	fi
	echo "BTKN cleanup done"
}

cmd_stop_blacktemple() {
	echo "===== STOP TEST BLACKTEMPLE ====="
	if [ -x "$BT_INIT" ]; then
		"$BT_INIT" stop 2>&1 || true
	else
		echo "NOT AVAILABLE: ${BT_INIT}"
	fi
}

cmd_restore_xkeen() {
	echo "===== RESTORE XKEEN ====="
	_was=0
	if [ -f "$SNAP_FILE" ]; then
		_was=$(awk -F= '/^xkeen_was_running=/ { print $2; exit }' "$SNAP_FILE" 2>/dev/null)
	fi
	if [ "${_was}" = "1" ]; then
		if [ -x "$XKEEN_INIT" ]; then
			"$XKEEN_INIT" start 2>&1 || true
		else
			echo "NOT AVAILABLE: ${XKEEN_INIT}"
		fi
	else
		echo "xkeen was not running at snapshot; not started"
	fi
}

cmd_verify() {
	echo "===== VERIFY ====="
	record_xray
	echo "xkeen_nat=$(chain_present ip nat xkeen)"
	echo "xkeen_mangle=$(chain_present ip mangle xkeen)"
	echo "xkeen_filter=$(chain_present ip filter xkeen)"
	_btkn=NOT_OBSERVED
	if have iptables; then
		if iptables -t nat -S 2>/dev/null | grep -q BTKN_ || iptables -t mangle -S 2>/dev/null | grep -q BTKN_; then
			_btkn=PRESENT
		fi
	fi
	echo "btkn_chains=${_btkn}"
	if have ip; then
		ip rule 2>/dev/null | grep -e 0x111 -e "$BTKN_MARK" || echo "no harness/xkeen fwmark in ip rule"
	fi
}

usage() {
	echo "usage: router-smoke-routing.sh {run|snapshot|apply|cleanup-btkn|stop-blacktemple|restore-xkeen|verify}"
}

require_gates

_cmd=${1:-}
if [ -z "$_cmd" ]; then
	echo "LIVE ROUTING SMOKE: NOT RUN"
	echo "reason: explicit subcommand required (snapshot|apply|cleanup-btkn|stop-blacktemple|restore-xkeen|verify|run)"
	exit 0
fi
case "$_cmd" in
	run)
		cmd_snapshot
		trap 'cmd_cleanup_btkn; cmd_stop_blacktemple; cmd_restore_xkeen; cmd_verify; trap - EXIT' EXIT
		stop_xkeen_temp
		cmd_apply
		cmd_verify
		;;
	snapshot) cmd_snapshot ;;
	apply) cmd_apply ;;
	cleanup-btkn) cmd_cleanup_btkn ;;
	stop-blacktemple) cmd_stop_blacktemple ;;
	restore-xkeen) cmd_restore_xkeen ;;
	verify) cmd_verify ;;
	*)
		usage
		exit 1
		;;
esac
exit 0
