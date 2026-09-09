#!/bin/sh
# Gated KN-1011 BlackTemple APP smoke (production path).
# Production constants: 11820 / 0x42544b4e / table 4254 / BTKN_* / btkn_*.
# Does not mutate iptables/ip rule/ip route: blacktempled netfilter-reconcile owns that.
# Production daemon never stops XKeen. This harness may, only with both gates.
# Without both gates: LIVE ROUTING SMOKE: NOT RUN and exit 0.
# Does not claim TPROXY SUPPORTED, KN-1011 SUPPORTED, or routing DONE.

SNAP_FILE="${BTKN_SMOKE_SNAP:-/tmp/btkn-r6i-smoke-snapshot.txt}"
CLIENT_FILE="/opt/blacktemple-kn/data/selected-client"
BIN="/opt/blacktemple-kn/bin/blacktempled"
OUR_XRAY="/opt/blacktemple-kn/bin/xray"
FOREIGN_XRAY="/opt/sbin/xray"
XRAY_JSON="/opt/blacktemple-kn/data/run/xray.json"
XRAY_ACCESS="/opt/blacktemple-kn/logs/xray-access.log"
XKEEN_INIT="/opt/etc/init.d/S05xkeen"
BT_INIT="/opt/etc/init.d/S99blacktemple-kn"
BTKN_MARK="0x42544b4e"
BTKN_TABLE="4254"
BTKN_PORT="11820"

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

pkg_installed() {
	opkg status "$1" 2>/dev/null | grep -q "installed"
}

is_rfc1918() {
	_ip=$1
	case "$_ip" in
		10.*) return 0 ;;
		192.168.*) return 0 ;;
		172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
	esac
	return 1
}

router_has_ip() {
	_want=$1
	ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -x -q "$_want"
}

record_our_xray() {
	_pid="NONE"
	_path="NONE"
	_ver="NONE"
	if [ -x "$OUR_XRAY" ]; then
		_ver=$("$OUR_XRAY" version 2>/dev/null | head -n 1)
	fi
	for _d in /proc/[0-9]*; do
		[ -d "$_d" ] || continue
		_exe=""
		[ -L "${_d}/exe" ] && _exe=$(readlink "${_d}/exe" 2>/dev/null)
		case "$_exe" in
			"$OUR_XRAY"|"${OUR_XRAY} (deleted)")
				_pid=${_d#/proc/}
				_path=$_exe
				break
				;;
		esac
	done
	echo "our_xray_pid=${_pid}"
	echo "our_xray_exe=${_path}"
	echo "our_xray_version=${_ver}"
}

record_foreign_xray() {
	_pid="NONE"
	_path="NONE"
	for _d in /proc/[0-9]*; do
		[ -d "$_d" ] || continue
		_exe=""
		[ -L "${_d}/exe" ] && _exe=$(readlink "${_d}/exe" 2>/dev/null)
		case "$_exe" in
			"$FOREIGN_XRAY"|"${FOREIGN_XRAY} (deleted)")
				_pid=${_d#/proc/}
				_path=$_exe
				break
				;;
		esac
	done
	echo "foreign_xray_pid=${_pid}"
	echo "foreign_xray_exe=${_path}"
}

listen_port() {
	_kind=$1
	_port=$2
	_pat=":${_port} "
	if have ss; then
		if [ "$_kind" = "udp" ]; then
			ss -lun 2>/dev/null | grep -q "$_pat"
		else
			ss -ltn 2>/dev/null | grep -q "$_pat"
		fi
		return $?
	fi
	if have netstat; then
		if [ "$_kind" = "udp" ]; then
			netstat -lun 2>/dev/null | grep -q "$_pat"
		else
			netstat -ltn 2>/dev/null | grep -q "$_pat"
		fi
		return $?
	fi
	return 1
}

btkn_present() {
	have iptables || return 1
	iptables -t nat -S 2>/dev/null | grep -q BTKN_ && return 0
	iptables -t mangle -S 2>/dev/null | grep -q BTKN_ && return 0
	return 1
}

xkeen_capture_active() {
	if [ -n "${_init_status:-}" ]; then
		echo "$_init_status" | grep -qi -e run -e start -e hybrid && return 0
	fi
	listen_port tcp 1181 && return 0
	listen_port udp 1181 && return 0
	for _d in /proc/[0-9]*; do
		[ -L "${_d}/exe" ] || continue
		_p=$(readlink "${_d}/exe" 2>/dev/null)
		if [ "$_p" = "$FOREIGN_XRAY" ] || [ "$_p" = "${FOREIGN_XRAY} (deleted)" ]; then
			return 0
		fi
	done
	return 1
}

cmd_deps() {
	echo "===== DEPS ====="
	_miss=0
	for _p in ip-full iptables ipset; do
		if pkg_installed "$_p"; then
			echo "dep_${_p}=installed"
			opkg status "$_p" 2>/dev/null | head -n 8
		else
			echo "DEPENDENCY_MISSING: ${_p}"
			_miss=1
		fi
	done
	if [ "$_miss" -ne 0 ]; then
		echo "DEPENDENCY_MISSING"
		return 2
	fi
	echo "DEPS: PASS"
}

cmd_snapshot() {
	echo "===== SNAPSHOT ====="
	echo "uptime=$(cat /proc/uptime 2>/dev/null)"
	echo "loadavg=$(cat /proc/loadavg 2>/dev/null)"
	_running=0
	_init_status="NOT AVAILABLE"
	if [ -x "$XKEEN_INIT" ]; then
		_init_status=$("$XKEEN_INIT" status 2>&1) || true
	fi
	if xkeen_capture_active; then
		_running=1
	fi
	{
		echo "xkeen_init=${XKEEN_INIT}"
		echo "xkeen_was_running=${_running}"
		echo "xkeen_init_status=${_init_status}"
		record_foreign_xray
		record_our_xray
		if listen_port tcp "${BTKN_PORT}"; then echo "listen_11820_tcp=PRESENT"; else echo "listen_11820_tcp=ABSENT"; fi
		if listen_port udp "${BTKN_PORT}"; then echo "listen_11820_udp=PRESENT"; else echo "listen_11820_udp=ABSENT"; fi
		if listen_port tcp 1181; then echo "listen_1181_tcp=PRESENT"; else echo "listen_1181_tcp=ABSENT"; fi
		if listen_port udp 1181; then echo "listen_1181_udp=PRESENT"; else echo "listen_1181_udp=ABSENT"; fi
		if have ip; then
			echo "--- ip rule ---"
			ip rule 2>/dev/null || true
			if ip rule 2>/dev/null | grep -q 'fwmark 0x111'; then
				echo "ip_rule_fwmark_111=PRESENT"
			else
				echo "ip_rule_fwmark_111=NOT OBSERVED"
			fi
			if ip rule 2>/dev/null | grep -qi "$BTKN_MARK"; then
				echo "ip_rule_fwmark_btkn=PRESENT"
			else
				echo "ip_rule_fwmark_btkn=ABSENT"
			fi
			echo "--- table 111 ---"
			ip -4 route show table 111 2>/dev/null || echo "table111=NOT READABLE"
			echo "--- table ${BTKN_TABLE} ---"
			ip -4 route show table "$BTKN_TABLE" 2>/dev/null || echo "table4254=ABSENT"
		fi
		echo "--- DNS :53 ---"
		if have ss; then
			ss -lntp 2>/dev/null | grep ':53 ' || echo "listen_53=NOT OBSERVED"
		elif have netstat; then
			netstat -lntp 2>/dev/null | grep ':53 ' || echo "listen_53=NOT OBSERVED"
		fi
		ps w 2>/dev/null | grep -i ndnproxy | grep -v grep || echo "ndnproxy=NOT OBSERVED"
		echo "--- BTKN iptables ---"
		if have iptables; then
			iptables -t nat -S 2>/dev/null | grep BTKN_ || echo "btkn_nat=ABSENT"
			iptables -t mangle -S 2>/dev/null | grep BTKN_ || echo "btkn_mangle=ABSENT"
		fi
		if have ipset; then
			ipset list -n 2>/dev/null | grep '^btkn_' || echo "btkn_ipset=ABSENT"
		fi
		echo "--- manager ---"
		if [ -x "$BT_INIT" ]; then
			"$BT_INIT" status 2>&1 || true
		fi
	} | tee "$SNAP_FILE"
	echo "snapshot_file=${SNAP_FILE}"
	if [ "$_running" -ne 1 ]; then
		echo "FAIL: expected XKeen ACTIVE before mutation"
		return 1
	fi
	if btkn_present; then
		echo "FAIL: BTKN present before mutation"
		return 1
	fi
	echo "SNAPSHOT: XKeen ACTIVE; BTKN absent"
}

cmd_resolve_client() {
	echo "===== RESOLVE CLIENT ====="
	CLIENT="${BTKN_TEST_CLIENT_IPV4:-}"
	_src="BTKN_TEST_CLIENT_IPV4"
	if [ -z "$CLIENT" ] && [ -n "$SSH_CONNECTION" ]; then
		CLIENT=$(echo "$SSH_CONNECTION" | awk '{print $1}')
		_src="SSH_CONNECTION"
	fi
	if [ -z "$CLIENT" ]; then
		echo "CLIENT_REQUIRED"
		echo "LIVE ROUTING: NOT RUN"
		return 3
	fi
	echo "client_source=${_src}"
	echo "client_raw=${CLIENT}"
	case "$CLIENT" in
		*.*.*.*) ;;
		*)
			echo "CLIENT_REQUIRED"
			echo "LIVE ROUTING: NOT RUN"
			return 3
			;;
	esac
	if ! is_rfc1918 "$CLIENT"; then
		echo "CLIENT_REQUIRED"
		echo "LIVE ROUTING: NOT RUN"
		return 3
	fi
	_last=$(echo "$CLIENT" | awk -F. '{print $4}')
	if [ "$_last" = "0" ] || [ "$_last" = "255" ]; then
		echo "CLIENT_REQUIRED"
		echo "LIVE ROUTING: NOT RUN"
		return 3
	fi
	if router_has_ip "$CLIENT"; then
		echo "CLIENT_REQUIRED"
		echo "reason: client equals router address"
		echo "LIVE ROUTING: NOT RUN"
		return 3
	fi
	mkdir -p /opt/blacktemple-kn/data 2>/dev/null || true
	echo "$CLIENT" > "$CLIENT_FILE"
	echo "SELECTED_CLIENT=${CLIENT}"
	echo "client_written=${CLIENT_FILE}"
}

cmd_start_our_xray() {
	echo "===== START OUR XRAY ====="
	if [ ! -x "$BIN" ]; then
		echo "FAIL: missing $BIN"
		return 1
	fi
	if [ ! -x "$OUR_XRAY" ]; then
		echo "FAIL: missing $OUR_XRAY"
		return 1
	fi
	if [ ! -f "$XRAY_JSON" ]; then
		echo "FAIL: missing $XRAY_JSON"
		return 1
	fi
	mkdir -p /opt/blacktemple-kn/logs /opt/blacktemple-kn/run /opt/blacktemple-kn/data/run 2>/dev/null || true
	: > "$XRAY_ACCESS"
	"$BIN" xray-stop >/dev/null 2>&1 || true
	if ! "$BIN" xray-start -c "$XRAY_JSON" -exe "$OUR_XRAY"; then
		echo "FAIL: xray-start"
		return 1
	fi
	sleep 1
	record_our_xray
	_pid="NONE"
	for _d in /proc/[0-9]*; do
		[ -L "${_d}/exe" ] || continue
		_p=$(readlink "${_d}/exe" 2>/dev/null)
		if [ "$_p" = "$OUR_XRAY" ]; then
			_pid=${_d#/proc/}
			break
		fi
	done
	echo "OUR_XRAY_PID=${_pid}"
	if [ "$_pid" = "NONE" ]; then
		echo "FAIL: OUR Xray not running"
		return 1
	fi
	_link=$(readlink "/proc/${_pid}/exe" 2>/dev/null)
	echo "OUR_XRAY_EXE=${_link}"
	if [ "$_link" != "$OUR_XRAY" ]; then
		echo "FAIL: exe is not OUR Xray"
		return 1
	fi
	_ver=$("$OUR_XRAY" version 2>/dev/null | head -n 1)
	echo "OUR_XRAY_VERSION=${_ver}"
	echo "$_ver" | grep -q '26.7.28' || echo "WARN: version string does not contain 26.7.28"
	if listen_port tcp "$BTKN_PORT"; then echo "listen_11820_tcp=PRESENT"; else echo "FAIL: TCP ${BTKN_PORT} not listening"; return 1; fi
	if listen_port udp "$BTKN_PORT"; then echo "listen_11820_udp=PRESENT"; else echo "FAIL: UDP ${BTKN_PORT} not listening"; return 1; fi
	_tcp_mid=$(sed 's/.*"tag":"redirect-in"//;s/"tag":"tproxy-in".*//' "$XRAY_JSON")
	if echo "$_tcp_mid" | grep -q tproxy; then
		echo "FAIL: TCP inbound has tproxy sockopt"
		return 1
	fi
	_udp_tail=$(sed 's/.*"tag":"tproxy-in"//' "$XRAY_JSON")
	if ! echo "$_udp_tail" | grep -q tproxy; then
		echo "FAIL: UDP inbound missing tproxy"
		return 1
	fi
	echo "START_OUR_XRAY: PASS"
}

cmd_pre_xkeen() {
	echo "===== PRE-XKEEN APPLY REFUSAL ====="
	_before_nat=$(iptables -t nat -S 2>/dev/null | grep -c BTKN_ || true)
	_before_mangle=$(iptables -t mangle -S 2>/dev/null | grep -c BTKN_ || true)
	_rc=0
	_out=$("$BIN" netfilter-reconcile 2>&1) || _rc=$?
	echo "$_out"
	echo "pre_xkeen_exit=${_rc}"
	if ! echo "$_out" | grep -q "existing capture engine"; then
		echo "FAIL: expected ErrExistingCaptureEngine"
		return 1
	fi
	_after_nat=$(iptables -t nat -S 2>/dev/null | grep -c BTKN_ || true)
	_after_mangle=$(iptables -t mangle -S 2>/dev/null | grep -c BTKN_ || true)
	if [ "${_before_nat}" != "${_after_nat}" ] || [ "${_before_mangle}" != "${_after_mangle}" ]; then
		echo "FAIL: BTKN mutated during XKeen-active Apply refusal"
		return 1
	fi
	if btkn_present; then
		echo "FAIL: BTKN present after refusal"
		return 1
	fi
	echo "PRE_XKEEN: ErrExistingCaptureEngine; ZERO BTKN mutations"
}

cmd_stop_xkeen() {
	echo "===== STOP XKEEN (harness gates only) ====="
	if [ ! -x "$XKEEN_INIT" ]; then
		echo "FAIL: missing ${XKEEN_INIT}"
		return 1
	fi
	if ! "$XKEEN_INIT" stop 2>&1; then
		echo "FAIL: XKeen stop"
		return 1
	fi
	sleep 1
	record_foreign_xray
	if listen_port tcp 1181 || listen_port udp 1181; then
		echo "FAIL: 1181 still listening"
		return 1
	fi
	echo "listen_1181=GONE"
	echo "STOP_XKEEN: PASS"
}

cmd_apply() {
	echo "===== APPLY blacktempled Reconcile ====="
	if ! "$BIN" netfilter-reconcile 2>&1; then
		echo "FAIL: netfilter-reconcile Apply"
		return 1
	fi
	cmd_verify_capture
}

cmd_verify_capture() {
	echo "===== VERIFY CAPTURE ====="
	_nat=$(iptables -t nat -S 2>/dev/null)
	_mangle=$(iptables -t mangle -S 2>/dev/null)
	echo "$_nat" | grep BTKN_ || true
	echo "$_mangle" | grep BTKN_ || true
	echo "$_nat" | grep -q 'PREROUTING -j BTKN_PRE' || { echo "FAIL: nat PREROUTING -> BTKN_PRE"; return 1; }
	echo "$_nat" | grep -q 'BTKN_PRE' || { echo "FAIL: BTKN_PRE missing"; return 1; }
	echo "$_nat" | grep -q 'BTKN_TCP' || { echo "FAIL: BTKN_TCP missing"; return 1; }
	echo "$_nat" | grep -q 'REDIRECT --to-ports 11820' || { echo "FAIL: TCP REDIRECT 11820"; return 1; }
	echo "$_mangle" | grep -q 'PREROUTING -j BTKN_PRE' || { echo "FAIL: mangle PREROUTING -> BTKN_PRE"; return 1; }
	echo "$_mangle" | grep -q 'CONNMARK --restore-mark' || { echo "FAIL: UDP CONNMARK restore"; return 1; }
	echo "$_mangle" | grep -q 'TPROXY' || { echo "FAIL: UDP TPROXY"; return 1; }
	echo "$_mangle" | grep -q '11820' || { echo "FAIL: TPROXY port 11820"; return 1; }
	if echo "$_nat" | grep -q 'OUTPUT -j BTKN_OUT'; then
		echo "FAIL: OUTPUT attached"
		return 1
	fi
	if echo "$_mangle" | grep -q 'OUTPUT -j BTKN_OUT'; then
		echo "FAIL: mangle OUTPUT attached"
		return 1
	fi
	if have ip6tables; then
		if ip6tables -t nat -S 2>/dev/null | grep -q BTKN_ || ip6tables -t mangle -S 2>/dev/null | grep -q BTKN_; then
			echo "FAIL: IPv6 BTKN present"
			return 1
		fi
	fi
	echo "IPv6_CAPTURE=UNTOUCHED"
	if have ip; then
		ip rule 2>/dev/null | grep -i "$BTKN_MARK" || { echo "FAIL: fwmark ${BTKN_MARK}"; return 1; }
		ip -4 route show table "$BTKN_TABLE" 2>/dev/null | grep -q 'local default' || { echo "FAIL: table ${BTKN_TABLE} local default"; return 1; }
	fi
	if have ipset; then
		ipset list btkn_clients_v4 2>/dev/null || { echo "FAIL: btkn_clients_v4"; return 1; }
	fi
	echo "TCP_REDIRECT=PRESENT"
	echo "UDP_TPROXY=PRESENT"
	echo "MARK=${BTKN_MARK}"
	echo "TABLE=${BTKN_TABLE}"
	echo "OUTPUT=UNTOUCHED"
	echo "VERIFY_CAPTURE: PASS"
}

cmd_counters() {
	echo "===== COUNTERS ====="
	if have iptables; then
		iptables -t nat -nvxL BTKN_TCP 2>/dev/null || true
		iptables -t mangle -nvxL BTKN_UDP 2>/dev/null || true
	fi
	echo "--- xray access tail ---"
	tail -n 20 "$XRAY_ACCESS" 2>/dev/null || echo "access_log=EMPTY"
}

cmd_fail_open() {
	echo "===== FAIL-OPEN OUR XRAY DEATH ====="
	"$BIN" xray-stop 2>&1 || true
	sleep 1
	record_our_xray
	if ! "$BIN" netfilter-reconcile 2>&1; then
		echo "FAIL: reconcile after xray death"
		return 1
	fi
	if btkn_present; then
		echo "FAIL: BTKN still present after fail-open"
		return 1
	fi
	if have ip; then
		if ip rule 2>/dev/null | grep -qi "$BTKN_MARK"; then
			echo "FAIL: mark still present"
			return 1
		fi
		if ip -4 route show table "$BTKN_TABLE" 2>/dev/null | grep -q .; then
			echo "FAIL: table4254 still present"
			return 1
		fi
	fi
	echo "FAIL_OPEN: BTKN cleanup PASS"
}

cmd_restart_manager() {
	echo "===== MANAGER RESTART ====="
	if [ ! -x "$BT_INIT" ]; then
		echo "FAIL: missing $BT_INIT"
		return 1
	fi
	"$BT_INIT" restart 2>&1 || true
	sleep 1
	if btkn_present; then
		echo "manager_restart_gap=BTKN_STILL_PRESENT"
	else
		echo "manager_restart_gap=DIRECT"
	fi
	if ! "$BIN" netfilter-reconcile 2>&1; then
		echo "FAIL: fresh reconcile after manager restart"
		return 1
	fi
	_jumps=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -c -- '-j BTKN_PRE' || true)
	echo "nat_prerouting_btkn_jumps=${_jumps}"
	if [ "${_jumps}" -gt 1 ]; then
		echo "FAIL: duplicate BTKN_PRE jumps"
		return 1
	fi
	cmd_verify_capture
	echo "MANAGER_RESTART: PASS"
}

cmd_cleanup_btkn() {
	echo "===== CLEANUP BTKN ONLY ====="
	if [ -x "$BIN" ]; then
		"$BIN" netfilter-reconcile stop 2>&1 || true
	fi
	if btkn_present; then
		echo "FAIL: BTKN still present after reconcile stop"
		return 1
	fi
	echo "BTKN cleanup done"
}

cmd_stop_blacktemple() {
	echo "===== STOP TEST BLACKTEMPLE ====="
	if [ -x "$BIN" ]; then
		"$BIN" xray-stop 2>&1 || true
		"$BIN" netfilter-reconcile stop 2>&1 || true
	fi
	record_our_xray
	echo "test OUR xray stopped"
}

cmd_restore_xkeen() {
	echo "===== RESTORE XKEEN ====="
	_was=0
	if [ -f "$SNAP_FILE" ]; then
		_was=$(awk -F= '/^xkeen_was_running=/ { print $2; exit }' "$SNAP_FILE" 2>/dev/null)
	fi
	if [ ! -x "$XKEEN_INIT" ]; then
		echo "RESTORE_XKEEN: FAIL"
		echo "FAIL: XKeen restore (init missing)"
		return 1
	fi
	if [ "${_was}" = "1" ] || [ -z "${_was}" ]; then
		if ! "$XKEEN_INIT" start 2>&1; then
			echo "RESTORE_XKEEN: FAIL"
			echo "FAIL: XKeen restore"
			return 1
		fi
	else
		echo "xkeen was not running at snapshot; not started"
	fi
	sleep 2
	record_foreign_xray
	if ! listen_port tcp 1181; then
		echo "RESTORE_XKEEN: FAIL"
		echo "FAIL: TCP 1181 not restored"
		return 1
	fi
	echo "RESTORE_XKEEN: PASS"
}

cmd_verify_restore() {
	echo "===== VERIFY RESTORE ====="
	if btkn_present; then
		echo "FAIL: BTKN present after restore"
		return 1
	fi
	if listen_port tcp "$BTKN_PORT" || listen_port udp "$BTKN_PORT"; then
		echo "FAIL: 11820 still listening"
		return 1
	fi
	record_foreign_xray
	record_our_xray
	if have ip; then
		ip rule 2>/dev/null | grep -e 0x111 || echo "ip_rule_fwmark_111=NOT OBSERVED"
		ip -4 route show table 111 2>/dev/null || echo "table111=NOT READABLE"
	fi
	echo "--- DNS :53 ---"
	if have ss; then
		ss -lntp 2>/dev/null | grep ':53 ' || echo "listen_53=NOT OBSERVED"
	fi
	ps w 2>/dev/null | grep -i ndnproxy | grep -v grep || echo "ndnproxy=NOT OBSERVED"
	echo "DNS=KEENETIC_DIRECT"
	echo "DNS_LEAK_FREE=NOT CLAIMED"
}

cmd_dns() {
	echo "===== DNS ====="
	echo "DNS=KEENETIC_DIRECT"
	echo "DNS_LEAK_FREE=NOT CLAIMED"
}

usage() {
	echo "usage: router-smoke-app.sh {deps|snapshot|resolve-client|start-our-xray|pre-xkeen|stop-xkeen|apply|verify-capture|counters|fail-open|restart-manager|cleanup-btkn|stop-blacktemple|restore-xkeen|verify-restore|dns}"
}

require_gates

_cmd=${1:-}
if [ -z "$_cmd" ]; then
	echo "LIVE ROUTING SMOKE: NOT RUN"
	echo "reason: explicit subcommand required"
	exit 0
fi
case "$_cmd" in
	deps) cmd_deps ;;
	snapshot) cmd_snapshot ;;
	resolve-client) cmd_resolve_client ;;
	start-our-xray) cmd_start_our_xray ;;
	pre-xkeen) cmd_pre_xkeen ;;
	stop-xkeen) cmd_stop_xkeen ;;
	apply) cmd_apply ;;
	verify-capture) cmd_verify_capture ;;
	counters) cmd_counters ;;
	fail-open) cmd_fail_open ;;
	restart-manager) cmd_restart_manager ;;
	cleanup-btkn) cmd_cleanup_btkn ;;
	stop-blacktemple) cmd_stop_blacktemple ;;
	restore-xkeen) cmd_restore_xkeen ;;
	verify-restore) cmd_verify_restore ;;
	dns) cmd_dns ;;
	*)
		usage
		exit 1
		;;
esac
exit $?
