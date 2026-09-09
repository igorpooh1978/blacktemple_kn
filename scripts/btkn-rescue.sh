#!/bin/sh
# Independent KN-1011 rescue watchdog. Does not call blacktempled.
# Owned namespace only: BTKN_* / btkn_* / mark 0x42544b4e / table 4254 / OUR Xray.
# Never global table flush, route/rule flush, indiscriminate process kill,
# module unload, or XKeen object deletion.

RUN="${BTKN_RESCUE_DIR:-/opt/blacktemple-kn/run}"
ARMED="$RUN/btkn-rescue.armed"
DISARM="$RUN/btkn-rescue.disarm"
OUR_XRAY="/opt/blacktemple-kn/bin/xray"
XKEEN_INIT="/opt/etc/init.d/S05xkeen"
MARK="0x42544b4e"
TABLE="4254"

mkdir -p "$RUN" 2>/dev/null || true

have() {
	command -v "$1" >/dev/null 2>&1
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

detach_jump() {
	_table=$1
	if ! have iptables; then
		return 0
	fi
	_n=0
	while [ "$_n" -lt 8 ]; do
		iptables -t "$_table" -D PREROUTING -j BTKN_PRE 2>/dev/null || break
		_n=$((_n + 1))
	done
}

flush_owned_chain() {
	_table=$1
	_chain=$2
	if ! have iptables; then
		return 0
	fi
	iptables -t "$_table" -F "$_chain" 2>/dev/null || true
	iptables -t "$_table" -X "$_chain" 2>/dev/null || true
}

stop_our_xray() {
	for _d in /proc/[0-9]*; do
		[ -d "$_d" ] || continue
		_exe=""
		[ -L "${_d}/exe" ] && _exe=$(readlink "${_d}/exe" 2>/dev/null)
		case "$_exe" in
			"$OUR_XRAY"|"${OUR_XRAY} (deleted)")
				_pid=${_d#/proc/}
				kill "$_pid" 2>/dev/null || true
				;;
		esac
	done
}

restore_xkeen() {
	if [ -x "$XKEEN_INIT" ]; then
		"$XKEEN_INIT" start 2>/dev/null || true
	fi
	_n=0
	while [ "$_n" -lt 30 ]; do
		if listen_port tcp 1181 && listen_port udp 1181; then
			echo "rescue_xkeen=RESTORED"
			return 0
		fi
		_n=$((_n + 1))
		sleep 1
	done
	echo "rescue_xkeen=DEADLINE"
	return 1
}

cmd_recover() {
	echo "===== RESCUE RECOVER ====="
	echo "run_id=$(cat "$ARMED" 2>/dev/null || echo none)"
	detach_jump nat
	detach_jump mangle
	flush_owned_chain nat BTKN_TCP
	flush_owned_chain nat BTKN_PRE
	flush_owned_chain nat BTKN_OUT
	flush_owned_chain mangle BTKN_UDP
	flush_owned_chain mangle BTKN_PRE
	flush_owned_chain mangle BTKN_OUT
	if have ip; then
		ip -4 rule del fwmark "$MARK/0xffffffff" lookup "$TABLE" 2>/dev/null || true
		ip -4 rule del fwmark "$MARK" lookup "$TABLE" 2>/dev/null || true
		ip -4 route del local default dev lo table "$TABLE" 2>/dev/null || true
	fi
	if have ipset; then
		ipset destroy btkn_clients_v4 2>/dev/null || true
		ipset destroy btkn_exclude_v4 2>/dev/null || true
	fi
	stop_our_xray
	restore_xkeen
	echo "rescue_btkn=REMOVED"
}

cmd_arm() {
	_id=$1
	_sec=$2
	if [ -z "$_id" ]; then
		_id="rescue-$$"
	fi
	if [ -z "$_sec" ]; then
		_sec=90
	fi
	echo "$_id" > "$ARMED"
	rm -f "$DISARM"
	echo "rescue_armed=${_id} deadline_sec=${_sec}"
	if [ -n "$BTKN_RESCUE_FOREGROUND" ]; then
		cmd_watch "$_sec"
		return $?
	fi
	sh "$0" watch "$_sec" >/dev/null 2>&1 &
}

cmd_watch() {
	_sec=$1
	if [ -z "$_sec" ]; then
		_sec=90
	fi
	_n=0
	while [ "$_n" -lt "$_sec" ]; do
		if [ -f "$DISARM" ]; then
			echo "rescue_disarmed"
			exit 0
		fi
		_n=$((_n + 1))
		sleep 1
	done
	cmd_recover
}

cmd_disarm() {
	echo "disarm" > "$DISARM"
	rm -f "$ARMED"
	echo "rescue_disarmed"
}

_cmd=$1
case "$_cmd" in
	arm) cmd_arm "$2" "$3" ;;
	watch) cmd_watch "$2" ;;
	disarm) cmd_disarm ;;
	recover) cmd_recover ;;
	*)
		echo "usage: btkn-rescue.sh {arm <run_id> <seconds>|watch <seconds>|disarm|recover}"
		exit 1
		;;
esac
