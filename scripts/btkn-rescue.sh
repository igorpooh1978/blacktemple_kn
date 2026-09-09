#!/bin/sh
# Independent KN-1011 rescue watchdog. Does not call blacktempled.
# Owned namespace only: BTKN_* / btkn_* / mark 0x42544b4e / table 4254 / OUR Xray.
# Never global table flush, route/rule flush, indiscriminate process kill,
# module unload, or XKeen object deletion.
# Each watcher owns a run token. Stale watchers must not recover a newer run.

RUN="${BTKN_RESCUE_DIR:-/opt/blacktemple-kn/run}"
CURRENT="$RUN/btkn-rescue.current"
OUR_XRAY="/opt/blacktemple-kn/bin/xray"
FOREIGN_XRAY="${BTKN_FOREIGN_XRAY:-/opt/sbin/xray}"
XKEEN_INIT="${BTKN_XKEEN_INIT:-/opt/etc/init.d/S05xkeen}"
MARK="0x42544b4e"
TABLE="4254"

mkdir -p "$RUN" 2>/dev/null || true

armed_file() {
	echo "$RUN/btkn-rescue.$1.armed"
}

disarm_file() {
	echo "$RUN/btkn-rescue.$1.disarm"
}

read_current() {
	cat "$CURRENT" 2>/dev/null || true
}

write_current() {
	echo "$1" > "$CURRENT.tmp.$$"
	mv "$CURRENT.tmp.$$" "$CURRENT"
}

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

foreign_xray_alive() {
	for _d in /proc/[0-9]*; do
		[ -d "$_d" ] || continue
		_exe=""
		[ -L "${_d}/exe" ] && _exe=$(readlink "${_d}/exe" 2>/dev/null)
		case "$_exe" in
			"$FOREIGN_XRAY"|"${FOREIGN_XRAY} (deleted)")
				return 0
				;;
		esac
	done
	return 1
}

xkeen_healthy() {
	foreign_xray_alive || return 1
	listen_port tcp 1181 || return 1
	listen_port udp 1181 || return 1
	return 0
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
	if xkeen_healthy; then
		echo "rescue_xkeen=ALREADY_HEALTHY"
		return 0
	fi
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
	_id=$1
	if [ -z "$_id" ]; then
		_id=$(read_current)
	fi
	_cur=$(read_current)
	if [ -z "$_id" ] || [ "$_cur" != "$_id" ]; then
		echo "rescue_stale id=${_id} current=${_cur}"
		return 0
	fi
	if [ -f "$(disarm_file "$_id")" ]; then
		echo "rescue_disarmed id=${_id}"
		return 0
	fi
	echo "===== RESCUE RECOVER ====="
	echo "run_id=${_id}"
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
	echo "$_id" > "$(armed_file "$_id")"
	rm -f "$(disarm_file "$_id")"
	write_current "$_id"
	echo "rescue_armed=${_id} deadline_sec=${_sec}"
	if [ -n "$BTKN_RESCUE_FOREGROUND" ]; then
		cmd_watch "$_id" "$_sec"
		return $?
	fi
	sh "$0" watch "$_id" "$_sec" >/dev/null 2>&1 &
}

cmd_watch() {
	_id=$1
	_sec=$2
	if [ -z "$_id" ]; then
		echo "rescue_stale id= missing"
		exit 0
	fi
	if [ -z "$_sec" ]; then
		_sec=90
	fi
	_n=0
	while [ "$_n" -lt "$_sec" ]; do
		if [ -f "$(disarm_file "$_id")" ]; then
			echo "rescue_disarmed id=${_id}"
			exit 0
		fi
		_cur=$(read_current)
		if [ "$_cur" != "$_id" ]; then
			echo "rescue_stale id=${_id} current=${_cur}"
			exit 0
		fi
		_n=$((_n + 1))
		sleep 1
	done
	cmd_recover "$_id"
}

cmd_disarm() {
	_id=$1
	if [ -z "$_id" ]; then
		_id=$(read_current)
	fi
	if [ -z "$_id" ]; then
		echo "rescue_disarmed"
		return 0
	fi
	echo "disarm" > "$(disarm_file "$_id")"
	rm -f "$(armed_file "$_id")"
	_cur=$(read_current)
	if [ "$_cur" = "$_id" ]; then
		rm -f "$CURRENT"
	fi
	echo "rescue_disarmed id=${_id}"
}

_cmd=$1
case "$_cmd" in
	arm) cmd_arm "$2" "$3" ;;
	watch) cmd_watch "$2" "$3" ;;
	disarm) cmd_disarm "$2" ;;
	recover) cmd_recover "$2" ;;
	*)
		echo "usage: btkn-rescue.sh {arm <run_id> <seconds>|watch <run_id> <seconds>|disarm [run_id]|recover [run_id]}"
		exit 1
		;;
esac
