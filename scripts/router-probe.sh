#!/bin/sh
# Read-only KN-1011 capability probe (POSIX / BusyBox).
# Best-effort: a missing tool prints NOT AVAILABLE and the probe continues.
# Resource-safe diagnostic: single instance, hard timeout, owned-tree cleanup.
# Does not mutate routing, firewall, sysctl, packages, or foreign processes.

BTKN_PROBE_LOCKDIR="${BTKN_PROBE_LOCKDIR:-/tmp/btkn-router-probe.lock}"
BTKN_PROBE_MAX_SEC="${BTKN_PROBE_MAX_SEC:-180}"
BTKN_PROBE_GRACE_SEC="${BTKN_PROBE_GRACE_SEC:-2}"
BTKN_PROBE_CMD_SEC="${BTKN_PROBE_CMD_SEC:-10}"
BTKN_PROBE_MAX_BYTES=262144
BTKN_WATCHDOG_PID=""
BTKN_SUPERVISOR_RUN_ID=""
BTKN_WORKER_PID=""

btkn_ppid() {
	sed -n 's/^PPid:[[:space:]]*//p' "/proc/$1/status" 2>/dev/null
}

btkn_cmdline() {
	if [ ! -r "/proc/$1/cmdline" ]; then
		echo ""
		return 1
	fi
	tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null || true
}

btkn_has_run_id() {
	_pid=$1
	_id=$2
	[ -n "$_id" ] || return 1
		[ -r "/proc/${_pid}/environ" ] || return 1
	cat "/proc/${_pid}/environ" 2>/dev/null | tr '\0' '\n' | grep -q "^BTKN_PROBE_RUN_ID=${_id}$"
}

btkn_forbidden_cmd() {
	_c=$(echo "$1" | tr 'A-Z' 'a-z')
	case "$_c" in
		*xray*|*xkeen*|*ndnproxy*|*nginx*|*ndm*) return 0 ;;
	esac
	return 1
}

btkn_root_ok() {
	_pid=$1
	_id=$2
	[ -d "/proc/${_pid}" ] || return 1
	_cmd=$(btkn_cmdline "$_pid")
	echo "$_cmd" | grep -q 'router-probe.sh' || return 1
	btkn_has_run_id "$_pid" "$_id" || return 1
	btkn_forbidden_cmd "$_cmd" && return 1
	return 0
}

btkn_is_probe_script() {
	echo "$1" | grep -q 'router-probe.sh'
}

btkn_collect_descendants() {
	_root=$1
	_list="${_root}"
	_changed=1
	while [ "$_changed" -eq 1 ]; do
		_changed=0
		for _d in /proc/[0-9]*; do
			_p=${_d#/proc/}
			echo " $_list " | grep -q " $_p " && continue
			_pp=$(btkn_ppid "$_p")
			echo " $_list " | grep -q " $_pp " || continue
			_cmd=$(btkn_cmdline "$_p")
			btkn_forbidden_cmd "$_cmd" && continue
			_list="${_list} ${_p}"
			_changed=1
		done
	done
	echo "$_list"
}

btkn_signal_list() {
	_sig=$1
	_root=$2
	shift 2
	_rev=""
	for _p in "$@"; do
		_rev="${_p} ${_rev}"
	done
	for _p in $_rev; do
		[ "$_p" = "$_root" ] && continue
		[ "$_p" = "1" ] && continue
		kill -$_sig "$_p" 2>/dev/null || true
	done
	[ "$_root" = "1" ] || kill -$_sig "$_root" 2>/dev/null || true
}

btkn_collect_owned() {
	btkn_collect_descendants "$1"
}

btkn_term_kill_tree() {
	_root=$1
	_list=$(btkn_collect_descendants "$_root")
	_rev=""
	for _p in $_list; do
		_rev="${_p} ${_rev}"
	done
	for _p in $_rev; do
		[ "$_p" = "$_root" ] && continue
		[ "$_p" = "1" ] && continue
		kill -TERM "$_p" 2>/dev/null || true
	done
	[ "$_root" = "1" ] || kill -TERM "$_root" 2>/dev/null || true
	sleep "$BTKN_PROBE_GRACE_SEC"
	_list=$(btkn_collect_descendants "$_root")
	for _p in $_list; do
		[ "$_p" = "1" ] && continue
		[ -d "/proc/${_p}" ] || continue
		kill -KILL "$_p" 2>/dev/null || true
	done
}

btkn_kill_owned_tree() {
	_root=${1:-$$}
	_id=${BTKN_PROBE_RUN_ID:-}
	btkn_root_ok "$_root" "$_id" || return 0
	btkn_term_kill_tree "$_root"
}

btkn_write_lock_meta() {
	_pid=$1
	{
		echo "run_id=${BTKN_SUPERVISOR_RUN_ID}"
		echo "pid=${_pid}"
		echo "script=$0"
		echo "started=$(date +%s)"
		echo "cmdline=$(btkn_cmdline "$_pid")"
	} > "$BTKN_PROBE_LOCKDIR/meta"
	echo "$_pid" > "$BTKN_PROBE_LOCKDIR/pid"
}

btkn_release_lock() {
	[ -d "$BTKN_PROBE_LOCKDIR" ] || return 0
	rm -f "$BTKN_PROBE_LOCKDIR/meta" "$BTKN_PROBE_LOCKDIR/pid" 2>/dev/null || true
	rmdir "$BTKN_PROBE_LOCKDIR" 2>/dev/null || rm -rf "$BTKN_PROBE_LOCKDIR" 2>/dev/null || true
}

btkn_stop_watchdog() {
	if [ -n "$BTKN_WATCHDOG_PID" ]; then
		for _d in /proc/[0-9]*; do
			_p=${_d#/proc/}
			_pp=$(btkn_ppid "$_p")
			if [ "$_pp" = "$BTKN_WATCHDOG_PID" ]; then
				kill -TERM "$_p" 2>/dev/null || true
			fi
		done
		kill -TERM "$BTKN_WATCHDOG_PID" 2>/dev/null || true
		BTKN_WATCHDOG_PID=""
	fi
}

btkn_timeout_kill() {
	echo "TIMEOUT"
	if [ -n "$BTKN_WORKER_PID" ] && [ -n "$BTKN_SUPERVISOR_RUN_ID" ]; then
		if btkn_root_ok "$BTKN_WORKER_PID" "$BTKN_SUPERVISOR_RUN_ID"; then
			btkn_term_kill_tree "$BTKN_WORKER_PID"
		fi
		btkn_reap_run_id "$BTKN_SUPERVISOR_RUN_ID"
	fi
	btkn_release_lock
}

btkn_on_signal() {
	_st=$?
	trap '' EXIT INT TERM HUP
	if [ -n "$BTKN_WORKER_PID" ] && [ -n "$BTKN_SUPERVISOR_RUN_ID" ]; then
		if btkn_root_ok "$BTKN_WORKER_PID" "$BTKN_SUPERVISOR_RUN_ID"; then
			btkn_term_kill_tree "$BTKN_WORKER_PID"
		fi
		btkn_reap_run_id "$BTKN_SUPERVISOR_RUN_ID"
	fi
	btkn_release_lock
	exit $_st
}

btkn_reap_run_id() {
	_id=$1
	[ -n "$_id" ] || return 0
	_list=""
	for _d in /proc/[0-9]*; do
		_p=${_d#/proc/}
		[ "$_p" = "$$" ] && continue
		btkn_has_run_id "$_p" "$_id" || continue
		_cmd=$(btkn_cmdline "$_p")
		btkn_forbidden_cmd "$_cmd" && continue
		_list="${_list} ${_p}"
	done
	[ -n "$_list" ] || return 0
	_rev=""
	for _p in $_list; do
		_rev="${_p} ${_rev}"
	done
	for _p in $_rev; do
		[ "$_p" = "1" ] && continue
		[ "$_p" = "$$" ] && continue
		kill -TERM "$_p" 2>/dev/null || true
	done
	sleep "$BTKN_PROBE_GRACE_SEC"
	for _p in $_rev; do
		[ "$_p" = "1" ] && continue
		[ "$_p" = "$$" ] && continue
		[ -d "/proc/${_p}" ] || continue
		btkn_has_run_id "$_p" "$_id" || continue
		_cmd=$(btkn_cmdline "$_p")
		btkn_forbidden_cmd "$_cmd" && continue
		kill -KILL "$_p" 2>/dev/null || true
	done
}

btkn_run_id_left() {
	_id=$1
	for _d in /proc/[0-9]*; do
		_p=${_d#/proc/}
		[ "$_p" = "$$" ] && continue
		btkn_has_run_id "$_p" "$_id" || continue
		_cmd=$(btkn_cmdline "$_p")
		btkn_forbidden_cmd "$_cmd" && continue
		return 0
	done
	return 1
}

btkn_lock_live_identity() {
	_meta="$BTKN_PROBE_LOCKDIR/meta"
	[ -r "$_meta" ] || return 1
	_oldpid=$(sed -n 's/^pid=//p' "$_meta" | head -n 1)
	_oldid=$(sed -n 's/^run_id=//p' "$_meta" | head -n 1)
	[ -n "$_oldpid" ] || return 1
	if [ ! -d "/proc/${_oldpid}" ]; then
		return 1
	fi
	if btkn_root_ok "$_oldpid" "$_oldid"; then
		return 0
	fi
	return 2
}

btkn_acquire() {
	if [ -z "$BTKN_PROBE_RUN_ID" ]; then
		BTKN_PROBE_RUN_ID="${$}-$(date +%s)"
	fi
	BTKN_SUPERVISOR_RUN_ID=$BTKN_PROBE_RUN_ID
	unset BTKN_PROBE_RUN_ID
	if mkdir "$BTKN_PROBE_LOCKDIR" 2>/dev/null; then
		:
	else
		btkn_lock_live_identity
		_lk=$?
		if [ "$_lk" -eq 0 ]; then
			echo "ALREADY_RUNNING"
			exit 0
		fi
		if [ "$_lk" -eq 2 ]; then
			echo "FOREIGN_OR_UNKNOWN_PROCESS"
			exit 0
		fi
		if [ ! -r "$BTKN_PROBE_LOCKDIR/meta" ]; then
			sleep 1
			btkn_lock_live_identity
			_lk=$?
			if [ "$_lk" -eq 0 ]; then
				echo "ALREADY_RUNNING"
				exit 0
			fi
			if [ "$_lk" -eq 2 ]; then
				echo "FOREIGN_OR_UNKNOWN_PROCESS"
				exit 0
			fi
		fi
		_oldid=$(sed -n 's/^run_id=//p' "$BTKN_PROBE_LOCKDIR/meta" 2>/dev/null | head -n 1)
		btkn_reap_run_id "$_oldid"
		btkn_release_lock
		if ! mkdir "$BTKN_PROBE_LOCKDIR" 2>/dev/null; then
			echo "ALREADY_RUNNING"
			exit 0
		fi
	fi
}

btkn_supervisor_run() {
	btkn_acquire
	_id=$BTKN_SUPERVISOR_RUN_ID
	trap 'btkn_on_signal' EXIT INT TERM HUP
	BTKN_PROBE_WORKER=1 BTKN_PROBE_RUN_ID="$_id" BTKN_PROBE_LOCKDIR="$BTKN_PROBE_LOCKDIR" \
		BTKN_PROBE_MAX_SEC="$BTKN_PROBE_MAX_SEC" BTKN_PROBE_GRACE_SEC="$BTKN_PROBE_GRACE_SEC" \
		BTKN_PROBE_CMD_SEC="$BTKN_PROBE_CMD_SEC" BTKN_PROBE_SELFTEST="${BTKN_PROBE_SELFTEST:-}" \
		sh "$0" "$@" &
	BTKN_WORKER_PID=$!
	btkn_write_lock_meta "$BTKN_WORKER_PID"
	_n=0
	while [ "$_n" -lt "$BTKN_PROBE_MAX_SEC" ]; do
		if [ ! -d "/proc/${BTKN_WORKER_PID}" ]; then
			wait "$BTKN_WORKER_PID"
			_st=$?
			trap '' EXIT INT TERM HUP
			btkn_release_lock
			exit $_st
		fi
		sleep 1
		_n=$((_n + 1))
	done
	echo "TIMEOUT"
	if btkn_root_ok "$BTKN_WORKER_PID" "$_id"; then
		btkn_term_kill_tree "$BTKN_WORKER_PID"
	fi
	btkn_reap_run_id "$_id"
	_left=0
	if btkn_run_id_left "$_id"; then
		_left=1
	fi
	trap '' EXIT INT TERM HUP
	btkn_release_lock
	wait "$BTKN_WORKER_PID" 2>/dev/null || true
	if [ "$_left" -eq 1 ]; then
		echo "TIMEOUT_CLEANUP_FAILED"
		exit 1
	fi
	exit 1
}

btkn_finish() {
	trap '' EXIT INT TERM HUP
	btkn_stop_watchdog
	btkn_release_lock
}

btkn_cmd_cleanup() {
	_want=$1
	if [ -z "$_want" ]; then
		echo "REMOTE_PROCESS_NOT_FOUND"
		return 1
	fi
	BTKN_PROBE_RUN_ID=$_want
	export BTKN_PROBE_RUN_ID
	_had=0
	if btkn_run_id_left "$_want"; then
		_had=1
	fi
	if [ -d "$BTKN_PROBE_LOCKDIR" ]; then
		_oldpid=$(sed -n 's/^pid=//p' "$BTKN_PROBE_LOCKDIR/meta" 2>/dev/null | head -n 1)
		_oldid=$(sed -n 's/^run_id=//p' "$BTKN_PROBE_LOCKDIR/meta" 2>/dev/null | head -n 1)
		if [ -n "$_oldid" ] && [ "$_oldid" != "$_want" ]; then
			echo "REMOTE_PROCESS_FOREIGN"
			return 1
		fi
		if [ -n "$_oldpid" ] && [ -d "/proc/${_oldpid}" ]; then
			if btkn_root_ok "$_oldpid" "$_want"; then
				btkn_kill_owned_tree "$_oldpid"
				_had=1
			elif [ -n "$_oldid" ]; then
				echo "REMOTE_PROCESS_FOREIGN"
				return 1
			fi
		fi
	fi
	btkn_reap_run_id "$_want"
	btkn_release_lock
	if btkn_run_id_left "$_want"; then
		echo "TIMEOUT_CLEANUP_FAILED"
		return 1
	fi
	if [ "$_had" -eq 1 ]; then
		echo "TIMEOUT_CLEANED"
		return 0
	fi
	echo "REMOTE_PROCESS_NOT_FOUND"
	return 1
}

btkn_cmd_cleanup_orphans() {
	if [ ! -d "$BTKN_PROBE_LOCKDIR" ]; then
		echo "REMOTE_PROCESS_NOT_FOUND"
		return 1
	fi
	btkn_lock_live_identity
	_lk=$?
	if [ "$_lk" -eq 0 ]; then
		echo "ALREADY_RUNNING"
		return 0
	fi
	if [ "$_lk" -eq 2 ]; then
		echo "FOREIGN_OR_UNKNOWN_PROCESS"
		return 1
	fi
	_oldid=$(sed -n 's/^run_id=//p' "$BTKN_PROBE_LOCKDIR/meta" 2>/dev/null | head -n 1)
	if [ -z "$_oldid" ]; then
		echo "FOREIGN_OR_UNKNOWN_PROCESS"
		return 1
	fi
	btkn_reap_run_id "$_oldid"
	btkn_release_lock
	if btkn_run_id_left "$_oldid"; then
		echo "TIMEOUT_CLEANUP_FAILED"
		return 1
	fi
	echo "TIMEOUT_CLEANED"
	return 0
}

redact() {
	# One-pass awk. No sed|awk|awk pipeline. IPv6 only on lines with :: or 3+ colons.
	if ! command -v awk >/dev/null 2>&1; then
		cat
		return 0
	fi
	awk -v cap="$BTKN_PROBE_MAX_BYTES" '
		BEGIN { n = 0 }
		function private_ip(ip,   a) {
			split(ip, a, ".")
			if (a[1] + 0 == 10) return 1
			if (a[1] + 0 == 127) return 1
			if (a[1] + 0 == 192 && a[2] + 0 == 168) return 1
			if (a[1] + 0 == 172 && a[2] + 0 >= 16 && a[2] + 0 <= 31) return 1
			if (a[1] + 0 == 169 && a[2] + 0 == 254) return 1
			if (a[1] + 0 == 0) return 1
			if (a[1] + 0 == 255) return 1
			return 0
		}
		function keep_ip6(tok,   n, cidr) {
			n = tolower(tok)
			gsub(/\[|\]/, "", n)
			cidr = ""
			if (match(n, /\/[0-9]+$/)) {
				cidr = substr(n, RSTART)
				n = substr(n, 1, RSTART - 1)
			}
			if (n == "::" || n == "::1") return 1
			if (n == "fe80::") return 1
			if (n == "fc00::" || n == "fd00::" || n == "ff00::") return 1
			return 0
		}
		{
			n += length($0) + 1
			if (n > cap) { print "[TRUNCATED]"; exit }
			if (length($0) > 4096) $0 = substr($0, 1, 4096) "[TRUNCATED]"
			gsub(/[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]/, "[REDACTED-MAC]")
			gsub(/[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]/, "[REDACTED-UUID]")
			gsub(/[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^ \t"'\'']+/, "[REDACTED-URL]")
			line = $0
			out = ""
			while (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
				out = out substr(line, 1, RSTART - 1)
				ip = substr(line, RSTART, RLENGTH)
				if (private_ip(ip)) out = out ip
				else out = out "[REDACTED-IP]"
				line = substr(line, RSTART + RLENGTH)
			}
			line = out line
			out = ""
			cc = gsub(/:/, ":", line)
			if (index(line, "::") > 0 || cc >= 3) {
				rest = line
				while (match(rest, /[0-9A-Fa-f]*:[0-9A-Fa-f:]+/)) {
					tok = substr(rest, RSTART, RLENGTH)
					nc = gsub(/:/, ":", tok)
					out = out substr(rest, 1, RSTART - 1)
					if (nc < 2) out = out tok
					else if (nc == 2 && index(tok, "::") == 0) out = out tok
					else if (keep_ip6(tok)) out = out tok
					else out = out "[REDACTED-IP6]"
					rest = substr(rest, RSTART + RLENGTH)
				}
				print out rest
			} else {
				print line
			}
		}
	'
}

xkeen_ipv6_names_targets() {
	# Chain names and jump targets only; drop -s/-d/--on-ip address args.
	if ! command -v awk >/dev/null 2>&1; then
		cat
		return 0
	fi
	awk '
		{
			out = ""
			skip = 0
			n = split($0, a, " ")
			for (i = 1; i <= n; i++) {
				if (skip) { skip = 0; continue }
				if (a[i] == "-s" || a[i] == "-d" || a[i] == "--on-ip" || a[i] == "--to" || a[i] == "--to-destination") {
					skip = 1
					continue
				}
				out = out a[i] " "
			}
			print out
		}
	'
}

section() {
	echo ""
	echo "===== $1 ====="
}

have() {
	command -v "$1" >/dev/null 2>&1
}

try() {
	_label=$1
	shift
	_bin=$1
	echo "--- ${_label} ---"
	if [ -z "$_bin" ]; then
		echo "NOT AVAILABLE"
		return 0
	fi
	if ! have "$_bin"; then
		echo "NOT AVAILABLE: ${_bin}"
		return 0
	fi
	"$@" 2>&1 | redact
	return 0
}

try_net() {
	_label=$1
	shift
	_bin=$1
	echo "--- ${_label} ---"
	if [ -z "$_bin" ]; then
		echo "NOT AVAILABLE"
		return 0
	fi
	if ! have "$_bin"; then
		echo "NOT AVAILABLE: ${_bin}"
		return 0
	fi
	(
		"$@" 2>&1 | redact
	) &
	_sup=$!
	_n=0
	while [ "$_n" -lt "$BTKN_PROBE_CMD_SEC" ]; do
		if [ ! -d "/proc/${_sup}" ]; then
			wait "$_sup" 2>/dev/null || true
			return 0
		fi
		sleep 1
		_n=$((_n + 1))
	done
	_cmd=$(btkn_cmdline "$_sup")
	btkn_forbidden_cmd "$_cmd" && return 0
	_list=$(btkn_collect_descendants "$_sup")
	_rev=""
	for _p in $_list; do
		_rev="${_p} ${_rev}"
	done
	for _p in $_rev; do
		[ "$_p" = "1" ] && continue
		kill -TERM "$_p" 2>/dev/null || true
	done
	sleep 1
	for _p in $_rev; do
		[ "$_p" = "1" ] && continue
		[ -d "/proc/${_p}" ] || continue
		kill -KILL "$_p" 2>/dev/null || true
	done
	wait "$_sup" 2>/dev/null || true
	echo "TIMEOUT"
	echo "BOUNDED: ${_label}"
	return 0
}

show_file() {
	_path=$1
	echo "--- ${_path} ---"
	if [ -r "$_path" ]; then
		cat "$_path" 2>&1 | redact
	else
		echo "NOT AVAILABLE: ${_path}"
	fi
}

tool_path() {
	_bin=$1
	if have "$_bin"; then
		echo "${_bin}: $(command -v "$_bin")"
	else
		echo "${_bin}: NOT AVAILABLE"
	fi
}

show_dir() {
	_path=$1
	echo "--- ${_path} ---"
	if [ -d "$_path" ]; then
		echo "dir_exists: ${_path}"
		ls -l "$_path" 2>&1 | redact
	else
		echo "NOT AVAILABLE: ${_path}"
	fi
}

classify_proc() {
	_blob=$1
	_class="UNKNOWN"
	case "${_blob}" in
		*blacktemple-kn*|*blacktempled*) _class="BLACKTEMPLE" ;;
		*xkeen*|*XKeen*|*Xkeen*) _class="XKEEN/OTHER" ;;
		*/opt/etc/xray*|*/opt/bin/xray*|*/opt/sbin/xray*) _class="XKEEN/OTHER" ;;
	esac
	echo "$_class"
}

report_proc() {
	_pid=$1
	echo "--- process ${_pid} ---"
	if [ ! -d "/proc/${_pid}" ]; then
		echo "NOT AVAILABLE: /proc/${_pid}"
		return 0
	fi
	_exe="NOT AVAILABLE"
	if [ -L "/proc/${_pid}/exe" ]; then
		_exe=$(readlink "/proc/${_pid}/exe" 2>/dev/null) || _exe="NOT AVAILABLE"
	fi
	_cmd=""
	if [ -r "/proc/${_pid}/cmdline" ]; then
		_cmd=$(tr '\0' ' ' < "/proc/${_pid}/cmdline" 2>/dev/null)
	fi
	_class=$(classify_proc "${_exe} ${_cmd}")
	echo "pid: ${_pid}"
	echo "exe: ${_exe}" | redact
	echo "cmdline: ${_cmd}" | redact
	echo "class: ${_class}"
	if [ -r "/proc/${_pid}/status" ]; then
		grep -E '^(Name|VmRSS|VmSize|VmSwap|Threads|FDSize):' "/proc/${_pid}/status" 2>/dev/null | redact
	else
		echo "NOT AVAILABLE: /proc/${_pid}/status"
	fi
	if [ -r "/proc/${_pid}/cgroup" ]; then
		echo "cgroup:"
		cat "/proc/${_pid}/cgroup" 2>/dev/null | redact
	else
		echo "NOT AVAILABLE: /proc/${_pid}/cgroup"
	fi
	if [ -r "/proc/${_pid}/smaps_rollup" ]; then
		echo "smaps_rollup:"
		grep -E '^(Rss|Pss|Swap|SwapPss):' "/proc/${_pid}/smaps_rollup" 2>/dev/null | redact
	else
		echo "NOT AVAILABLE: /proc/${_pid}/smaps_rollup"
	fi
}

excerpt_topic_lines() {
	_file=$1
	if [ ! -f "$_file" ] || [ ! -r "$_file" ]; then
		return 0
	fi
	echo "--- excerpt ${_file} ---"
	grep -n -E -i 'iptables|ipset|TPROXY|REDIRECT|MARK|CONNMARK|fwmark|[[:space:]]ip[[:space:]]+rule|[[:space:]]ip[[:space:]]+route|DNS|[[:space:]]53([^0-9]|$)|policy|routing-mark|proxy[[:space:]]*mode' "$_file" 2>/dev/null | head -n 20 | redact || echo "(no matching topic lines)"
}

if [ "${1:-}" = "--cleanup-run-id" ]; then
	btkn_cmd_cleanup "$2"
	exit $?
fi
if [ "${1:-}" = "--cleanup-orphans" ]; then
	btkn_cmd_cleanup_orphans
	exit $?
fi
if [ "${1:-}" = "--selftest-pipeline" ]; then
	BTKN_PROBE_RUN_ID=${BTKN_PROBE_RUN_ID:-pipe-$$}
	export BTKN_PROBE_RUN_ID
	_self=$$
	BTKN_PROBE_CMD_SEC=${BTKN_PROBE_CMD_SEC:-1}
	try_net "selftest-hang-upstream" sleep 120
	_left=0
	for _d in /proc/[0-9]*; do
		_p=${_d#/proc/}
		[ "$_p" = "$_self" ] && continue
		btkn_has_run_id "$_p" "$BTKN_PROBE_RUN_ID" || continue
		_cmd=$(btkn_cmdline "$_p")
		btkn_forbidden_cmd "$_cmd" && continue
		_left=1
	done
	if [ "$_left" -eq 1 ]; then
		echo "PIPELINE_ORPHAN"
		exit 1
	fi
	echo "PIPELINE_CLEAN"
	exit 0
fi
if [ "${1:-}" = "--selftest-hang" ]; then
	BTKN_PROBE_SELFTEST=hang
	export BTKN_PROBE_SELFTEST
	shift
fi
if [ -z "${BTKN_PROBE_WORKER:-}" ]; then
	btkn_supervisor_run "$@"
	exit $?
fi
if [ "${BTKN_PROBE_SELFTEST:-}" = "hang" ]; then
	echo "SELFTEST_HANG pid=$$ run_id=${BTKN_PROBE_RUN_ID}"
	sleep 9999
	exit 0
fi

echo "blacktemple-kn router-probe"
echo "run_id=${BTKN_PROBE_RUN_ID}"
echo "lock=${BTKN_PROBE_LOCKDIR}"
echo "max_sec=${BTKN_PROBE_MAX_SEC}"

# ----- SYSTEM -----
section "SYSTEM"
try "uname -a" uname -a
try "uname -m" uname -m
try "uname -s" uname -s
try "uname -r" uname -r
show_file /proc/version
try "uptime" uptime
if [ -r /proc/device-tree/model ]; then
	show_file /proc/device-tree/model
else
	echo "--- /proc/device-tree/model ---"
	echo "NOT AVAILABLE: /proc/device-tree/model"
fi

# ----- CPU -----
section "CPU"
show_file /proc/cpuinfo

# ----- MEMORY -----
section "MEMORY"
show_file /proc/meminfo
try "free" free
try "free -m" free -m
show_file /proc/loadavg
echo "--- process count ---"
if [ -d /proc ]; then
	_pc=0
	for _pd in /proc/[0-9]*; do
		[ -d "$_pd" ] || continue
		_pc=$((_pc + 1))
	done
	echo "proc_count: ${_pc}"
else
	echo "NOT AVAILABLE: /proc"
fi

# ----- SWAP -----
section "SWAP"
show_file /proc/swaps
show_file /proc/sys/vm/swappiness
show_file /proc/sys/vm/overcommit_memory
show_file /proc/sys/vm/overcommit_ratio
show_file /proc/sys/vm/vfs_cache_pressure
show_file /proc/sys/vm/dirty_ratio
show_file /proc/sys/vm/dirty_background_ratio

# ----- ZRAM / ZSWAP -----
section "ZRAM"
echo "--- /sys/block/zram* ---"
_zram=0
for _z in /sys/block/zram*; do
	if [ -e "$_z" ]; then
		_zram=1
		ls -ld "$_z" 2>&1 | redact
	fi
done
if [ "$_zram" -eq 0 ]; then
	echo "NOT AVAILABLE"
fi
echo "--- zswap enabled ---"
if [ -r /sys/module/zswap/parameters/enabled ]; then
	cat /sys/module/zswap/parameters/enabled 2>&1 | redact
else
	echo "NOT AVAILABLE"
fi

# ----- CGROUP -----
section "CGROUP"
show_file /proc/cgroups
try "mount" mount
show_file /proc/self/cgroup
echo "--- cgroup filesystem ---"
show_dir /sys/fs/cgroup
show_dir /sys/fs/cgroup/memory
echo "--- cgroup version (read-only) ---"
_cgver="NONE"
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
	_cgver="V2"
elif [ -d /sys/fs/cgroup/memory ]; then
	_cgver="V1"
elif [ -r /proc/cgroups ]; then
	if grep -q '^memory' /proc/cgroups 2>/dev/null; then
		_cgver="UNKNOWN"
	fi
fi
echo "cgroup_version: ${_cgver}"
echo "--- memory controller files (read only, never written) ---"
for _f in \
	/sys/fs/cgroup/memory/memory.swappiness \
	/sys/fs/cgroup/memory/memory.limit_in_bytes \
	/sys/fs/cgroup/memory/memory.soft_limit_in_bytes \
	/sys/fs/cgroup/memory/memory.usage_in_bytes \
	/sys/fs/cgroup/memory/memory.stat \
	/sys/fs/cgroup/cgroup.controllers \
	/sys/fs/cgroup/memory.current \
	/sys/fs/cgroup/memory.high \
	/sys/fs/cgroup/memory.max \
	/sys/fs/cgroup/memory.swap.current \
	/sys/fs/cgroup/memory.swap.max \
	/sys/fs/cgroup/memory.stat
do
	show_file "$_f"
done
echo "--- memory controller mounted? ---"
if mount 2>/dev/null | grep -q -e 'cgroup.*memory' -e 'cgroup2'; then
	mount 2>/dev/null | grep -e cgroup | redact
else
	echo "NOT OBSERVED: cgroup memory mount"
fi

# ----- FILESYSTEM -----
section "FILESYSTEM"
try "df" df
try "df -h" df -h
try "mount" mount

# ----- ENTWARE -----
section "ENTWARE"
try "opkg print-architecture" opkg print-architecture
show_file /opt/etc/entware_release
show_file /opt/etc/entware-release
echo "--- /opt ---"
if [ -d /opt ]; then
	echo "dir_exists: /opt"
	ls -ld /opt 2>&1 | redact
else
	echo "NOT AVAILABLE: /opt"
fi

# ----- TOOLS -----
section "TOOLS"
tool_path ip
tool_path iptables
tool_path iptables-save
tool_path ipset
tool_path nft
tool_path xray
tool_path ndmc
tool_path ip6tables
tool_path ss
tool_path netstat

# ----- NETWORK -----
section "NETWORK"
show_file /proc/net/dev
try_net "ip addr" ip addr
try_net "ip -s link" ip -s link
try_net "ip neigh" ip neigh

# ----- ROUTING -----
section "ROUTING"
try_net "ip route" ip route
try_net "ip route show table main" ip route show table main
try_net "ip route show table default" ip route show table default
try_net "ip route show table local" ip route show table local
try_net "ip route show table all" ip route show table all
try_net "ip rule" ip rule
try_net "ip rule list" ip rule list
echo "--- policy tables referenced by ip rule ---"
if have ip; then
	_seen_tbl=" "
	ip rule 2>/dev/null | awk '{
		for (i = 1; i <= NF; i++) {
			if ($i == "lookup" && (i + 1) <= NF) print $(i + 1)
		}
	}' | head -n 12 | while IFS= read -r _tbl; do
		[ -n "$_tbl" ] || continue
		case "$_tbl" in
			unspec|all) continue ;;
		esac
		echo " $_seen_tbl " | grep -q " $_tbl " && continue
		_seen_tbl="${_seen_tbl}${_tbl} "
		try_net "ip route show table ${_tbl}" ip route show table "$_tbl"
	done
else
	echo "NOT AVAILABLE: ip"
fi
try_net "ip -6 route" ip -6 route
try_net "ip -6 rule" ip -6 rule
echo "--- fwmark tokens in ip rule ---"
if have ip; then
	ip rule 2>/dev/null | redact | grep -i -e fwmark -e fwmask || echo "no fwmark in ip rule"
else
	echo "NOT AVAILABLE: ip"
fi

# ----- FIREWALL -----
section "FIREWALL"
try "iptables --version" iptables --version
try "ip6tables --version" ip6tables --version
try "nft list tables" nft list tables
if have ndmc; then
	try "ndmc show version" ndmc -c show version
	try "ndmc show system" ndmc -c show system
else
	echo "--- ndmc ---"
	echo "NOT AVAILABLE: ndmc"
fi

# ----- IPTABLES -----
section "IPTABLES"
try "iptables --version" iptables --version
if have iptables; then
	try_net "iptables -t nat -S" iptables -t nat -S
	try_net "iptables -t mangle -S" iptables -t mangle -S
	try_net "iptables -t filter -S" iptables -t filter -S
	echo "--- iptables-save ---"
	echo "SKIPPED: bounded table -S dumps already collected"
else
	echo "NOT AVAILABLE: iptables"
fi

# ----- IP6TABLES -----
section "IP6TABLES"
try "ip6tables --version" ip6tables --version
if have ip6tables; then
	try_net "ip6tables -t nat -S" ip6tables -t nat -S
	try_net "ip6tables -t mangle -S" ip6tables -t mangle -S
	try_net "ip6tables -t filter -S" ip6tables -t filter -S
else
	echo "NOT AVAILABLE: ip6tables"
fi
show_file /proc/net/ip6_tables_targets
show_file /proc/net/ip6_tables_matches
echo "--- IPv6 XKeen rules (names/targets only; addresses redacted) ---"
echo "see bounded ip6tables -S dumps above (no second full-table scan)"
_xkeen_ip6_nat="SEE_BOUNDED_DUMP"
_xkeen_ip6_mangle="SEE_BOUNDED_DUMP"
_xkeen_ip6_filter="SEE_BOUNDED_DUMP"
echo "xkeen_ipv6_nat: ${_xkeen_ip6_nat}"
echo "xkeen_ipv6_mangle: ${_xkeen_ip6_mangle}"
echo "xkeen_ipv6_filter: ${_xkeen_ip6_filter}"
echo "NOTE: IPv6 dump is evidence only. BlackTemple IPv6 capture remains UNVERIFIED. Not SUPPORTED."

# ----- TARGETS -----
section "TARGETS"
show_file /proc/net/ip_tables_targets
show_file /proc/net/ip_tables_matches
show_file /proc/net/ip6_tables_targets
show_file /proc/net/ip6_tables_matches
echo "--- iptables help (read-only) ---"
if have iptables; then
	iptables -h 2>&1 | redact
else
	echo "NOT AVAILABLE: iptables"
fi
echo "--- TPROXY MARK CONNMARK REDIRECT (read-only evidence) ---"
for _t in TPROXY MARK CONNMARK REDIRECT; do
	_src=""
	if [ -r /proc/net/ip_tables_targets ] && grep -qw "$_t" /proc/net/ip_tables_targets 2>/dev/null; then
		_src="${_src} ip_tables_targets"
	fi
	if [ -r /proc/modules ]; then
		if grep -q "xt_${_t}" /proc/modules 2>/dev/null || grep -q "ipt_${_t}" /proc/modules 2>/dev/null; then
			_src="${_src} proc_modules"
		fi
	fi
	if have lsmod; then
		if lsmod 2>/dev/null | grep -q "xt_${_t}\|ipt_${_t}"; then
			_src="${_src} lsmod"
		fi
	fi
	if have iptables; then
		if iptables -h 2>/dev/null | grep -qw "$_t"; then
			_src="${_src} iptables_help"
		fi
	fi
	if [ -n "$_src" ]; then
		echo "${_t}: PRESENT (${_src} )"
	else
		echo "${_t}: NOT OBSERVED"
	fi
done
echo "--- IPv6 TPROXY MARK CONNMARK REDIRECT (read-only evidence) ---"
for _t in TPROXY MARK CONNMARK REDIRECT; do
	_src=""
	if [ -r /proc/net/ip6_tables_targets ] && grep -qw "$_t" /proc/net/ip6_tables_targets 2>/dev/null; then
		_src="${_src} ip6_tables_targets"
	fi
	if [ -r /proc/modules ]; then
		if grep -q "xt_${_t}" /proc/modules 2>/dev/null || grep -q "ip6t_${_t}" /proc/modules 2>/dev/null; then
			_src="${_src} proc_modules"
		fi
	fi
	if have lsmod; then
		if lsmod 2>/dev/null | grep -q "xt_${_t}\|ip6t_${_t}"; then
			_src="${_src} lsmod"
		fi
	fi
	if have ip6tables; then
		if ip6tables -h 2>/dev/null | grep -qw "$_t"; then
			_src="${_src} ip6tables_help"
		fi
	fi
	if [ -n "$_src" ]; then
		echo "IPv6 ${_t}: PRESENT (${_src} )"
	else
		echo "IPv6 ${_t}: NOT OBSERVED"
	fi
done

# ----- IPSET -----
section "IPSET"
try "ipset version" ipset version
try "ipset list -n" ipset list -n

# ----- TUN -----
section "TUN"
echo "--- /dev/net/tun ---"
if [ -c /dev/net/tun ]; then
	echo "TUN_CHARDEV: PRESENT"
	ls -l /dev/net/tun 2>&1 | redact
else
	echo "TUN_CHARDEV: ABSENT"
fi
echo "--- tun module ---"
if [ -r /proc/modules ] && grep -qw tun /proc/modules 2>/dev/null; then
	echo "tun_module: PRESENT"
	grep -w tun /proc/modules 2>/dev/null | redact
else
	echo "tun_module: NOT OBSERVED"
fi

# ----- KERNEL -----
section "KERNEL"
show_file /proc/sys/net/ipv4/ip_forward
show_file /proc/sys/net/ipv6/conf/all/forwarding
show_file /proc/sys/net/ipv4/conf/all/rp_filter
show_file /proc/sys/net/ipv4/conf/all/route_localnet
try "sysctl net.ipv4.ip_forward" sysctl net.ipv4.ip_forward
show_file /proc/sys/fs/file-max

# ----- MODULES -----
section "MODULES"
show_file /proc/modules
try "lsmod" lsmod
echo "--- capture-related modules ---"
if [ -r /proc/modules ]; then
	grep -i -e tproxy -e redirect -e 'xt_mark' -e connmark -e '^tun' -e ip_set -e xt_set -e nf_tproxy /proc/modules 2>/dev/null | redact || echo "no matching modules"
else
	echo "NOT AVAILABLE: /proc/modules"
fi

# ----- DNS -----
section "DNS"
show_file /etc/resolv.conf
show_file /tmp/resolv.conf
show_file /opt/etc/resolv.conf
show_dir /opt/etc/ndm
show_dir /opt/etc/ndm/netfilter.d
show_dir /opt/etc/ndm/fs.d
show_dir /opt/etc/dnsmasq.d
show_dir /opt/etc/xkeen
echo "--- DNS-related processes ---"
if have ps; then
	ps w 2>/dev/null | redact | grep -i -e dnsmasq -e ndnproxy -e unbound -e dnscrypt -e xkeen -e adguard || echo "no matching DNS processes"
else
	echo "NOT AVAILABLE: ps"
fi
echo "--- who listens on TCP 53 / UDP 53 ---"
_dns_tcp="NOT OBSERVED"
_dns_udp="NOT OBSERVED"
if have netstat; then
	try_net "netstat -lnt" netstat -lnt
	try_net "netstat -lnu" netstat -lnu
	_dns_tcp="SEE_BOUNDED_DUMP"
	_dns_udp="SEE_BOUNDED_DUMP"
elif have ss; then
	try_net "ss -lnt" ss -lnt
	try_net "ss -lnu" ss -lnu
	_dns_tcp="SEE_BOUNDED_DUMP"
	_dns_udp="SEE_BOUNDED_DUMP"
else
	echo "NOT AVAILABLE: netstat/ss"
fi
echo "tcp53_listener: ${_dns_tcp}"
echo "udp53_listener: ${_dns_udp}"
echo "--- DNS service hints (process names only) ---"
_keen_dns="NOT OBSERVED"
_adg="NOT OBSERVED"
_other_dns="NOT OBSERVED"
if have ps; then
	_ps=$(ps w 2>/dev/null)
	echo "$_ps" | redact | grep -i -e ndnproxy -e 'dnsmasq' >/dev/null && _keen_dns="PRESENT"
	echo "$_ps" | redact | grep -i adguard >/dev/null && _adg="PRESENT"
	echo "$_ps" | redact | grep -i -e unbound -e dnscrypt -e named -e 'systemd-resolve' >/dev/null && _other_dns="PRESENT"
fi
echo "keenetic_dns_hint: ${_keen_dns}"
echo "adguard_hint: ${_adg}"
echo "other_dns_hint: ${_other_dns}"

# ----- XRAY -----
section "XRAY"
tool_path xray
echo "--- known xray paths ---"
for _p in /opt/blacktemple-kn/bin/xray /opt/bin/xray /opt/sbin/xray /usr/bin/xray; do
	if [ -e "$_p" ]; then
		ls -l "$_p" 2>&1 | redact
	else
		echo "NOT AVAILABLE: ${_p}"
	fi
done
show_dir /opt/etc/xray
show_dir /opt/etc/xray/configs
echo "--- xray processes (path/args; configs not dumped) ---"
if have ps; then
	ps w 2>/dev/null | redact | grep -i xray || echo "no xray process"
else
	echo "NOT AVAILABLE: ps"
fi
echo "--- per-PID xray / blacktempled (classified; not every pidof) ---"
_xray_pids=0
for _d in /proc/[0-9]*; do
	[ -d "$_d" ] || continue
	_pid=${_d#/proc/}
	_name=""
	[ -r "${_d}/comm" ] && _name=$(cat "${_d}/comm" 2>/dev/null)
	_cmd=""
	[ -r "${_d}/cmdline" ] && _cmd=$(tr '\0' ' ' < "${_d}/cmdline" 2>/dev/null)
	_exe=""
	[ -L "${_d}/exe" ] && _exe=$(readlink "${_d}/exe" 2>/dev/null)
	case "${_name} ${_cmd} ${_exe}" in
		*xray*|*Xray*|*XRAY*|*blacktempled*)
			report_proc "$_pid"
			_xray_pids=$((_xray_pids + 1))
			;;
	esac
done
if [ "$_xray_pids" -eq 0 ]; then
	echo "no xray/blacktempled /proc pids"
fi
if have xray; then
	echo "--- xray version ---"
	xray version 2>&1 | redact
	xray -version 2>&1 | redact
else
	echo "--- xray version ---"
	echo "NOT AVAILABLE: xray"
fi
echo "--- xray-related chains (names only via existing list) ---"
echo "see bounded iptables -S dumps above"

# ----- XKEEN -----
section "XKEEN"
tool_path xkeen
echo "--- xkeen coexistence (Linux process/path/dir/chains/DNS/ports; no xkeen pbr) ---"
for _p in /opt/etc/xkeen /opt/sbin/xkeen /opt/bin/xkeen /opt/etc/xray/configs; do
	if [ -e "$_p" ]; then
		echo "exists: ${_p}"
		ls -ld "$_p" 2>&1 | redact
	else
		echo "NOT AVAILABLE: ${_p}"
	fi
done
echo "--- xkeen version/help (read-only flags only) ---"
if have xkeen; then
	try "xkeen -v" xkeen -v
	try "xkeen -h" xkeen -h
else
	echo "NOT AVAILABLE: xkeen"
fi
if have ps; then
	echo "--- xkeen processes ---"
	ps w 2>/dev/null | redact | grep -i xkeen || echo "no xkeen process"
	echo "--- xray args (may belong to xkeen) ---"
	ps w 2>/dev/null | redact | grep -i xray || echo "no xray process"
else
	echo "NOT AVAILABLE: ps"
fi
echo "--- xkeen-related chains ---"
echo "see bounded iptables -S dumps above"
_xkeen_nat="SEE_BOUNDED_DUMP"
_xkeen_mangle="SEE_BOUNDED_DUMP"
echo "--- xkeen DNS hooks (dir listing) ---"
show_dir /opt/etc/xkeen
show_dir /opt/etc/ndm/netfilter.d
echo "--- xkeen init/hook topic excerpts (limited lines; not a full dump) ---"
_nexcerpt=0
_hook_stop=0
for _hookdir in /opt/etc/xkeen /opt/etc/ndm/netfilter.d /opt/etc/ndm/fs.d /opt/etc/init.d /opt/etc/xray; do
	[ -d "$_hookdir" ] || continue
	for _hf in "$_hookdir"/*; do
		[ -f "$_hf" ] || continue
		_base=$(echo "$_hf" | grep -i -e xkeen -e xray -e tproxy -e redirect || true)
		# Always scan xkeen dirs; elsewhere only name-matched files.
		case "$_hookdir" in
			*/xkeen*|*/netfilter.d|*/fs.d)
				:
				;;
			*)
				[ -n "$_base" ] || continue
				;;
		esac
		_nexcerpt=$((_nexcerpt + 1))
		if [ "$_nexcerpt" -gt 12 ]; then
			echo "(further hook files skipped)"
			_hook_stop=1
			break
		fi
		excerpt_topic_lines "$_hf"
	done
	[ "${_hook_stop:-0}" -eq 1 ] && break
done
echo "--- xkeen-related listen ports ---"
if have netstat; then
	try_net "netstat -lntup" netstat -lntup
elif have ss; then
	try_net "ss -lntup" ss -lntup
else
	echo "NOT AVAILABLE: netstat/ss"
fi
echo "--- XKeen capability summary (observed only) ---"
_xk_inst="NO"
if have xkeen || [ -e /opt/sbin/xkeen ] || [ -e /opt/bin/xkeen ] || [ -d /opt/etc/xkeen ]; then
	_xk_inst="YES"
fi
echo "XKeen installed: ${_xk_inst}"
echo "version: see xkeen -v above or UNKNOWN"
_xk_xray="UNKNOWN"
for _p in /opt/sbin/xray /opt/bin/xray /opt/etc/xray; do
	if [ -e "$_p" ]; then
		_xk_xray=$_p
		break
	fi
done
echo "Xray path: ${_xk_xray}"
if [ -d /opt/etc/xray/configs ]; then
	echo "Xray config dir: /opt/etc/xray/configs"
elif [ -d /opt/etc/xray ]; then
	echo "Xray config dir: /opt/etc/xray"
else
	echo "Xray config dir: UNKNOWN"
fi
echo "capture hints: UNKNOWN until topic excerpts/iptables names reviewed"
echo "DNS interception hints: UNKNOWN"
echo "PBR/mark hints: UNKNOWN"
echo "own chains: nat=${_xkeen_nat} mangle=${_xkeen_mangle}"
echo "own IPv6 chains: nat=${_xkeen_ip6_nat:-UNKNOWN} mangle=${_xkeen_ip6_mangle:-UNKNOWN} filter=${_xkeen_ip6_filter:-UNKNOWN}"
echo "own ports: see listen lines"
echo "Entware traffic handling hints: UNKNOWN"
echo "IPv6 capture (BlackTemple): UNVERIFIED"

# ----- INIT -----
section "INIT"
show_dir /opt/etc/init.d
show_dir /etc/init.d
echo "--- init names matching xray/xkeen/blacktemple ---"
if [ -d /opt/etc/init.d ]; then
	ls /opt/etc/init.d 2>/dev/null | grep -i -e xray -e xkeen -e blacktemple -e btkn || echo "no matching init names"
else
	echo "NOT AVAILABLE: /opt/etc/init.d"
fi

# ----- LIMITS -----
section "LIMITS"
echo "--- ulimit -a ---"
if have ulimit; then
	ulimit -a 2>&1 | redact
else
	# ulimit is usually a shell builtin
	ulimit -a 2>&1 | redact
fi
show_file /proc/sys/fs/file-nr
show_file /proc/sys/fs/file-max

# ----- SOCKETS -----
section "SOCKETS"
try_net "netstat -lntup" netstat -lntup
try_net "ss -lntup" ss -lntup
try_net "netstat -ln" netstat -ln

# ----- BASELINE -----
section "BASELINE"
echo "--- pre-BlackTemple resource snapshot ---"
if [ -r /proc/meminfo ]; then
	grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null | redact
else
	echo "NOT AVAILABLE: /proc/meminfo"
fi
show_file /proc/loadavg
echo "--- /opt free ---"
if have df; then
	df /opt 2>&1 | redact
	df -h /opt 2>&1 | redact
else
	echo "NOT AVAILABLE: df"
fi
echo "--- process count ---"
echo "proc_count: ${_pc:-UNKNOWN}"
echo "--- current Xray RSS/VmSwap (classified pids) ---"
_saw_xray=0
for _d in /proc/[0-9]*; do
	[ -d "$_d" ] || continue
	_pid=${_d#/proc/}
	_name=""
	[ -r "${_d}/comm" ] && _name=$(cat "${_d}/comm" 2>/dev/null)
	case "$_name" in
		xray|Xray)
			_saw_xray=1
			echo "pid ${_pid}:"
			grep -E '^(VmRSS|VmSwap):' "${_d}/status" 2>/dev/null | redact
			;;
	esac
done
if [ "$_saw_xray" -eq 0 ]; then
	echo "no comm=xray processes"
fi

# ----- PACKAGE-PROVENANCE -----
section "PACKAGE-PROVENANCE"
echo "read-only opkg status/files/search only; never update/install/remove"
if have opkg; then
	for _pkg in ip-full iptables ipset ca-bundle; do
		echo "--- opkg status ${_pkg} ---"
		opkg status "$_pkg" 2>&1 | redact || echo "NOT AVAILABLE: ${_pkg}"
		echo "--- opkg files ${_pkg} ---"
		opkg files "$_pkg" 2>&1 | redact || echo "NOT AVAILABLE: files ${_pkg}"
	done
	for _p in /opt/sbin/ip /opt/sbin/iptables /opt/sbin/ipset /opt/bin/ip /opt/bin/iptables /opt/bin/ipset; do
		echo "--- opkg search ${_p} ---"
		if [ -e "$_p" ]; then
			opkg search "$_p" 2>&1 | redact || echo "NOT AVAILABLE: search ${_p}"
		else
			echo "NOT AVAILABLE: ${_p}"
		fi
	done
else
	echo "NOT AVAILABLE: opkg"
fi
echo "NOTE: ca-bundle listed for provenance only. BlackTemple Go TLS does not depend on system CA bundle."

# ----- MODULE-PROVENANCE -----
section "MODULE-PROVENANCE"
_kver=$(uname -r 2>/dev/null)
echo "uname -r: ${_kver:-UNKNOWN}"
echo "search roots only: /lib/modules/\$kver /lib/system-modules/\$kver /opt/lib/modules /opt/lib/system-modules/\$kver"
for _root in "/lib/modules/${_kver}" "/lib/system-modules/${_kver}" "/opt/lib/modules" "/opt/lib/system-modules/${_kver}"; do
	echo "--- ${_root} ---"
	if [ -d "$_root" ]; then
		ls -l "$_root" 2>&1 | redact | grep -i -e tproxy -e socket -e mark -e connmark -e redirect -e xt_set -e addrtype -e conntrack || echo "(no matching module files in this root)"
	else
		echo "NOT AVAILABLE: ${_root}"
	fi
done
echo "loaded capture-related modules (from /proc/modules; not an install):"
if [ -r /proc/modules ]; then
	grep -i -e tproxy -e redirect -e 'xt_mark' -e connmark -e xt_socket -e xt_set -e addrtype -e conntrack /proc/modules 2>/dev/null | redact || echo "no matching loaded modules"
	echo "--- nf_tproxy_ipv4 / xt_TPROXY loaded? ---"
	grep -E -i '^(xt_TPROXY|nf_tproxy_ipv4|xt_tproxy)[[:space:]]' /proc/modules 2>/dev/null | redact || echo "nf_tproxy_ipv4/xt_TPROXY: NOT OBSERVED in /proc/modules"
else
	echo "NOT AVAILABLE: /proc/modules"
fi
echo "--- command -v modprobe ---"
if command -v modprobe >/dev/null 2>&1; then
	echo "MODPROBE: PRESENT"
	command -v modprobe 2>/dev/null | redact
else
	echo "MODPROBE: NOT AVAILABLE"
fi
echo "--- exact module filenames (read-only; not loaded) ---"
for _base in xt_TPROXY.ko nf_tproxy_ipv4.ko xt_socket.ko xt_mark.ko xt_MARK.ko xt_connmark.ko xt_CONNMARK.ko xt_REDIRECT.ko ipt_REDIRECT.ko xt_set.ko xt_addrtype.ko xt_conntrack.ko; do
	_found=0
	for _root in "/lib/modules/${_kver}" "/lib/system-modules/${_kver}" "/opt/lib/modules" "/opt/lib/system-modules/${_kver}"; do
		_p="${_root}/${_base}"
		if [ -e "$_p" ]; then
			_found=1
			echo "FOUND: ${_p}"
			ls -l "$_p" 2>&1 | redact
			if [ -L "$_p" ]; then
				echo "SYMLINK: YES ${_p}"
			else
				echo "SYMLINK: NO ${_p}"
			fi
		fi
	done
	if [ "$_found" -eq 0 ]; then
		echo "NOT OBSERVED: ${_base}"
	fi
done

# ----- SUMMARY -----
section "SUMMARY"
_swap_present="NO"
_swap_size="0"
_swap_used="0"
if [ -r /proc/swaps ]; then
	_swap_n=$(awk 'NR>1 && $1 != "" {c++} END {print c+0}' /proc/swaps 2>/dev/null)
	if [ "${_swap_n:-0}" -gt 0 ]; then
		_swap_present="YES"
	fi
	_swap_size=$(awk 'NR>1 {s+=$3} END {print s+0}' /proc/swaps 2>/dev/null)
	_swap_used=$(awk 'NR>1 {s+=$4} END {print s+0}' /proc/swaps 2>/dev/null)
fi
_swappiness="NOT AVAILABLE"
[ -r /proc/sys/vm/swappiness ] && _swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null)
_zram_yn="NO"
for _z in /sys/block/zram*; do
	[ -e "$_z" ] && _zram_yn="YES"
done
_zswap_yn="NO"
if [ -r /sys/module/zswap/parameters/enabled ]; then
	_zs=$(cat /sys/module/zswap/parameters/enabled 2>/dev/null)
	if [ "$_zs" = "Y" ] || [ "$_zs" = "1" ]; then
		_zswap_yn="YES"
	else
		_zswap_yn="NO"
	fi
fi
_memcg="NONE"
_memcg_mounted="NO"
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
	_memcg="V2"
	if grep -qw memory /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
		_memcg_mounted="YES"
	fi
elif [ -d /sys/fs/cgroup/memory ]; then
	_memcg="V1"
	_memcg_mounted="YES"
fi
_per_swap="UNKNOWN"
if [ -r /sys/fs/cgroup/memory/memory.swappiness ]; then
	_per_swap="YES"
elif [ -r /sys/fs/cgroup/memory.swap.max ]; then
	_per_swap="YES"
elif [ "$_memcg" = "NONE" ]; then
	_per_swap="NO"
fi
echo "Swap present: ${_swap_present}"
echo "Swap size: ${_swap_size}"
echo "Swap used: ${_swap_used}"
echo "Swappiness: ${_swappiness}"
echo "ZRAM: ${_zram_yn}"
echo "ZSWAP: ${_zswap_yn}"
echo "Memory cgroup: ${_memcg}"
echo "memory controller mounted: ${_memcg_mounted}"
echo "Per-process swap control possible: ${_per_swap}"
echo "tcp53_listener: ${_dns_tcp:-UNKNOWN}"
echo "udp53_listener: ${_dns_udp:-UNKNOWN}"
echo "NOTE: TPROXY/REDIRECT/MARK in iptables help is PRESENT/NOT OBSERVED, not SUPPORTED"
echo "IPv6 capture (BlackTemple): UNVERIFIED (see IP6TABLES dump; not a capture path proof)"

echo ""
echo "===== END ====="
echo "probe complete (read-only)"
btkn_finish
exit 0
