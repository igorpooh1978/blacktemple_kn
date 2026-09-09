#!/bin/sh
# Executable process-safety acceptance for scripts/router-probe.sh.
# Linux /proc required. Invoked by TestProbeExecutableProcessSafety.
# Does not talk to KN-1011.

set -eu

PROBE=${1:-}
if [ -z "$PROBE" ]; then
	echo "usage: probe_safety_exec.sh /path/to/router-probe.sh" >&2
	exit 2
fi
if [ ! -f "$PROBE" ]; then
	echo "missing probe script: $PROBE" >&2
	exit 2
fi

FAIL=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAIL=1; }

WORKDIR=$(mktemp -d /tmp/btkn-psafety.XXXXXX)
cleanup_all() {
	if [ -n "${HANG_PID:-}" ]; then
		kill -KILL "$HANG_PID" 2>/dev/null || true
	fi
	if [ -n "${DECOY_PID:-}" ]; then
		kill -KILL "$DECOY_PID" 2>/dev/null || true
	fi
	if [ -n "${WRONG_PID:-}" ]; then
		kill -KILL "$WRONG_PID" 2>/dev/null || true
	fi
	if [ -n "${XRAY_PID:-}" ]; then
		kill -KILL "$XRAY_PID" 2>/dev/null || true
	fi
	if [ -n "${STALE_PID:-}" ]; then
		kill -KILL "$STALE_PID" 2>/dev/null || true
	fi
	if [ -n "${REUSE_PID:-}" ]; then
		kill -KILL "$REUSE_PID" 2>/dev/null || true
	fi
	rm -rf "$WORKDIR"
}
trap cleanup_all EXIT INT TERM

count_run_id() {
	_id=$1
	_n=0
	for _d in /proc/[0-9]*; do
		[ -r "${_d}/environ" ] || continue
		cat "${_d}/environ" 2>/dev/null | tr '\0' '\n' | grep -q "^BTKN_PROBE_RUN_ID=${_id}$" || continue
		_n=$((_n + 1))
	done
	echo "$_n"
}

alive() {
	[ -n "$1" ] && [ -d "/proc/$1" ]
}

cmdline_of() {
	tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null || true
}

# --- D: foreign similar cmdline must survive --cleanup-orphans (name-only is forbidden)
DECOY_PID=""
sh -c 'sleep 120; # btkn-router-probe.sh' &
DECOY_PID=$!
sleep 0.2
if ! alive "$DECOY_PID"; then
	fail "D decoy did not start"
else
	_out=$(BTKN_PROBE_GRACE_SEC=1 sh "$PROBE" --cleanup-orphans 2>/dev/null || true)
	sleep 1
	if alive "$DECOY_PID"; then
		if echo "$_out" | grep -q 'FOREIGN_OR_UNKNOWN_PROCESS\|REMOTE_PROCESS_NOT_FOUND\|TIMEOUT_CLEANED\|ALREADY_RUNNING'; then
			pass "D foreign similar-cmdline survives name-only cleanup"
		else
			pass "D foreign similar-cmdline survives (--cleanup-orphans output unrecognised but decoy alive)"
		fi
	else
		fail "D foreign similar-cmdline was killed by --cleanup-orphans"
	fi
	kill -KILL "$DECOY_PID" 2>/dev/null || true
	DECOY_PID=""
fi

# --- E: wrong run_id survives --cleanup-run-id
WRONG_PID=""
BTKN_PROBE_RUN_ID=foreign-run-id sleep 120 &
WRONG_PID=$!
sleep 0.2
if ! alive "$WRONG_PID"; then
	fail "E wrong-run-id decoy did not start"
else
	sh "$PROBE" --cleanup-run-id "ours-run-id" >/dev/null 2>&1 || true
	sleep 1
	if alive "$WRONG_PID"; then
		pass "E wrong-run-id process survives"
	else
		fail "E process with wrong run_id was killed"
	fi
	kill -KILL "$WRONG_PID" 2>/dev/null || true
	WRONG_PID=""
fi

# --- F: xray-like foreign process survives
XRAY_DIR=$WORKDIR/bin
mkdir -p "$XRAY_DIR"
printf '%s\n' '#!/bin/sh' 'exec sleep 120' > "$XRAY_DIR/xray"
chmod +x "$XRAY_DIR/xray"
XRAY_PID=""
"$XRAY_DIR/xray" &
XRAY_PID=$!
sleep 0.2
if ! alive "$XRAY_PID"; then
	fail "F xray-like decoy did not start"
else
	sh "$PROBE" --cleanup-orphans >/dev/null 2>&1 || true
	sh "$PROBE" --cleanup-run-id "xray-should-not-match" >/dev/null 2>&1 || true
	sleep 1
	if alive "$XRAY_PID"; then
		pass "F xray-like foreign process survives"
	else
		fail "F xray-like process was killed"
	fi
	kill -KILL "$XRAY_PID" 2>/dev/null || true
	XRAY_PID=""
fi

# Isolated lock for remaining scenarios
export BTKN_PROBE_LOCKDIR="$WORKDIR/lock"
export BTKN_PROBE_GRACE_SEC=1
export BTKN_PROBE_CMD_SEC=1

# --- H: stale lock with live foreign PID reuse
REUSE_PID=""
sleep 120 &
REUSE_PID=$!
sleep 0.2
mkdir "$BTKN_PROBE_LOCKDIR" 2>/dev/null || true
{
	echo "run_id=stale-reuse"
	echo "pid=${REUSE_PID}"
	echo "script=${PROBE}"
	echo "cmdline=sleep 120"
} > "$BTKN_PROBE_LOCKDIR/meta"
_hout=$(BTKN_PROBE_MAX_SEC=2 BTKN_PROBE_SELFTEST=hang sh "$PROBE" --selftest-hang 2>/dev/null || true)
if echo "$_hout" | grep -q FOREIGN_OR_UNKNOWN_PROCESS; then
	if alive "$REUSE_PID"; then
		pass "H stale lock PID reuse is FOREIGN_OR_UNKNOWN_PROCESS and not killed"
	else
		fail "H FOREIGN printed but reused PID was killed"
	fi
else
	fail "H expected FOREIGN_OR_UNKNOWN_PROCESS, got: $(echo "$_hout" | tr '\n' ' ')"
	if ! alive "$REUSE_PID"; then
		fail "H reused PID was killed"
	fi
fi
kill -KILL "$REUSE_PID" 2>/dev/null || true
REUSE_PID=""
rm -rf "$BTKN_PROBE_LOCKDIR"

# --- A: two concurrent probes, one winner
export BTKN_PROBE_LOCKDIR="$WORKDIR/lock-a"
export BTKN_PROBE_MAX_SEC=8
HANG_PID=""
BTKN_PROBE_RUN_ID=run-a BTKN_PROBE_SELFTEST=hang sh "$PROBE" --selftest-hang >"$WORKDIR/a.out" 2>&1 &
HANG_PID=$!
_i=0
while [ "$_i" -lt 20 ]; do
	if grep -q SELFTEST_HANG "$WORKDIR/a.out" 2>/dev/null; then
		break
	fi
	if grep -q ALREADY_RUNNING "$WORKDIR/a.out" 2>/dev/null; then
		break
	fi
	sleep 0.2
	_i=$((_i + 1))
done
_bout=$(BTKN_PROBE_RUN_ID=run-b BTKN_PROBE_SELFTEST=hang BTKN_PROBE_MAX_SEC=2 sh "$PROBE" --selftest-hang 2>/dev/null || true)
if echo "$_bout" | grep -q ALREADY_RUNNING; then
	if grep -q SELFTEST_HANG "$WORKDIR/a.out" 2>/dev/null; then
		pass "A single-instance: one winner, second ALREADY_RUNNING"
	else
		fail "A second ALREADY_RUNNING but first did not print SELFTEST_HANG"
	fi
else
	fail "A second probe did not print ALREADY_RUNNING: $(echo "$_bout" | tr '\n' ' ')"
fi

# --- B: hard timeout kills worker tree, lock gone, run_id count 0
kill -KILL "$HANG_PID" 2>/dev/null || true
wait "$HANG_PID" 2>/dev/null || true
HANG_PID=""
rm -rf "$BTKN_PROBE_LOCKDIR"
export BTKN_PROBE_LOCKDIR="$WORKDIR/lock-b"
export BTKN_PROBE_MAX_SEC=2
BTKN_PROBE_RUN_ID=run-timeout BTKN_PROBE_SELFTEST=hang sh "$PROBE" --selftest-hang >"$WORKDIR/b.out" 2>&1 || true
sleep 1
_bjoin=$(cat "$WORKDIR/b.out" 2>/dev/null || true)
_left=$(count_run_id run-timeout)
if echo "$_bjoin" | grep -q TIMEOUT; then
	if [ ! -d "$BTKN_PROBE_LOCKDIR" ] && [ "$_left" -eq 0 ]; then
		pass "B hard-timeout: TIMEOUT, lock removed, owned run_id count 0"
	else
		fail "B TIMEOUT printed but lock_exists=$( [ -d "$BTKN_PROBE_LOCKDIR" ] && echo yes || echo no ) owned=$_left"
	fi
else
	fail "B expected TIMEOUT from supervisor, got: $(echo "$_bjoin" | tr '\n' ' ')"
fi
rm -rf "$BTKN_PROBE_LOCKDIR"

# --- C: hanging pipeline: upstream and redactor gone
export BTKN_PROBE_LOCKDIR="$WORKDIR/lock-c"
_cout=$(BTKN_PROBE_RUN_ID=run-pipe BTKN_PROBE_CMD_SEC=1 sh "$PROBE" --selftest-pipeline 2>/dev/null || true)
_pleft=$(count_run_id run-pipe)
if echo "$_cout" | grep -q PIPELINE_CLEAN; then
	if [ "$_pleft" -eq 0 ]; then
		pass "C hanging pipeline: upstream and redactor gone"
	else
		fail "C PIPELINE_CLEAN but run_id leftovers=$_pleft"
	fi
else
	fail "C expected PIPELINE_CLEAN, leftovers=$_pleft output=$(echo "$_cout" | tr '\n' ' ')"
fi
rm -rf "$BTKN_PROBE_LOCKDIR"

# --- G: stale valid run_id is cleaned, new probe starts
export BTKN_PROBE_LOCKDIR="$WORKDIR/lock-g"
export BTKN_PROBE_MAX_SEC=8
STALE_PID=""
BTKN_PROBE_RUN_ID=run-stale BTKN_PROBE_SELFTEST=hang sh "$PROBE" --selftest-hang >"$WORKDIR/g1.out" 2>&1 &
STALE_PID=$!
_i=0
while [ "$_i" -lt 20 ]; do
	if grep -q SELFTEST_HANG "$WORKDIR/g1.out" 2>/dev/null; then
		break
	fi
	sleep 0.2
	_i=$((_i + 1))
done
# SIGKILL supervisor and recorded worker so EXIT traps do not run
if [ -n "$STALE_PID" ]; then
	_wpid=$(sed -n 's/^pid=//p' "$BTKN_PROBE_LOCKDIR/meta" 2>/dev/null | head -n 1)
	kill -KILL "$STALE_PID" 2>/dev/null || true
	if [ -n "$_wpid" ] && [ "$_wpid" != "$$" ]; then
		kill -KILL "$_wpid" 2>/dev/null || true
	fi
	wait "$STALE_PID" 2>/dev/null || true
fi
STALE_PID=""
# leftover sleeper with the same run_id (orphaned after SIGKILL of parent)
BTKN_PROBE_RUN_ID=run-stale sleep 120 &
_orphan=$!
sleep 0.2
_gout=$(BTKN_PROBE_RUN_ID=run-new BTKN_PROBE_SELFTEST=hang BTKN_PROBE_MAX_SEC=3 sh "$PROBE" --selftest-hang 2>/dev/null || true)
sleep 0.5
if echo "$_gout" | grep -q SELFTEST_HANG; then
	if alive "$_orphan"; then
		fail "G new probe started but stale run_id orphan still alive"
		kill -KILL "$_orphan" 2>/dev/null || true
	else
		pass "G stale valid run_id cleaned and new probe started"
	fi
else
	fail "G new probe did not start after stale lock: $(echo "$_gout" | tr '\n' ' ')"
	kill -KILL "$_orphan" 2>/dev/null || true
fi
# stop the new hang if it won
for _d in /proc/[0-9]*; do
	[ -r "${_d}/environ" ] || continue
	_p=${_d#/proc/}
	cat "${_d}/environ" 2>/dev/null | tr '\0' '\n' | grep -q "^BTKN_PROBE_RUN_ID=run-new$" || continue
	kill -KILL "$_p" 2>/dev/null || true
done
rm -rf "$BTKN_PROBE_LOCKDIR"

if [ "$FAIL" -ne 0 ]; then
	echo "RESULT: FAIL"
	exit 1
fi
echo "RESULT: PASS"
exit 0
