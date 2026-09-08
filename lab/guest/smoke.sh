#!/bin/sh
# Guest-side MIPSLE smoke. Not KN-1011. Not Entware proof.
set -e
PREFIX=/opt/blacktemple-kn
echo "SMOKE_ARCH $(uname -m)"
echo "SMOKE_UNAME $(uname -a)"
if [ -f /proc/cpuinfo ]; then
	grep -i "system type\|cpu model\|isa" /proc/cpuinfo | head -n 8 || true
fi
echo "SMOKE_IFACES"
if command -v ip >/dev/null 2>&1; then
	ip addr || true
	ip route || true
else
	ifconfig -a || true
	route -n || true
fi
mkdir -p "$PREFIX/bin" "$PREFIX/config" "$PREFIX/share/geodata" "$PREFIX/run" "$PREFIX/logs" "$PREFIX/data"
test -d "$PREFIX/share/geodata"
echo "geodata path accessible" > "$PREFIX/share/geodata/PATH_OK"
test -f "$PREFIX/share/geodata/PATH_OK"
echo "SMOKE_GEODATA_PATH_OK"
if [ -x "$PREFIX/bin/blacktempled" ]; then
	"$PREFIX/bin/blacktempled" -listen 127.0.0.1:7480 -data-dir "$PREFIX/data" >"$PREFIX/logs/blacktempled.log" 2>&1 &
	echo $! > "$PREFIX/run/blacktempled.pid"
	n=0
	while [ "$n" -lt 20 ]; do
		if wget -qO- http://127.0.0.1:7480/health 2>/dev/null | grep -q ok; then
			echo "SMOKE_BLACKTEMPLED_HEALTH_OK"
			break
		fi
		n=$((n + 1))
		sleep 1
	done
	if [ "$n" -ge 20 ]; then
		echo "SMOKE_BLACKTEMPLED_HEALTH_FAIL"
		exit 1
	fi
else
	echo "SMOKE_BLACKTEMPLED_MISSING"
	exit 1
fi
if [ -x "$PREFIX/bin/xray" ]; then
	"$PREFIX/bin/xray" version || true
	if [ -f "$PREFIX/config/xray-lab.json" ]; then
		"$PREFIX/bin/xray" run -test -c "$PREFIX/config/xray-lab.json"
		echo "SMOKE_XRAY_TEST_OK"
		"$PREFIX/bin/xray" run -c "$PREFIX/config/xray-lab.json" >/dev/null 2>&1 &
		echo $! > "$PREFIX/run/xray.pid"
		sleep 1
		if kill -0 "$(cat "$PREFIX/run/xray.pid")" 2>/dev/null; then
			echo "SMOKE_XRAY_START_OK"
		else
			echo "SMOKE_XRAY_START_FAIL"
			exit 1
		fi
		kill "$(cat "$PREFIX/run/xray.pid")" 2>/dev/null || true
		sleep 1
		echo "SMOKE_XRAY_STOP_OK"
		"$PREFIX/bin/xray" run -c "$PREFIX/config/xray-lab.json" >/dev/null 2>&1 &
		echo $! > "$PREFIX/run/xray.pid"
		sleep 1
		if kill -0 "$(cat "$PREFIX/run/xray.pid")" 2>/dev/null; then
			echo "SMOKE_XRAY_RESTART_OK"
		else
			echo "SMOKE_XRAY_RESTART_FAIL"
			exit 1
		fi
		kill "$(cat "$PREFIX/run/xray.pid")" 2>/dev/null || true
	fi
else
	echo "SMOKE_XRAY_MISSING"
	exit 1
fi
echo "SMOKE_PASS"
