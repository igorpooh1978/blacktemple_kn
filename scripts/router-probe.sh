#!/bin/sh
# Read-only KN-1011 capability probe (POSIX / BusyBox).
# Best-effort: a missing tool prints NOT AVAILABLE and the probe continues.
# Does not mutate routing, firewall, sysctl, packages, or processes.

echo "blacktemple-kn router-probe"
echo "mode=read-only"
echo "shell=$0"

redact() {
	# Strip MAC, UUID, SSID, URL, key-shaped values, and public IPs from stdin.
	if ! command -v sed >/dev/null 2>&1; then
		cat
		return 0
	fi
	sed \
		-e 's/[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]/[REDACTED-MAC]/g' \
		-e 's/[0-9a-fA-F]\{8\}-[0-9a-fA-F]\{4\}-[0-9a-fA-F]\{4\}-[0-9a-fA-F]\{4\}-[0-9a-fA-F]\{12\}/[REDACTED-UUID]/g' \
		-e 's/[Ss][Ss][Ii][Dd]="[^"]*"/ssid="[REDACTED-SSID]"/g' \
		-e 's/[Ss][Ss][Ii][Dd]=[^[:space:]]*/ssid=[REDACTED-SSID]/g' \
		-e 's/[Ee][Ss][Ss][Ii][Dd][: ][^[:space:]]*/ESSID:[REDACTED-SSID]/g' \
		-e 's/\(password\|passwd\|privateKey\|publicKey\|accessKey\|secret\|token\|uuid\)":[[:space:]]*"[^"]*"/\1":"[REDACTED]"/g' \
		-e 's/[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^[:space:]"'\'']*/[REDACTED-URL]/g' \
	| redact_ip
}

redact_ip() {
	if ! command -v awk >/dev/null 2>&1; then
		cat
		return 0
	fi
	awk '
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
		{
			rest = $0
			out = ""
			while (match(rest, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
				out = out substr(rest, 1, RSTART - 1)
				ip = substr(rest, RSTART, RLENGTH)
				if (private_ip(ip)) out = out ip
				else out = out "[REDACTED-IP]"
				rest = substr(rest, RSTART + RLENGTH)
			}
			print out rest
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
try "ip addr" ip addr
try "ip -s link" ip -s link
try "ip neigh" ip neigh

# ----- ROUTING -----
section "ROUTING"
try "ip route" ip route
try "ip route show table main" ip route show table main
try "ip route show table default" ip route show table default
try "ip route show table local" ip route show table local
try "ip route show table all" ip route show table all
try "ip rule" ip rule
try "ip rule list" ip rule list
echo "--- policy tables referenced by ip rule ---"
if have ip; then
	ip rule 2>/dev/null | awk '{
		for (i = 1; i <= NF; i++) {
			if ($i == "lookup" && (i + 1) <= NF) print $(i + 1)
		}
	}' | while IFS= read -r _tbl; do
		[ -n "$_tbl" ] || continue
		echo "--- ip route show table ${_tbl} ---"
		ip route show table "$_tbl" 2>&1 | redact
	done
else
	echo "NOT AVAILABLE: ip"
fi
try "ip -6 route" ip -6 route
try "ip -6 rule" ip -6 rule
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
	echo "--- iptables -t nat -S ---"
	iptables -t nat -S 2>&1 | redact
	echo "--- iptables -t mangle -S ---"
	iptables -t mangle -S 2>&1 | redact
	echo "--- iptables -t filter -S ---"
	iptables -t filter -S 2>&1 | redact
	echo "--- iptables-save ---"
	if have iptables-save; then
		iptables-save 2>&1 | redact
	else
		echo "NOT AVAILABLE: iptables-save"
	fi
else
	echo "NOT AVAILABLE: iptables"
fi

# ----- TARGETS -----
section "TARGETS"
show_file /proc/net/ip_tables_targets
show_file /proc/net/ip_tables_matches
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
	ps w 2>/dev/null | redact | grep -i -e dnsmasq -e ndnproxy -e unbound -e dnscrypt -e xkeen || echo "no matching DNS processes"
else
	echo "NOT AVAILABLE: ps"
fi

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
if have xray; then
	echo "--- xray version ---"
	xray version 2>&1 | redact
	xray -version 2>&1 | redact
else
	echo "--- xray version ---"
	echo "NOT AVAILABLE: xray"
fi
echo "--- xray-related chains (names only via existing list) ---"
if have iptables; then
	iptables -t nat -S 2>&1 | redact | grep -i -e xray -e XRAY -e BTKN_ || echo "no xray/BTKN_ tokens in nat"
	iptables -t mangle -S 2>&1 | redact | grep -i -e xray -e XRAY -e BTKN_ || echo "no xray/BTKN_ tokens in mangle"
	iptables -t filter -S 2>&1 | redact | grep -i -e xray -e XRAY -e BTKN_ || echo "no xray/BTKN_ tokens in filter"
else
	echo "NOT AVAILABLE: iptables"
fi

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
if have ps; then
	echo "--- xkeen processes ---"
	ps w 2>/dev/null | redact | grep -i xkeen || echo "no xkeen process"
	echo "--- xray args (may belong to xkeen) ---"
	ps w 2>/dev/null | redact | grep -i xray || echo "no xray process"
else
	echo "NOT AVAILABLE: ps"
fi
echo "--- xkeen-related chains ---"
if have iptables; then
	iptables -t nat -S 2>&1 | redact | grep -i -e xkeen -e XKEEN || echo "no xkeen tokens in nat"
	iptables -t mangle -S 2>&1 | redact | grep -i -e xkeen -e XKEEN || echo "no xkeen tokens in mangle"
	iptables -t filter -S 2>&1 | redact | grep -i -e xkeen -e XKEEN || echo "no xkeen tokens in filter"
else
	echo "NOT AVAILABLE: iptables"
fi
echo "--- xkeen DNS hooks (dir listing only) ---"
show_dir /opt/etc/xkeen
show_dir /opt/etc/ndm/netfilter.d
echo "--- xkeen-related listen ports ---"
if have netstat; then
	netstat -lntup 2>&1 | redact | grep -i -e xray -e xkeen || echo "no xray/xkeen listen lines"
elif have ss; then
	ss -lntup 2>&1 | redact | grep -i -e xray -e xkeen || echo "no xray/xkeen listen lines"
else
	echo "NOT AVAILABLE: netstat/ss"
fi

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
try "netstat -lntup" netstat -lntup
try "ss -lntup" ss -lntup
try "netstat -ln" netstat -ln

echo ""
echo "===== END ====="
echo "probe complete (read-only)"
exit 0
