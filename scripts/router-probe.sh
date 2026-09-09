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
	| redact_ip | redact_ip6
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

redact_ip6() {
	# Redact global IPv6; keep loopback, link-local, ULA, multicast.
	# Skip HH:MM:SS (two colons, no ::) to avoid clobbering timestamps.
	if ! command -v awk >/dev/null 2>&1; then
		cat
		return 0
	fi
	awk '
		function colons(s,   n, i) {
			n = 0
			for (i = 1; i <= length(s); i++) {
				if (substr(s, i, 1) == ":") n++
			}
			return n
		}
		function local_ip6(ip,   n, cidr) {
			n = tolower(ip)
			gsub(/\[|\]/, "", n)
			cidr = ""
			if (match(n, /\/[0-9]+$/)) {
				cidr = substr(n, RSTART)
				n = substr(n, 1, RSTART - 1)
			}
			if (n == "::" || n == "::1") return 1
			# Prefix-only link-local / ULA / multicast; host IIDs are redacted.
			if (n == "fe80::" && cidr != "") return 1
			if (n == "fc00::" || n == "fd00::" || n == "ff00::") return 1
			return 0
		}
		{
			rest = $0
			out = ""
			while (match(rest, /\[?[0-9A-Fa-f:]+\]?(\/[0-9]+)?/)) {
				tok = substr(rest, RSTART, RLENGTH)
				c = colons(tok)
				keep = 0
				if (c < 2) keep = 1
				else if (c == 2 && index(tok, "::") == 0) keep = 1
				else if (local_ip6(tok)) keep = 1
				out = out substr(rest, 1, RSTART - 1)
				if (keep) out = out tok
				else out = out "[REDACTED-IP6]"
				rest = substr(rest, RSTART + RLENGTH)
			}
			print out rest
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

# ----- IP6TABLES -----
section "IP6TABLES"
try "ip6tables --version" ip6tables --version
if have ip6tables; then
	echo "--- ip6tables -t nat -S ---"
	ip6tables -t nat -S 2>&1 | redact
	echo "--- ip6tables -t mangle -S ---"
	ip6tables -t mangle -S 2>&1 | redact
	echo "--- ip6tables -t filter -S ---"
	ip6tables -t filter -S 2>&1 | redact
else
	echo "NOT AVAILABLE: ip6tables"
fi
show_file /proc/net/ip6_tables_targets
show_file /proc/net/ip6_tables_matches
echo "--- IPv6 XKeen rules (names/targets only; addresses redacted) ---"
_xkeen_ip6_nat="NOT OBSERVED"
_xkeen_ip6_mangle="NOT OBSERVED"
_xkeen_ip6_filter="NOT OBSERVED"
if have ip6tables; then
	if ip6tables -t nat -S 2>/dev/null | grep -i -e xkeen -e XKEEN >/dev/null; then
		_xkeen_ip6_nat="PRESENT"
		ip6tables -t nat -S 2>&1 | redact | grep -i -e xkeen -e XKEEN | xkeen_ipv6_names_targets
	else
		echo "no xkeen tokens in ip6tables nat"
	fi
	if ip6tables -t mangle -S 2>/dev/null | grep -i -e xkeen -e XKEEN >/dev/null; then
		_xkeen_ip6_mangle="PRESENT"
		ip6tables -t mangle -S 2>&1 | redact | grep -i -e xkeen -e XKEEN | xkeen_ipv6_names_targets
	else
		echo "no xkeen tokens in ip6tables mangle"
	fi
	if ip6tables -t filter -S 2>/dev/null | grep -i -e xkeen -e XKEEN >/dev/null; then
		_xkeen_ip6_filter="PRESENT"
		ip6tables -t filter -S 2>&1 | redact | grep -i -e xkeen -e XKEEN | xkeen_ipv6_names_targets
	else
		echo "no xkeen tokens in ip6tables filter"
	fi
else
	echo "NOT AVAILABLE: ip6tables"
fi
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
	echo "--- netstat -lnt (TCP) :53 ---"
	netstat -lnt 2>/dev/null | redact | grep -E '[:.]53[[:space:]]' || echo "no TCP :53"
	echo "--- netstat -lnu (UDP) :53 ---"
	netstat -lnu 2>/dev/null | redact | grep -E '[:.]53[[:space:]]' || echo "no UDP :53"
	echo "--- netstat -lntup :53 ---"
	netstat -lntup 2>/dev/null | redact | grep -E '[:.]53[[:space:]]' || echo "no :53 lines"
	if netstat -lnt 2>/dev/null | grep -E '[:.]53[[:space:]]' >/dev/null; then
		_dns_tcp="PRESENT"
	fi
	if netstat -lnu 2>/dev/null | grep -E '[:.]53[[:space:]]' >/dev/null; then
		_dns_udp="PRESENT"
	fi
elif have ss; then
	echo "--- ss -lnt :53 ---"
	ss -lnt 2>/dev/null | redact | grep -E '[:.]53[[:space:]]' || echo "no TCP :53"
	echo "--- ss -lnu :53 ---"
	ss -lnu 2>/dev/null | redact | grep -E '[:.]53[[:space:]]' || echo "no UDP :53"
	echo "--- ss -lntup :53 ---"
	ss -lntup 2>/dev/null | redact | grep -E '[:.]53[[:space:]]' || echo "no :53 lines"
	if ss -lnt 2>/dev/null | grep -E '[:.]53[[:space:]]' >/dev/null; then
		_dns_tcp="PRESENT"
	fi
	if ss -lnu 2>/dev/null | grep -E '[:.]53[[:space:]]' >/dev/null; then
		_dns_udp="PRESENT"
	fi
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
_xkeen_nat="NOT OBSERVED"
_xkeen_mangle="NOT OBSERVED"
if have iptables; then
	if iptables -t nat -S 2>/dev/null | grep -i -e xkeen -e XKEEN >/dev/null; then
		_xkeen_nat="PRESENT"
		iptables -t nat -S 2>&1 | redact | grep -i -e xkeen -e XKEEN
	else
		echo "no xkeen tokens in nat"
	fi
	if iptables -t mangle -S 2>/dev/null | grep -i -e xkeen -e XKEEN >/dev/null; then
		_xkeen_mangle="PRESENT"
		iptables -t mangle -S 2>&1 | redact | grep -i -e xkeen -e XKEEN
	else
		echo "no xkeen tokens in mangle"
	fi
	iptables -t filter -S 2>&1 | redact | grep -i -e xkeen -e XKEEN || echo "no xkeen tokens in filter"
else
	echo "NOT AVAILABLE: iptables"
fi
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
	netstat -lntup 2>&1 | redact | grep -i -e xray -e xkeen || echo "no xray/xkeen listen lines"
elif have ss; then
	ss -lntup 2>&1 | redact | grep -i -e xray -e xkeen || echo "no xray/xkeen listen lines"
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
try "netstat -lntup" netstat -lntup
try "ss -lntup" ss -lntup
try "netstat -ln" netstat -ln

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
else
	echo "NOT AVAILABLE: /proc/modules"
fi

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
exit 0
