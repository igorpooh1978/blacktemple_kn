# KN-1011 capabilities (read-only probe)

Status: **RUN** (2026-09-09). Raw dump is gitignored: `.research-local/hardware/kn1011-probe-20260909-091721.txt`.

This file is sanitized. No LAN/WAN addresses, MACs, SSIDs, UUIDs, passwords, Xray JSON bodies, or subscription URLs.

Probe did not mutate iptables, policy routing, sysctl, packages, or processes. TPROXY/REDIRECT/MARK/TUN below are **PRESENT / NOT OBSERVED** evidence only — not `SUPPORTED`, not an engine choice. ADR-009 remains **UNKNOWN**.

## Device (observed)

| Item | Evidence |
| --- | --- |
| Kernel | `4.9-ndm-5` (`Linux version 4.9-ndm-5`, gcc 14.3.0 crosstool-NG, SMP Fri Aug 14 2026) |
| SoC | `MediaTek MT7621 SoC` (`/proc/cpuinfo` `system type`) |
| CPU | 4× `MIPS 1004Kc V2.15`, `isa` includes `mips32r2` |
| `uname -m` | `mips` |
| RAM | `MemTotal: 513828 kB`, `MemAvailable` ≈ 353–354 MB at probe time |
| Root | squashfs `/dev/root` 15.0M 100% full |
| Entware | `Entware 2025.05`, `arch mipsel-3.4_kn`, glibc 2.27, `/opt` on USB ext4 |
| nft | **NOT AVAILABLE** |
| iptables | `/opt/sbin/iptables` (also `ip6tables v1.4.21`) |
| ipset | **PRESENT** (`ipset v7.24`; kernel protocol 6 vs userspace 6–7 warning) |

## ROUTING MATRIX

| Capability | Result | Evidence |
| --- | --- | --- |
| IPv4 forward | YES | `/proc/sys/net/ipv4/ip_forward` = `1` |
| IPv6 forward | YES | `/proc/sys/net/ipv6/conf/all/forwarding` = `1` |
| `rp_filter` (all) | 0 | `/proc/sys/net/ipv4/conf/all/rp_filter` |
| `route_localnet` (all) | 1 | `/proc/sys/net/ipv4/conf/all/route_localnet` |
| Policy routing | PRESENT | `ip rule`: fwmark `0x111` → table `111`; fwmark `0xffffaaa` → table `4096` then blackhole |
| Table 111 | PRESENT | `local default dev lo table 111 scope host` (typical TPROXY divert) |
| Table 4096 | PRESENT | default via WAN iface + LAN scopes (addresses redacted) |
| `ipset` | PRESENT | NDM sets plus XKeen `xkeen_deny_mac`, `geo_exclude`, `geo_override`, `user_exclude`, `ext_exclude` (+ v6 twins) |
| nftables | NOT AVAILABLE | `nft` missing; live path is iptables/xtables |
| BTKN_ chains | NOT OBSERVED | no `xray`/`BTKN_` tokens in nat/mangle/filter |

Default route lives on WAN VLAN iface (`eth3.3` in dump). LAN bridges `br0`/`br1` present. Addresses omitted.

## FIREWALL / CAPTURE EVIDENCE (not an engine pick)

| Target / device | Probe label | Notes |
| --- | --- | --- |
| TPROXY | **PRESENT** | `/proc/net/ip_tables_targets`, `xt_TPROXY` in `lsmod` (refcount 2), live mangle `xkeen` UDP `-j TPROXY --on-port 1181 --on-ip 127.0.0.1 --tproxy-mark 0x111` |
| REDIRECT | **PRESENT** | target list + live nat `xkeen` TCP `-j REDIRECT --to-ports 1181`; Keenetic `_NDM_DNS_FLT_REDIR` REDIRECT DNS ports on `br0`/`br1` |
| MARK / CONNMARK | **PRESENT** | targets + live UDP `MARK 0x111` / `CONNMARK`; policy mark `0xffffaaa` on PREROUTING |
| `xt_socket` | PRESENT | `lsmod` refcount 2; UDP path uses `-m socket --transparent` |
| TUN chardev | **PRESENT** | `/dev/net/tun` `crw-rw-rw-` 10,200 |
| `tun` module | **NOT OBSERVED** | `tun_module: NOT OBSERVED` |
| Live XKeen capture split | OBSERVED | hook excerpt: `network_redirect='tcp'`, `network_tproxy='udp'`, both ports `1181` |

Do **not** read PRESENT as SUPPORTED for BlackTemple. Capture engine is **not** selected here.

## DNS MATRIX

| Item | Result | Evidence |
| --- | --- | --- |
| TCP :53 listener | PRESENT | `ndnproxy` (`pid 524`) on `0.0.0.0:53` and `[::]:53` |
| UDP :53 listener | PRESENT | same `ndnproxy` |
| Keenetic DNS | PRESENT | `/usr/sbin/ndnproxy` (main + Policy0); `keenetic_dns_hint: PRESENT` |
| AdGuard | NOT OBSERVED | `adguard_hint: NOT OBSERVED` |
| Stub resolver | 127.0.0.1 | `/etc/resolv.conf` nameserver loopback |
| LAN DNS REDIRECT | PRESENT | `_NDM_DNS_FLT_REDIR` UDP/TCP 53, 5353, 1253 → same local ports on `br0`/`br1` |
| Hotspot DNS REDIRECT | PRESENT | `_NDM_HOTSPOT_DNSREDIR` UDP/TCP 53 → port `41100` (LAN addrs omitted) |
| XKeen DNS intercept | OFF (config excerpt) | `/opt/etc/ndm/netfilter.d/proxy.sh`: `file_dns='false'`, `proxy_dns='off'` |
| XKeen `-dns` CLI | listed in `-h` | **not executed** (forbidden mutating flag) |

## SWAP MATRIX

| Item | Result | Evidence |
| --- | --- | --- |
| Swap present | YES | `/proc/swaps`: `/dev/sda1` partition |
| Swap size | 2097148 (kB in `/proc/swaps`) | ~2 GiB; `SwapTotal: 2097148 kB` |
| Swap used | 0 | `SwapFree` equals `SwapTotal`; `/proc/swaps` Used=0 |
| Swappiness | 60 | `/proc/sys/vm/swappiness` |
| ZRAM | NO | no `/sys/block/zram*` |
| ZSWAP | NO | zswap enabled node NOT AVAILABLE |
| USB layout | OBSERVED | `sda1` swap, `sda2` ext4 mounted as `/opt` (~54.6G, ~1% used) |

## CGROUP MATRIX

| Item | Result | Evidence |
| --- | --- | --- |
| `/proc/cgroups` | NOT AVAILABLE | |
| `/proc/self/cgroup` | NOT AVAILABLE | |
| `/sys/fs/cgroup` | NOT AVAILABLE | |
| cgroup version | NONE | probe `cgroup_version: NONE` |
| Memory cgroup | NONE | SUMMARY: `Memory cgroup: NONE` |
| memory controller mounted | NO | |
| Per-process swap control | NO | no memory.swappiness / memory.swap.max |

Mounts observed: squashfs root, tmpfs `/tmp`, ubifs `/storage`, ext4 USB `/opt`. No cgroup mount.

## XRAY RESOURCE BASELINE

| Item | Result |
| --- | --- |
| BlackTemple xray | NOT AVAILABLE (`/opt/blacktemple-kn/bin/xray` missing) |
| `/opt/bin/xray` | NOT AVAILABLE |
| Live xray | `/opt/sbin/xray`, cmdline `xray run`, **class: XKEEN/OTHER** |
| PID | 25942 |
| VmRSS | 54460 kB |
| VmSize | 601020 kB |
| VmSwap | 0 kB |
| Threads | 13 |
| Version | `Xray 26.7.28` `go1.26.5 linux/mipsle` |
| Listen (XKeen inbound) | TCP/UDP `1181` (process xray); `xkeen-ui` TCP `1000` |
| Load / procs at baseline | loadavg ~1.20 1.37 0.88; `proc_count: 134` |

Xray JSON under `/opt/etc/xray/configs/` exists; contents not copied into git.

## XKEEN EVIDENCE

| Item | Result |
| --- | --- |
| Installed | YES (`/opt/sbin/xkeen`, `/opt/etc/xkeen`) |
| `xkeen -v` | `XKeen 2.0 Stable`, build `2026-06-06 08:53:30 MSK`; Xray `26.7.28` (Russian UI text mojibake in Windows capture; ASCII tokens unambiguous) |
| Init | `/opt/etc/init.d/S05xkeen`, `S99xkeen-ui` |
| Hook | `/opt/etc/ndm/netfilter.d/proxy.sh` (22369 bytes) |
| Chains | nat + mangle chain `xkeen`; comments `xkeen_rule` |
| TCP capture | REDIRECT → 1181 |
| UDP capture | TPROXY → 1181, mark `0x111` |
| Policy mark | `0xffffaaa` (PREROUTING + `ip rule`) |
| Private nets excluded | RFC1918 / loopback / link-local / broadcast in `xkeen` chain (plus redacted extra prefixes) |
| Help flags **not** run | `-dns`, `-pr`, `-ipv6`, `-pbr` (and other mutators) |
| BlackTemple coexistence | no BTKN_ chains; do not touch `/opt/sbin/xray` or XKeen hooks |

## MEMORY (for later routing design)

Evidence only, no engine or cgroup policy chosen:

- ~502 MiB RAM; at probe ~354 MiB available; one XKeen Xray already ~53 MiB RSS / ~587 MiB VSZ.
- ~2 GiB disk swap idle; swappiness 60; **no** memory cgroup to isolate Xray swap.
- Large USB `/opt` (not overlay RAM).

## Commands actually run

```powershell
.\router-smoke.ps1 -Mode Probe
```

Runner loaded gitignored `.env` (not committed). Copy used `ssh cat` because remote SFTP (`/opt/libexec/sftp-server`) is absent. Password was not placed on the ssh argv.

Remote: `sh /tmp/btkn-router-probe.sh` (read-only).

## Not done

- KN-1011 smoke hardware gate (`-Mode Smoke`) still unimplemented (exit 2).
- No iptables/TPROXY/TUN applied by BlackTemple.
- No TrafficCaptureEngine selection.
- R6 not started.
- No merge to `main`.
