# QEMU MIPSLE integration lab

**QEMU ≠ KN-1011.** This lab is an automatic **MIPS little-endian** integration gate on QEMU **Malta** (`qemu-system-mipsel -machine malta`). It is **not** a MediaTek MT7621 emulator, not Keenetic NDM, not hardware offload, and not a Keenetic firewall.

A green QEMU job is **not** hardware PASS.

The lab is **experimental**. Failures fail the job. There is no silent skip of failing qemu tests.

## Pin

Lock file: [`openwrt.lock.json`](openwrt.lock.json)

| Field | Value |
| --- | --- |
| OpenWrt | 24.10.8 (pinned, not latest) |
| Target | `malta/le` |
| Architecture | mipsel (little-endian) |
| Machine | `malta` |
| CPU in QEMU | 24Kc |
| Kernel | `openwrt-24.10.8-malta-le-vmlinux-initramfs.elf` |
| SHA256 | `78407e58231a82de3d8b0ef0f1ae52209487548bb3fdd2e37559681b08951553` |
| Upstream | https://downloads.openwrt.org/releases/24.10.8/targets/malta/le/ |
| sha256sums | https://downloads.openwrt.org/releases/24.10.8/targets/malta/le/sha256sums |

Verified against the official `sha256sums` file on 2026-09-08. Boot method matches OpenWrt `target/linux/malta/README`:

```text
qemu-system-mipsel -kernel openwrt-malta-le-vmlinux-initramfs.elf -nographic -m 256
```

Overlay base (optional qcow2, golden image never mutated): `openwrt-24.10.8-malta-le-rootfs-ext4.img.gz`.

## What this proves (when QEMU is installed)

- MIPSLE executable runs on Malta
- `blacktempled` starts and `/health` responds (guest loopback)
- Xray MIPSLE `version`, `run -test`, start/stop/restart
- Service lifecycle inside the guest
- Geodata **path** `/opt/blacktemple-kn/share/geodata` is writable (no geo engine, no GPL dat in CI)
- Basic networking: WAN = QEMU user NAT, LAN/test isolated, hostfwd only on `127.0.0.1`

## What this does not prove

- MT7621 performance or cycle accuracy
- Keenetic NDM
- Hardware offload
- Keenetic firewall hooks
- Entware / `mipsel-3.4_kn` (OpenWrt opkg on Malta is not Entware)

## Network isolation

- Default: no tap/bridge, no production LAN
- WAN: QEMU user-mode NAT
- LAN: user-mode `restrict=on` plus SSH/health hostfwd bound to `127.0.0.1`
- `-AllowHostLAN` / `-allow-host-lan` is an explicit opt-in that **still does not** attach tap/bridge to the physical LAN

## Windows (`lab.ps1`)

From the repo root:

```powershell
.\lab.ps1 -Action test
.\lab.ps1 -Action prepare
.\lab.ps1 -Action smoke -Daemon .\out\bin\blacktempled-mipsle -Xray .\out\xray-p0\xray
```

`CGO_ENABLED=0`. The script does **not** install QEMU.

If `qemu-system-mipsel` is missing:

```text
QEMU_NOT_INSTALLED
```

Install it yourself:

- Official Windows builds: https://www.qemu.org/download/#windows → https://qemu.weilnetz.de/w64/
- winget (verified in `microsoft/winget-pkgs`): `winget install --id SoftwareFreedomConservancy.QEMU`

Cache: `.cache/qemu/` (gitignored). Blobs are not committed.

## Tests

```powershell
go test ./lab/...
```

Unit tests cover lock validation, incomplete lock, SHA mismatch, missing QEMU, boot timeout, SSH timeout. Live boot is a separate `smoke` action.

## CI

`.github/workflows/qemu.yml` on `ubuntu-latest`, pinned image, cache, timeout. Experimental, not disabled. Does not download GPL geodata.
