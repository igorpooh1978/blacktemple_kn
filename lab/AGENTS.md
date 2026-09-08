# lab/

QEMU **Malta** MIPSLE integration lab.

**QEMU ≠ KN-1011.** This is not an MT7621 emulator. Do not report QEMU PASS as KN-1011 PASS. Do not claim Keenetic NDM, hardware offload, or Keenetic firewall hooks.

Pinned image: `openwrt.lock.json` (OpenWrt `malta/le`, little-endian). Not floating `latest`.

Images, qcow2, and `.cache` stay gitignored.

Live smoke is **experimental**. Missing `qemu-system-mipsel` is `QEMU_NOT_INSTALLED` / `NOT RUN`, not a fake PASS.

Do not download GPL geodata in CI.
