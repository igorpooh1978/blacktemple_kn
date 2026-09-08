# Geodata source candidates

Status of every row: **NOT SELECTED**. `SourceEnabled()` is **NO**.
This file is research notes only. No license or redistribution conclusion.

Observed APK identifiers (Loyalsoldier / runetfreedom / Chocolate4U) map to the
public GitHub repositories below. Names like `*-blacktemple-rules-dat` were
**not** confirmed as separate canonical upstreams.

Fetched 2026-09-08 (GitHub API + project README). Sizes are of the files present
on that date and will change.

## Loyalsoldier/v2ray-rules-dat

| Field | Observation |
| --- | --- |
| URL | https://github.com/Loyalsoldier/v2ray-rules-dat |
| License (GitHub SPDX) | GPL-3.0 |
| Release model | GitHub Releases; tag like `202609072354`; README: GitHub Actions daily ~06:00 CST |
| DAT compatibility | README: drop-in `geoip.dat` / `geosite.dat` for V2Ray, Xray-core, mihomo, hysteria, Trojan-Go, leaf |
| Size (release 202609072354) | geoip.dat 17120329 bytes; geosite.dat 10968988 bytes |
| Update frequency | Daily automated release (project claim) |
| Checksums | Sidecar `geoip.dat.sha256sum` / `geosite.dat.sha256sum` on the same release |
| Supply-chain | Public GitHub Actions artifacts; floating `latest` and jsDelivr `@release`; no pin in this tree |
| Enabled | **NO** |

## runetfreedom/russia-v2ray-rules-dat

| Field | Observation |
| --- | --- |
| URL | https://github.com/runetfreedom/russia-v2ray-rules-dat |
| License (GitHub SPDX) | GPL-3.0 |
| Release model | `release` branch overwrite (not a dated GitHub Release for the DAT pair); README: every 6 hours |
| DAT compatibility | README: V2Ray / Xray-core / v2rayN / mihomo / others; includes v2fly domain-list-community categories plus `ru-blocked*` |
| Size (`release` branch 2026-09-08) | geoip.dat 18567967 bytes; geosite.dat 73703302 bytes |
| Update frequency | Every 6 hours (project claim) |
| Checksums | `geoip.dat.sha256sum` / `geosite.dat.sha256sum` on the `release` branch |
| Supply-chain | Aggregates antifilter.download / re:filter / related lists via sibling repos; floating branch head; KN-1011 flash: ~73 MiB geosite is large vs default 32 MiB manager cap |
| Enabled | **NO** |

## Chocolate4U/Iran-v2ray-rules

| Field | Observation |
| --- | --- |
| URL | https://github.com/Chocolate4U/Iran-v2ray-rules |
| License (GitHub SPDX) | GPL-3.0 (README: project except upstream sources) |
| Release model | `release` branch plus GitHub Releases; workflow publishes DAT + MMDB + sha256sum |
| DAT compatibility | README: v2ray/xray `geoip.dat` / `geosite.dat`; also lite DAT and MaxMind MMDB (MMDB is not used by this manager) |
| Size (`release` branch 2026-09-08) | geoip.dat 17001343 bytes; geosite.dat 7660766 bytes |
| Update frequency | GitHub Actions cadence (observed daily-ish releases historically) |
| Checksums | `geoip.dat.sha256sum` / `geosite.dat.sha256sum` on the `release` branch |
| Supply-chain | Builds with Loyalsoldier geoip tooling + v2fly domain-list-community; floating `release` / `latest` |
| Enabled | **NO** |

## Manager policy

- No default download URL.
- Install is local-file only (size limit, SHA256, Validator, atomic replace).
- Official Xray-core geoip/geosite are a separate upstream; not bundled here.
