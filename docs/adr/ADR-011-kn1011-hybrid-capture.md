# ADR-011: KN-1011 hybrid-iptables capture

## Status

Accepted (R6)

## Context

ADR-009 defined `TrafficCaptureEngine` with candidates `transparent-iptables` and `xray-tun`, and left the first choice **UNKNOWN** until KN-1011 evidence. That ADR is not edited here.

R5.1 read-only probe on KN-1011 is merged. Hardware evidence SHA:

```text
90379f924d1bca60366423217701ff8e590b502e
```

Sanitized probe: `docs/hardware/kn-1011-capabilities.md` (2026-09-09). Observed:

| Item | Evidence |
| --- | --- |
| Kernel | `4.9-ndm-5` |
| SoC | MT7621 |
| RAM | 513828 kB |
| Entware | `/opt` on USB ext4 |
| iptables | `/opt/sbin/iptables` (xtables) |
| nft | **NOT AVAILABLE** |
| ipset | **PRESENT** |
| IPv4 / IPv6 forwarding | `1` |
| cgroup | **NONE** |
| swappiness | `60` |
| DNS | `ndnproxy` `:53`; XKeen `proxy_dns=off` |
| XKeen | 2.0 Stable owns TCP **REDIRECT** + UDP **TPROXY** port **1181**, mark `0x111`, policy `0xffffaaa`, table `111` |

`blackTempleHardwareSmoke`: **NOT RUN**. Capability labels remain PRESENT / OBSERVED, not `SUPPORTED`.

## Decision

### Engine

```text
captureEngine: hybrid-iptables
selection: SELECTED_BY_HARDWARE_EVIDENCE
backend: iptables/xtables
```

KN-1011 split (IPv4):

| Traffic | Mechanism |
| --- | --- |
| IPv4 TCP | REDIRECT |
| IPv4 UDP | TPROXY |

- **TUN** is fallback, not primary. Do not install a userspace TUN path as the default capture.
- **nft** is not available; do not generate nftables rules.
- **Mihomo** is not used.
- IPv4 hybrid = **SELECTED**. IPv6 capture = **UNVERIFIED**. Never globally disable IPv6.

### Ports, marks, table

BlackTemple must never use XKeen's port **1181**.

| Item | Value |
| --- | --- |
| Capture port | **11820** |
| TPROXY mark | `0x42544b4e/0xffffffff` (ASCII-ish `BTKN`) |
| Policy table | `4254` |
| Reserved bypass mark | `0x42544b4f` (unused unless a later wave needs it) |

### Chains and ipsets

Own chains only (`BTKN_` prefix). Never `-F` foreign tables. Never modify XKeen chains.

```text
BTKN_PRE
BTKN_TCP
BTKN_UDP
BTKN_OUT   (reserved; not required for first smoke)
```

```text
btkn_clients_v4
btkn_exclude_v4
```

### DNS

DNS interception is a **later stage**. First smoke DNS mode:

```text
KEENETIC_DIRECT
```

This is **not** `DNS_LEAK_FREE`. Do not intercept `:53` / `ndnproxy` in R6.

`DNSCaptureEngine` is a **seam only** in this wave (interface / stub). Not implemented.

### Fail-open and XKeen coexistence

Default crash / capture-failure policy: **fail-open** (no kill switch as default).

XKeen coexistence: **conflict detected, never modified**.

| Call | Behavior when XKeen capture is present |
| --- | --- |
| `Plan` / `DryRun` / `Preflight` | allowed (read / compute only) |
| `Apply()` | must return `ErrExistingCaptureEngine` |

Production `blacktempled` **never** stops XKeen. Only the M harness may pause/stop XKeen, and only behind **dual gates**. This wave does **not** start R6-I (live `Apply` on KN-1011).

### First smoke (when a later wave runs it)

Not run in this orchestration commit.

- One explicit client: `BTKN_TEST_CLIENT_IPV4` (in `btkn_clients_v4`)
- Private / RFC1918: **DIRECT**
- Public IPv4: via BlackTemple Xray (port 11820)
- DNS: `KEENETIC_DIRECT`

### Memory

`Memory` mode **AUTO** leaves Keenetic `vm.swappiness=60`. Do not run `sysctl -w vm.swappiness`.

`GOMEMLIMIT` research is allowed later; it is **not** a default.

cgroup is NONE on this device; do not assume memory.swappiness / memory.swap.max.

### UI (do not edit `web/` in this wave)

User-facing control: **«Маршрутизация / Автоматически»**.

Advanced diagnostics may later show:

```text
Engine Hybrid
TCP/UDP
DNS Keenetic
IPv6 проверяется
```

Stream G does not implement that in R6.

### Contract name vs runtime name

Frozen `contracts/schemas/config.schema.json` `capture.engine` enum remains:

```text
unspecified | transparent-iptables | xray-tun
```

Runtime / ADR name is `hybrid-iptables`. This wave does **not** rewrite the frozen schema. Gap: `.ai/reports/r6-contract-gap-capture-engine.md`. Suggested later mapping: add enum value `hybrid-iptables`, or treat `transparent-iptables` as an alias for this hybrid.

## Consequences

- R6 parallel streams: O (this ADR + orchestration), C (Xray inbounds on 11820), D (hybrid planner / Preflight; `Apply` refuses XKeen), F (`packaging/keenetic/**` + platform), M (dual-gate harness scaffolding).
- R6-I (live Apply) is **not** started by agent O. Next step is **ORCHESTRATOR REVIEW**, not R6-I.
- Do not write `SUPPORTED` for capture, TCP REDIRECT, UDP TPROXY, or protocols until `blackTempleHardwareSmoke` PASSes on KN-1011.
- ADR-009 remains historically UNKNOWN at freeze time; **this** ADR is the selection record.
