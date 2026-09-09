# R6 parallel scope

Wave R6 is parallel streams **O, C, D, F, M**. Merge is **not** authorized.

`captureEngine` is **hybrid-iptables**, `SELECTED_BY_HARDWARE_EVIDENCE` (ADR-011). Evidence SHA `90379f924d1bca60366423217701ff8e590b502e`. Live smoke **NOT RUN**. Do not write `SUPPORTED`.

Next recommended step: **ORCHESTRATOR REVIEW**. R6-I (live `Apply`) is **not** started.

## Agents

| Agent | Branch | Worktree | Owns |
| --- | --- | --- | --- |
| O | `agent/r6/orchestration` | `blacktemple_kn-wt/r6-orchestration` | ADR-011, manifest, ownership, task files, reports |
| C | `agent/r6/xray-engine` | `blacktemple_kn-wt/r6-xray-engine` | Xray generator inbounds on port **11820** |
| D | `agent/r6/routing-capture` | `blacktemple_kn-wt/r6-routing-capture` | hybrid-iptables Plan/DryRun/Preflight; `Apply` → `ErrExistingCaptureEngine` if XKeen |
| F | `agent/r6/service-keenetic` | `blacktemple_kn-wt/r6-service-keenetic` | `packaging/keenetic/**`, `packaging/init/**`, `src/internal/platform/**`, supervisor |
| M | `agent/r6/kn1011-harness` | `blacktemple_kn-wt/r6-kn1011-harness` | `router-smoke.ps1`, `scripts/router-*.sh`, `docs/hardware/**` |

Not in wave: A, B, E, G, H, I, J, K, L.

## Frozen decisions (do not re-open)

- IPv4 TCP = REDIRECT, IPv4 UDP = TPROXY, backend = iptables/xtables
- TUN = fallback, not primary
- nft = not available
- Mihomo not used
- DNS first smoke = `KEENETIC_DIRECT` (not `DNS_LEAK_FREE`); no DNS intercept this wave
- `DNSCaptureEngine` = seam only
- fail-open default
- XKeen conflict detected, never modified
- BlackTemple port **11820** (never 1181)
- TPROXY mark `0x42544b4e/0xffffffff`, table `4254`
- Memory AUTO leaves swappiness=60; no `sysctl -w vm.swappiness`
- Production daemon never stops XKeen; only M harness with dual gates (not executed this wave)

## Contract gap

`contracts/schemas/config.schema.json` `capture.engine` enum is still `unspecified|transparent-iptables|xray-tun`. Runtime name is `hybrid-iptables`. Schema is not edited in R6. See `.ai/reports/r6-contract-gap-capture-engine.md`.
