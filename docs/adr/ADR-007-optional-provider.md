# ADR-007: Provider cabinet is optional and not on the core VPN path

## Status

Accepted (R2 freeze)

## Context

APK содержит CabinetAPI (JWT, devices, tariffs, pay, changeKey, swapKernel, news/support/TV pairing). Observed host strings exist in the APK. Publishing or calling that proprietary API is **out of scope** until a confirmed contract is frozen.

## Decision

```text
core router VPN
≠
optional provider integration
```

`Provider` / `CabinetCapability` — интерфейсы. Core работает при недоступном cabinet.

Support commands на роутере: allowlist + schema + audit + local enable. Default: remote admin commands **disabled**.

Не hardcode proprietary base URL в исходниках.

## Consequences

R12 отдельная волна. Core VPN не блокируется.
