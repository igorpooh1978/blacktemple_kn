# ADR-002: Primary target KN-1011 / mipsel-3.4_kn / softfloat

## Status

Accepted (R2 freeze)

## Context

Development happens on Windows 11. Production CPU is MT7621 MIPS32r2 LE soft-float.

## Decision

P0:

```text
GOOS=linux
GOARCH=mipsle
GOMIPS=softfloat
CGO_ENABLED=0
IPK=mipsel-3.4_kn
```

P1: `mipsel-3.4`, `mips-3.4`.
P2 build-only: hardfloat. Не production без железа.
mips64/mips64le — не сейчас.

QEMU не считается тестом MT7621.

## Consequences

Все release binaries проверяются `tools/elfcheck`.
