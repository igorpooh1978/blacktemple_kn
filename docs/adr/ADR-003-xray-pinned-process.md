# ADR-003: Xray is a pinned child process, not a library

## Status

Accepted (R2 freeze)

## Context

APK uses `libgojni.so` + bundled Xray-core (string evidence: `Xray-Core v 26.2.6`) plus tun helpers.

## Decision

- Xray — отдельный executable `/opt/blacktemple-kn/bin/xray`.
- Pin в `third_party/xray.lock.json` (версия + URL + SHA256).
- Никакого `latest` auto-rollout.
- `blacktempled` супервизит процесс: STOPPED/STARTING/RUNNING/RELOADING/FAILED/BACKOFF.
- Crash isolation, independent update, rollback.
- Config generator пишет `run/xray.json`. Пользователь JSON не редактирует.

Pinned watch version as of 2026-09-08: **Xray-core v26.3.27**. Hardware verification: not done.

Для KN-1011 из zip `Xray-linux-mips32le.zip` брать **`xray_softfloat`**, не hardfloat `xray`.

## Consequences

Обновление Xray — отдельный lifecycle от application update.
