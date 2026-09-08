# ADR-001: Clean-room router product, not an Android port

## Status

Accepted (R2 freeze)

## Context

Reference APK `blacktemple1-3-12.apk` is a Flutter/Xray Android client. The product goal is Keenetic/Entware with the same *user-visible* simplicity, not a source port.

## Decision

- Исследовать APK только статически / black-box.
- Не копировать Dart/Java/Kotlin/Go, assets, Rive, fonts.
- Функциональные эквиваленты: per-app → per-device, VpnService → Entware daemon, Quick Tile → mobile Web UI.
- Не переносить hev-socks5-tunnel / tun2socks, пока kernel KN-1011 не докажет, что TUN/TPROXY/REDIRECT хуже.

## Consequences

Capability matrix обязательна. Пробелы помечаются, а не «теряются».
