# ADR-004: One Entware service, three restart operations

## Status

Accepted (R2 freeze)

## Context

Android foreground service и `restartVpn` / `restartWithNewConfig` нельзя перенести 1:1.

## Decision

Один OS service: `blacktempled` via `/opt/etc/init.d/S99blacktemple-kn`.

Не systemd. Следовать `/opt/etc/init.d/rc.unslung` / `rc.func`.

Три разных операции:

1. **Restart VPN** — только Xray.
2. **Restart manager** — `blacktempled`, здоровый Xray по возможности оставить (PID persist + reclaim).
3. **Full restart** — manager + Xray + network reconcile.

Safe manager restart: detached `blacktempled restart-helper`, без синхронного kill HTTP-процесса.

Default crash policy: **FAIL OPEN** (снять BTKN hooks). Kill switch — advanced opt-in.

Prefix iptables: `BTKN_`. Никогда `-F` чужих таблиц. Coexistence с xkeen: свои порты, chains, PID, `/opt/blacktemple-kn/bin/xray` (не `/opt/bin/xray`).

## Consequences

UI обязан называть операции теми же тремя именами.
