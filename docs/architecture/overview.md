# Architecture overview

Product principle: пользователь знает только Ключ / Подключить / Сервер / Маршрутизация.

## Processes

```text
S99blacktemple-kn
        │
        ▼
   blacktempled          HTTP LAN UI/API, supervisor, config
        │
        ▼
   xray (child)          pinned external binary
```

## Config generation

Пользователь не управляет `01_log.json` … `05_outbounds.json`. Generated config — internal, Advanced view = read-only.

Key change workflow:

```text
candidate → xray run -test → health probe → activate → last-known-good
```

Failure: restore previous working key/config. Не ломать живой VPN.

## Policy stack

```text
built-in defaults
  → provider remote defaults (allowlisted)
    → local user overrides
      → session override
```

## Capture

`TrafficCaptureEngine` — выбор после kernel probe KN-1011. См. ADR-009.

## Provider

Optional. Core VPN без cabinet. См. ADR-007.

## Resource budgets (targets, not measurements)

- `blacktempled` stripped ≤ 10 MB
- web gzip ≤ 250 KB
- idle RSS `blacktempled` ≤ 10–12 MB
- idle CPU ≈ 0

Xray и geodata измеряются отдельно.
