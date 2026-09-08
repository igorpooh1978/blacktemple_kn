# ADR-010: Remote policy and lists are allowlisted, never executable

## Status

Accepted (R2 freeze)

## Context

APK embeds many `x-*` remote setting keys and downloads remote lists (countries, domains, Telegram/WhatsApp IPs, geodata).

## Decision

Priority:

```text
built-in defaults
  → provider remote defaults
    → local user overrides
      → temporary session override
```

Remote values: JSON schema + allowlist. Нельзя: shell, произвольные команды, wipe files, arbitrary firewall text, download+exec, silently restart Linux daemon.

`RemoteListManager`: ETag, If-Modified-Since, TTL, backoff, checksum, atomic replace, rollback, offline cache. Никогда не удалять рабочий list до проверки нового.

Geodata: Xray files on disk, не в RAM `blacktempled`. Отдельный `GeodataManager`.

GPL geodata sources из APK **не включены** до license/security review (см. `THIRD_PARTY_NOTICES.md`).

## Consequences

Stream E реализует менеджеры против `contracts/schemas/`.
