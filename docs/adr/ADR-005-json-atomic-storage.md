# ADR-005: JSON config, atomic files, no SQLite in v1

## Status

Accepted (R2 freeze)

## Context

Router flash/RAM малы. Нужны atomic replace и last-known-good.

## Decision

V1 storage = JSON files.

```text
write .tmp → fsync → rename
```

Sensitive files mode `0600`.

Разделить: config, runtime state, cache, last-known-good, backup.

Не SQLite, не ORM.

## Consequences

Контракты в `contracts/schemas/`. Миграции — versioned JSON, не SQL.
