# ADR-008: Windows-native IPK and ELF toolchain

## Status

Accepted (R2 freeze)

## Context

Обычная разработка — Windows 11. Не требовать WSL/Docker/OpenWrt SDK для hello/IPK.

## Decision

- `tools/elfcheck` — `debug/elf`, отказ PE, проверка MIPS LE 32-bit, static/dynamic.
- `tools/ipkpack` — reproducible `.ipk` (ar + control.tar.gz + data.tar.gz) без Linux `ar`.
- `build.ps1` — единый pipeline.

## Consequences

CI повторяет те же Go tools на Linux runner; логика упаковки одна.
