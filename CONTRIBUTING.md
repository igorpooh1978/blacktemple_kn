# Contributing

## Для людей

1. Fork / branch от `main`.
2. Не коммитить APK, secrets, `.research-local/`.
3. Следовать `AGENTS.md` и `docs/ai/OWNERSHIP.md`.
4. Контракты в `contracts/` менять только после согласования.
5. PR должен содержать реальные команды и результаты тестов. Не выдумывать PASS.

## Для AI-агентов

См. `AGENTS.md`, `docs/ai/PARALLEL-WORK.md`, `docs/ai/AGENT-HANDOFF.md`.

Формат ветки: `agent/<wave>/<task>`.

## Стиль

- Go: `gofmt`, `go vet`, без DI-framework, ORM, CQRS, event bus.
- Web: Preact + TypeScript + Vite + plain CSS. Без React/Vue/Angular/Tailwind runtime.
- Комментарии в коде — по делу, на английском или русском, без рекламы инструментов.
