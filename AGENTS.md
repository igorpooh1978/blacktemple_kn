# AGENTS.md

Этот репозиторий подготовлен для параллельной работы AI-агентов.

Оркестратор проекта — отдельный диалог. Агенты в Cursor **исполняют назначенную волну**, не пересобирают DAG и не merge'ат `main` самостоятельно.

## Язык

- Ответы пользователю и оркестратору — на русском.
- Идентификаторы кода, команды, логи, схемы — на английском.
- Пользовательский UI — русский в `web/` (без сторонних UI-kit).

## Clean-room

Reference APK `blacktemple1-3-12.apk` можно использовать только локально:

- статическое исследование;
- black-box;
- capability / UX / observable contracts.

Запрещено коммитить: APK, декомпил, Dart/Java/Kotlin/Go из APK, assets, Rive, proprietary fonts, токены, credentials, реальные BlackKey.

Исследование → `.research-local/` (gitignore).
В git только собственные выводы, схемы и код.

## Параллельная работа

Формат веток:

```text
agent/<wave>/<task>
```

Каждой задаче оркестратор назначает:

```text
BASE_SHA
ALLOWED_PATHS
FORBIDDEN_PATHS
DEPENDENCIES
ACCEPTANCE_TESTS
```

Агент не должен:

- менять чужую ownership-зону;
- самостоятельно merge `main`;
- переписывать общий contract без согласования;
- делать force push `main`;
- silently rebase чужие branches.

Конфликт разрешает только оркестратор.

## Source of truth

| Документ | Роль |
| --- | --- |
| `docs/research/APK-FEATURE-MATRIX.md` | обнаруженные возможности APK |
| `docs/adr/` | архитектурные решения |
| `contracts/` | замороженные API/schema |
| `docs/ai/OWNERSHIP.md` | зоны файлов |
| `agent-manifest.yml` | волны, ветки, зависимости |
| `docs/hardware/KN-1011.md` | целевое железо |

Не писать VPN вслепую. Не маркировать протокол `SUPPORTED`, пока нет hardware PASS.

## Handoff

Каждый агент возвращает блок из `docs/ai/AGENT-HANDOFF.md`.

Запрещено придумывать тесты, traces, команды, benchmark, output. Если не запускалось: `NOT RUN`.

## Git

- Одна git-команда на вызов терминала.
- Нет `git push --force`, `git reset --hard`, history rewrite.
- После завершённой волны: commit + push на tracking branch/`main` без вопроса про git.
- Сообщения коммитов нейтральные, без упоминания инструментов генерации.

## Сборка

Основной environment: Windows 11 + PowerShell.

```powershell
.\build.ps1
```

Production: `CGO_ENABLED=0`. Xray — отдельный pinned executable, не Go library.

## Локальные правила областей

- `src/AGENTS.md`
- `web/AGENTS.md`
- `packaging/AGENTS.md`
- `lab/AGENTS.md`
