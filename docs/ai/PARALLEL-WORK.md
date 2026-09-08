# Parallel work

Агенты могут работать параллельно **только** в назначенных ownership-зонах.

Текущая волна: **R4**. `merge_authorized: false`.

## Git: branch + worktree

Формат ветки:

```text
agent/<wave>/<task>
```

R4:

```text
agent/r4/orchestration
agent/r4/runtime-auth
agent/r4/profiles-key
agent/r4/xray-engine
agent/r4/service-supervisor
agent/r4/web-ui
agent/r4/build-package
```

Worktree (пример от корня sibling checkout):

```text
git worktree add <repo>-wt/<task> -b agent/r4/<task> 41099b953e8318d2c6115e04521a2f9821627378
```

Каждый агент редактирует **только свой worktree**. Не трогать основной checkout и чужие worktree.

## Назначение задачи

Обязательные поля (см. `.ai/tasks/`):

```text
BASE_SHA
ALLOWED_PATHS
FORBIDDEN_PATHS
DEPENDENCIES
ACCEPTANCE_CRITERIA
```

R4 `BASE_SHA`: `41099b953e8318d2c6115e04521a2f9821627378`

## Packaging split

- F: `packaging/init/**`
- H: `packaging/**` кроме `packaging/init/**`

## Shared freeze

`go.mod` / `go.sum` — общая заморозка. Агент **не** добавляет зависимости без contract gap.

`contracts/` и `docs/adr/` не менять.

## Запреты

- менять чужую зону;
- merge `main` самостоятельно (и любой другой merge);
- переписывать `contracts/` без согласования;
- force push `main`;
- silently rebase чужие branches;
- коммитить APK / secrets / `.research-local/`.

## Конфликты

Если два агента коснулись одного файла — **стоп**. Отчёт оркестратору. Не «чинить» чужой diff.

Известные стыки R4 (не файловые конфликты, а интеграция после merge оркестратором):

- G пишет `web/`; H `build.ps1` копирует `web/dist` → `src/cmd/blacktempled/assets`; A делает `go:embed`.
- A вызывает пакеты B/C/F после merge; до merge каждый работает от BASE_SHA.
