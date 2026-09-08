# Parallel work

Агенты могут работать параллельно **только** в назначенных ownership-зонах.

## Git

```text
git branches + git worktree
```

Ветка:

```text
agent/<wave>/<task>
```

Примеры:

```text
agent/r3/go-runtime
agent/r3/web-ui
agent/r3/ipk-builder
agent/r3/geodata
```

## Назначение задачи

Обязательные поля промпта:

```text
BASE_SHA
ALLOWED_PATHS
FORBIDDEN_PATHS
DEPENDENCIES
ACCEPTANCE_TESTS
```

## Запреты

- менять чужую зону;
- merge `main` самостоятельно;
- переписывать `contracts/` без согласования;
- force push `main`;
- silently rebase чужие branches;
- коммитить APK / secrets / `.research-local/`.

## Конфликты

Если два агента коснулись одного файла — **стоп**. Отчёт оркестратору. Не «чинить» чужой diff.
