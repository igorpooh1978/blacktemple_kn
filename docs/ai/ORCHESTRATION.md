# Orchestration

Оркестратор (ChatGPT в основном диалоге) владеет DAG.

## Роли

Оркестратор:

- определяет волны;
- раздаёт параллельные задачи;
- назначает ownership файлов;
- фиксирует `BASE_SHA`;
- принимает/отклоняет результаты;
- определяет merge order;
- выдаёт следующие промпты;
- принимает архитектурные решения;
- разрешает конфликты;
- определяет readiness следующей волны.

Исполняющий агент:

- выполняет назначенную волну;
- исследует;
- пишет код и тесты;
- запускает реальные проверки;
- коммитит и пушит **свою** ветку `agent/<wave>/<task>`;
- возвращает полный technical report.

Агент **не** начинает следующую волну самовольно, **не** merge'ит `main` (и никакую другую ветку), и **не** меняет архитектуру после freeze без оркестратора.

## Волны

| Wave | Цель | Status |
| --- | --- | --- |
| R0 | Public repo, AI docs, bootstrap | done |
| R1 | Full APK capability audit | prior |
| R2 | Architecture + frozen contracts | frozen |
| R3 | Windows toolchain, MIPS, ELF, IPK | prior |
| R4 | Minimal `blacktempled` + embedded UI | **current** (parallel O/A/B/C/F/G/H) |
| R5 | BlackKey / profiles / keys | next after R4 merge |
| R6 | Xray config + supervisor | later |
| R7 | Routing / DNS / geodata / lists | later |
| R8 | Service lifecycle | later |
| R9 | Full UI | later |
| R10 | Packaging / updater / rollback | later |
| R11 | QEMU lab | later |
| R12 | Provider capabilities | later |
| R13 | KN-1011 hardware gate | later |
| R14 | Stable release | later |

## R4 (current)

- `BASE_SHA`: `41099b953e8318d2c6115e04521a2f9821627378`
- `merge_authorized`: **false**
- Параллельные агенты: O, A, B, C, F, G, H
- Ветки: `agent/r4/<task>` в отдельных git worktree
- Task manifests: `.ai/tasks/r4-*.yml`
- Канон ownership: `agent-manifest.yml` + `OWNERSHIP.md`

## Merge

Только оркестратор определяет порядок merge в `main`. Агенты пушат свои `agent/<wave>/<task>` ветки и **не** merge'ат.

Исключение bootstrap R0: первый commit идёт прямо в `main`, потому что репозитория ещё нет.
