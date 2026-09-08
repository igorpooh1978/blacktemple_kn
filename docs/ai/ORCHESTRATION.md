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
- коммитит и пушит;
- возвращает полный technical report.

Агент **не** начинает следующую волну самовольно и **не** меняет архитектуру после freeze без оркестратора.

## Волны

| Wave | Цель |
| --- | --- |
| R0 | Public repo, AI docs, bootstrap |
| R1 | Full APK capability audit |
| R2 | Architecture + frozen contracts |
| R3 | Windows toolchain, MIPS, ELF, IPK |
| R4 | Minimal `blacktempled` + embedded UI |
| R5 | BlackKey / profiles / keys |
| R6 | Xray config + supervisor |
| R7 | Routing / DNS / geodata / lists |
| R8 | Service lifecycle |
| R9 | Full UI |
| R10 | Packaging / updater / rollback |
| R11 | QEMU lab |
| R12 | Provider capabilities |
| R13 | KN-1011 hardware gate |
| R14 | Stable release |

## Merge

Только оркестратор определяет порядок merge в `main`. Агенты пушат свои `agent/<wave>/<task>` ветки.

Исключение bootstrap R0: первый commit идёт прямо в `main`, потому что репозитория ещё нет.
