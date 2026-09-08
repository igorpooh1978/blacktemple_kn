# Agent handoff

Каждый агент возвращает оркестратору:

```text
STATUS
TASK
BASE SHA
FINAL SHA
BRANCH
PUSH STATUS
CHANGED FILES
IMPLEMENTED
NOT IMPLEMENTED
ARCHITECTURAL DECISIONS
COMMANDS ACTUALLY RUN
TESTS ACTUALLY RUN
TEST RESULTS
BUILD ARTIFACTS
MEASUREMENTS
KNOWN RISKS
BLOCKERS
NEXT RECOMMENDED STEP
```

Правила:

- Если команда/тест/benchmark не запускались — писать `NOT RUN`.
- Не придумывать output.
- SHA только из `git rev-parse`.
- Размеры и checksum только из реальных файлов.
