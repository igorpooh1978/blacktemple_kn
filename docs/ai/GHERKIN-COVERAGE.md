# Gherkin coverage

Источник: `features/*.feature` + `features/scenario-map.json`.
Проверка: `go run ./tools/gherkincheck` (stdlib only, без Godog/Cucumber).

Процесс:

```text
Behavior → Gherkin → executable acceptance → RED → production code → GREEN
```

Временные RED-мутации не коммитятся. Если RED нельзя доказать безопасно: `RED_PROOF_NOT_AVAILABLE` в `scenario-map.json`.

## Current map (R6-G)

Counts from `go run ./tools/gherkincheck` (RUN):

```text
scenarios=86
p0=86
p1=0
p2=0
features=12
mapped=86
```

R6-G retrofits P0 coverage of **current** production behavior. New Scenario IDs map existing tests; duplicates of PROF-001…TOOL-017 were not created.

New this wave (non-exhaustive): PROF-003…007, CONN-002…006, XRAY-004…006, ROUT-009…017, KEEN-005…010, LIFE-003…008, ATOM-002, GEO-002…005, LIST-003…006, POL-003…004, PKG-002, TOOL-018…021.

`gherkincheck` now also rejects:

- P0 mapping without `path::TestName`
- feature vs map priority mismatch
- duplicate test refs on the same Scenario ID

## RED this wave

- `BTKN-TOOL-018` dump budget — on exact `03e9fea` `TestProbeDumpBudgetFitsDeadline` FAIL:

```text
try_net=28 loop_extra=11 cmd_sec=10 overhead=20 worst=410s >= max_sec=180
```

Production dump then collapsed (CMD_SEC default 4, duplicate netstat/ip/opkg dumps bounded or skipped). Temporary production mutation was not required.

Other newly mapped scenarios: `RED_PROOF_NOT_AVAILABLE` (already GREEN on `03e9fea`; overlapping H.1 RED proofs remain for TOOL-011…017, ROUT-031, KEEN-003).

Do not claim 100% RED proof.

H.1 process-safety executable coverage is unchanged: `docs/hardware/probe_safety_exec.sh` via `TestProbeExecutableProcessSafety`.
