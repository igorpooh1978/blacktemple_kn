# Gherkin coverage

Источник: `features/*.feature` + `features/scenario-map.json`.
Проверка: `go run ./tools/gherkincheck` (stdlib only, без Godog/Cucumber).

Процесс:

```text
Behavior → Gherkin → executable acceptance → RED → production code → GREEN
```

Временные RED-мутации не коммитятся. Если RED нельзя доказать безопасно: `RED_PROOF_NOT_AVAILABLE` в `scenario-map.json`.

## Current map (R6-H.1)

Counts from `go run ./tools/gherkincheck`:

```text
scenarios=36
p0=36
p1=0
p2=0
features=12
mapped=36
```

RED proofs this iteration (temporary production mutation against HEAD `594245c`, restored, not committed):

- `BTKN-ROUT-031` — err-only classifier → FAIL `TestIsAbsentObjectFailureRealisticExitError` → restore GREEN
- `BTKN-KEEN-003` — prefix-only `HasPrefix(root)` → FAIL `TestValidateModulePath` on `/lib/modules-evil` → restore GREEN
- `BTKN-TOOL-011` — `BeginWrite` without `EndWrite` → FAIL `TestCopyScriptViaSshCatClosesStdin` → restore GREEN
- `BTKN-TOOL-012` — no lock directory → FAIL `TestProbeSingleInstanceAlreadyRunning` → restore GREEN
- `BTKN-TOOL-013` — no `FOREIGN_OR_UNKNOWN_PROCESS` → FAIL `TestProbeStaleLockRecovers` → restore GREEN
- `BTKN-TOOL-014` — no remote `TIMEOUT` / tree kill → FAIL `TestProbeHardTimeoutKillsOwnedTree` → restore GREEN
- `BTKN-TOOL-015` — HEAD storm guard missing `ALREADY_RUNNING`/`TIMEOUT`/TERM+KILL → FAIL `TestProbeFailureLeavesNoStorm` → restore GREEN

New TOOL scenarios this iteration:

- `BTKN-TOOL-011` SSH cat EOF
- `BTKN-TOOL-012` single-instance probe
- `BTKN-TOOL-013` stale lock recovery
- `BTKN-TOOL-014` hard runtime tree kill
- `BTKN-TOOL-015` no CPU storm leftovers
- `BTKN-TOOL-016` one-pass redactor
- `BTKN-TOOL-017` never kill Xray/XKeen/arbitrary awk

Also: `BTKN-ROUT-031` (H1-A), `BTKN-KEEN-003` / `BTKN-KEEN-004` (H1-C).

Hardware probe self-protection is diagnostic infrastructure: single instance, bounded, self-terminating, owned-tree only.
