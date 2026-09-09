# Gherkin coverage

Источник: `features/*.feature` + `features/scenario-map.json`.
Проверка: `go run ./tools/gherkincheck` (stdlib only, без Godog/Cucumber).

Процесс:

```text
Behavior → Gherkin → executable acceptance → RED → production code → GREEN
```

Временные RED-мутации не коммитятся. Если RED нельзя доказать безопасно: `RED_PROOF_NOT_AVAILABLE` в `scenario-map.json`.

## Current map (R6-H.1 FIX-2)

Counts from `go run ./tools/gherkincheck`:

```text
scenarios=36
p0=36
p1=0
p2=0
features=12
mapped=36
```

RED proofs this iteration (tests against `65cbb2f`, no temporary production mutation committed):

- `BTKN-TOOL-015` / name-only reap — `TestNoNameOnlyOrphanReap` FAIL on `btkn_reap_other_probe_scripts`
- executable D — `--cleanup-orphans` killed a foreign `btkn-router-probe.sh` cmdline decoy (`FAIL: D foreign similar-cmdline was killed`)
- executable A/G hung or printed `FOREIGN_OR_UNKNOWN_PROCESS` until supervisor/worker + `router-probe.sh` identity

GREEN: `docs/hardware/probe_safety_exec.sh` via `TestProbeExecutableProcessSafety` (Linux /proc). Windows skips the exec test; static `TestNoNameOnlyOrphanReap` still runs.

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
