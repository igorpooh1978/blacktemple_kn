# Test protocol

Не выдавать target за result. Не маркировать `SUPPORTED` без hardware PASS.

## Gherkin

Сначала сценарий в `features/`, затем executable test, затем RED, затем код, затем GREEN.

```powershell
go run ./tools/gherkincheck
```

P0 без mapping в `features/scenario-map.json` — FAIL. Нет Godog и нет Cucumber.
Если RED нельзя доказать без порчи контракта: `RED_PROOF_NOT_AVAILABLE` с точной причиной.

## Уровни

1. **Unit** — Go `go test`, frontend Vitest. Windows.
2. **Gherkin mapping** — `go run ./tools/gherkincheck`.
3. **Contract** — JSON Schema + OpenAPI fixtures.
4. **Package** — ELF check + IPK validate.
5. **QEMU** — MIPSLE smoke. Не выдавать за MT7621.
6. **Hardware** — `router-smoke.ps1` на KN-1011. Probe: READ-ONLY, single-instance, bounded. Live routing smoke только при обоих mutation gates.

## Failure injection (обязательный backlog)

- broken / expired BlackKey
- empty subscription
- bad server / all servers down
- invalid Xray config
- Xray crash / crash loop
- corrupt geoip.dat / geosite.dat / remote list
- download interrupted
- GitHub unavailable / provider unavailable
- DNS / WAN unavailable
- disk full / permission failure
- manager restart / crash
- router reboot
- failed upgrade / failed rollback

## Evidence

Каждый PASS должен иметь команду + output. См. `TRACE-EVIDENCE.md`.
Gherkin coverage: `docs/ai/GHERKIN-COVERAGE.md`.
