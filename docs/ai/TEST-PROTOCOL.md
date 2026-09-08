# Test protocol

Не выдавать target за result. Не маркировать `SUPPORTED` без hardware PASS.

## Уровни

1. **Unit** — Go `go test`, frontend Vitest. Windows.
2. **Contract** — JSON Schema + OpenAPI fixtures.
3. **Package** — ELF check + IPK validate.
4. **QEMU** — MIPSLE smoke. Не выдавать за MT7621.
5. **Hardware** — `router-smoke.ps1` на KN-1011.

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
