# Ownership

Каноническая таблица зон. Детали волн — в `agent-manifest.yml`.

Текущая волна: **R5** (prep integrated). R6 не начата.

| Stream | Paths | Notes |
| --- | --- | --- |
| A Go runtime/API | `src/cmd/`, `src/internal/app/`, `src/internal/api/`, `src/internal/auth/` | HTTP, sessions, embed |
| B Keys | `src/internal/profiles/`, `src/internal/subscription/`, `src/internal/keys/`, `src/internal/countries/`, `src/internal/servers/` | BlackKey lifecycle |
| C Xray | `src/internal/xray/`, `src/internal/protocols/`, `third_party/xray.lock.json` | generator + pin |
| D Routing | `src/internal/routing/`, `src/internal/dns/`, `src/internal/geodata/` | no geo engine in daemon |
| E Lists/policy | `src/internal/remotelists/`, `src/internal/remotepolicy/` | schema allowlist |
| F Service | `src/internal/supervisor/`, `src/internal/platform/`, `packaging/init/` | Entware init only; **not** `packaging/control/` |
| G Web | `web/` | Preact, gzip ≤ 250 KB |
| H Build | `build.ps1`, `bootstrap.ps1`, `test.ps1`, `package.ps1`, `tools/`, `packaging/**` **кроме** `packaging/init/**` | Windows IPK/ELF + control scripts |
| I Updater | `src/internal/updater/`, `scripts/install.sh` | GitHub Releases |
| I Shared atomic | `src/internal/atomicfile/` | control/pointer file replace (R5-I) |
| J Lab | `lab/`, `lab.ps1`, `.github/workflows/qemu.yml` | QEMU ≠ hardware |
| K Security | `SECURITY.md`, auth, `security.yml` | redaction, CSRF; R4 auth code is stream A |
| L Provider | `src/internal/provider/`, `src/internal/news/`, `src/internal/support/`, `src/internal/pairing/` | optional, not core VPN |
| M Hardware | `router-smoke.ps1`, `scripts/router-probe.sh`, `docs/hardware/` | KN-1011 gate |

## R5 exclusive files

- `scripts/router-probe.sh` — stream **M only**. Nobody else edits it (not I, not D, not J, not other R5 agents).
- `scripts/install.sh` remains stream **I**.

## Packaging split (F vs H)

- **F** owns `packaging/init/**` (включая `S99blacktemple-kn`).
- **H** owns everything else under `packaging/` (`packaging/control/**`, `packaging/AGENTS.md`, будущие rootfs templates).
- H **не** редактирует init-скрипт. F **не** редактирует control/postinst/prerm/postrm.

## Shared freeze

Только оркестратор / явная волна (агенты R5 не трогают):

- `contracts/`
- `docs/adr/`
- `docs/ai/` (исключение: agent O в волне оркестрации)
- `AGENTS.md`
- `agent-manifest.yml` (исключение: agent O)
- `go.mod`, `go.sum` — shared freeze; **нельзя добавлять Go-зависимости** без contract gap оркестратора

Неназначенные пакеты (`src/internal/config/`, `diagnostics/` и т.п.) не захватываются молча: только gap + назначение оркестратора.
