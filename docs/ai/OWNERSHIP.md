# Ownership

Каноническая таблица зон. Детали волн — в `agent-manifest.yml`.

Текущая волна: **R6** (`in_progress`, `merge_authorized: false`). `hybrid-iptables` выбран по hardware evidence (ADR-011). Live smoke **NOT RUN**. R6-I не стартует в этой оркестрации.

| Stream | Paths | Notes |
| --- | --- | --- |
| A Go runtime/API | `src/cmd/`, `src/internal/app/`, `src/internal/api/`, `src/internal/auth/` | HTTP, sessions, embed |
| B Keys | `src/internal/profiles/`, `src/internal/subscription/`, `src/internal/keys/`, `src/internal/countries/`, `src/internal/servers/` | BlackKey lifecycle |
| C Xray | `src/internal/xray/`, `src/internal/protocols/`, `third_party/xray.lock.json` | generator + pin; R6 inbounds on port 11820 |
| D Routing | `src/internal/routing/`, `src/internal/dns/`, `src/internal/geodata/` | hybrid-iptables planner; no geo engine in daemon |
| E Lists/policy | `src/internal/remotelists/`, `src/internal/remotepolicy/` | schema allowlist |
| F Service | `src/internal/supervisor/`, `src/internal/platform/`, `packaging/init/`, `packaging/keenetic/` | Entware init + Keenetic netfilter templates; **not** `packaging/control/` |
| G Web | `web/` | Preact, gzip ≤ 250 KB; R6 не редактирует UI |
| H Build | `build.ps1`, `bootstrap.ps1`, `test.ps1`, `package.ps1`, `tools/`, `packaging/**` **кроме** `packaging/init/**` и `packaging/keenetic/**` | Windows IPK/ELF + control scripts |
| I Updater | `src/internal/updater/`, `scripts/install.sh` | GitHub Releases |
| I Shared atomic | `src/internal/atomicfile/` | control/pointer file replace (R5-I) |
| J Lab | `lab/`, `lab.ps1`, `.github/workflows/qemu.yml` | QEMU ≠ hardware |
| K Security | `SECURITY.md`, auth, `security.yml` | redaction, CSRF; R4 auth code is stream A |
| L Provider | `src/internal/provider/`, `src/internal/news/`, `src/internal/support/`, `src/internal/pairing/` | optional, not core VPN |
| M Hardware | `router-smoke.ps1`, `scripts/router-*.sh`, `docs/hardware/` | KN-1011 gate; dual-gate harness only |

## R6 exclusive files

- `scripts/router-*.sh` (включая `scripts/router-probe.sh`) — stream **M only**.
- `router-smoke.ps1` — stream **M only**.
- `docs/hardware/**` — stream **M only**.
- `packaging/keenetic/**` — stream **F only** (новый путь R6).
- `scripts/install.sh` remains stream **I**.

## Packaging split (F vs H)

- **F** owns `packaging/init/**` (включая `S99blacktemple-kn`) **и** `packaging/keenetic/**`.
- **H** owns everything else under `packaging/` (`packaging/control/**`, `packaging/AGENTS.md`, будущие rootfs templates).
- H **не** редактирует init-скрипт и **не** редактирует `packaging/keenetic/**`. F **не** редактирует control/postinst/prerm/postrm.

## Shared freeze

Только оркестратор / явная волна (агенты R6 не трогают, кроме O для ADR-011):

- `contracts/`
- `docs/adr/` — ADR-001…ADR-010 не редактировать; ADR-011 принят агентом O
- `docs/ai/` (исключение: agent O в волне оркестрации)
- `AGENTS.md`
- `agent-manifest.yml` (исключение: agent O)
- `go.mod`, `go.sum` — shared freeze; **нельзя добавлять Go-зависимости** без contract gap оркестратора

Неназначенные пакеты (`src/internal/config/`, `diagnostics/` и т.п.) не захватываются молча: только gap + назначение оркестратора.
