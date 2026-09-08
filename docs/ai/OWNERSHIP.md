# Ownership

Каноническая таблица зон. Детали волн — в `agent-manifest.yml`.

| Stream | Paths | Notes |
| --- | --- | --- |
| A Go runtime/API | `src/cmd/`, `src/internal/app/`, `src/internal/api/`, `src/internal/auth/` | HTTP, sessions, embed |
| B Keys | `src/internal/profiles/`, `subscription/`, `keys/`, `countries/`, `servers/` | BlackKey lifecycle |
| C Xray | `src/internal/xray/`, `protocols/`, `third_party/xray.lock.json` | generator + pin |
| D Routing | `src/internal/routing/`, `dns/`, `geodata/` | no geo engine in daemon |
| E Lists/policy | `src/internal/remotelists/`, `remotepolicy/` | schema allowlist |
| F Service | `src/internal/supervisor/`, `platform/`, `packaging/init/` | Entware, not systemd |
| G Web | `web/` | Preact, gzip ≤ 250 KB |
| H Build | `*.ps1` root build scripts, `tools/`, `packaging/` | Windows IPK/ELF |
| I Updater | `src/internal/updater/`, `scripts/install.sh` | GitHub Releases |
| J Lab | `lab/`, `lab.ps1` | QEMU ≠ hardware |
| K Security | `SECURITY.md`, auth, `security.yml` | redaction, CSRF |
| L Provider | `provider/`, `news/`, `support/`, `pairing/` | optional, not core VPN |
| M Hardware | `router-smoke.ps1`, `docs/hardware/` | KN-1011 gate |

Общие freeze-зоны (только оркестратор / явная волна):

- `contracts/`
- `docs/adr/`
- `docs/ai/`
- `AGENTS.md`
- `agent-manifest.yml`
