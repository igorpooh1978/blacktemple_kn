# Repository map

```text
/
├── AGENTS.md
├── agent-manifest.yml
├── README.md
├── LICENSE
├── THIRD_PARTY_NOTICES.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODEOWNERS
├── bootstrap.ps1 build.ps1 test.ps1 package.ps1 release.ps1 router-smoke.ps1 lab.ps1
├── .ai/          tasks, reports, contracts notes, templates
├── contracts/    openapi, schemas, events  (FROZEN)
├── docs/         ai, adr, hardware, research, releases, architecture
├── src/          Go daemon (blacktempled)
├── web/          Preact/Vite UI → go:embed dist
├── packaging/    Entware templates; init/ = stream F, control/ = stream H
├── tools/        elfcheck, ipkpack
├── scripts/      install.sh and helpers
├── lab/          QEMU notes (not hardware)
├── tests/        extra fixtures
├── third_party/  lock files only
└── .github/workflows/
```

Runtime on router:

```text
/opt/blacktemple-kn/
├── bin/blacktempled
├── bin/xray
├── config/
├── data/
├── run/
├── backup/
└── logs/
```

Init: `/opt/etc/init.d/S99blacktemple-kn`.
