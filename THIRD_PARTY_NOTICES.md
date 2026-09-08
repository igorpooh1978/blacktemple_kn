# Third-party notices

Этот проект собирает и распространяет собственные компоненты под MIT.

Ниже — внешние зависимости, которые **могут** попадать в runtime/IPK. Они не копируются в git как бинарники (кроме pin-метаданных).

## Xray-core

- Upstream: https://github.com/XTLS/Xray-core
- License: Mozilla Public License 2.0
- Role: отдельный pinned executable `/opt/blacktemple-kn/bin/xray`
- Pin: `third_party/xray.lock.json`
- Hardware verification: **not done** (KN-1011 status = untested)

MPL-2.0 требует предоставить Source Form Xray-core. Релизный IPK должен указывать URL исходников соответствующей версии.

## Geodata (не включено в v0 hello IPK)

Кандидаты, обнаруженные в APK и проверенные 2026-09-08:

| Observed APK identifier | Current public repo | License (fetched) | Status |
| --- | --- | --- | --- |
| Loyalsoldier / blacktemple-rules-dat | [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | GPL-3.0 | **not enabled** — license + size review required |
| runetfreedom / russia-blacktemple-rules-dat | [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat) | GPL-3.0 | **not enabled** |
| Chocolate4U / Iran-blacktemple-rules | [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules) | GPL-3.0 | **not enabled** |

Автоматически эти источники **не** подключаются. Нужен отдельный ADR после license/security review.

Официальные Xray geoip/geosite из релиза Xray-core также имеют собственные notices; они не являются нашим geo engine.

## UI toolchain (build PC only)

Vite, Preact, TypeScript — только на машине сборки. На роутер Node.js не ставится.
