# Remote list sources (license review)

APK string/dex evidence (2026-09-08) содержит идентификаторы, похожие на:

- `Loyalsoldier`
- `runetfreedom`
- `Chocolate4U`
- `blacktemple-rules`

Текущие публичные репозитории (проверены fetch 2026-09-08):

| Candidate | Repo exists | License file | Xray-compatible DAT | Enabled |
| --- | --- | --- | --- | --- |
| Loyalsoldier/v2ray-rules-dat | yes | GPL-3.0 | yes (geoip.dat / geosite.dat) | **no** |
| runetfreedom/russia-v2ray-rules-dat | yes | GPL-3.0 | yes | **no** |
| Chocolate4U/Iran-v2ray-rules | yes | GPL-3.0 | yes | **no** |

Имена `*-blacktemple-rules-dat` как отдельные GitHub repo **не** подтверждались как канонические upstream. Использовать только после:

1. license compatibility с MIT IPK;
2. security (supply chain);
3. размер на KN-1011 flash;
4. pin + checksum (не `latest`).

До ADR включения — GeodataManager может принимать **ручной** файл пользователя, без дефолтного download этих URL.
