# APK feature matrix (clean-room)

Reference: local file `blacktemple1-3-12.apk` (106 482 561 bytes, 759 zip entries).  
Method: zip listing + printable strings from `libapp.so` / `libgojni.so` / `classes.dex` / Flutter assets.  
No decompiled sources were copied into git. Raw dumps stay in `.research-local/`.

Confidence:

| Value | Meaning |
| --- | --- |
| STATIC_CONFIRMED | строка/файл/native lib в APK |
| BLACKBOX_CONFIRMED | не проверялось (нет UI run в этой волне) |
| INFERRED | поведение восстановлено по именам/логам |
| PROVIDER_DEPENDENT | требует cabinet/provider API |
| ANDROID_SPECIFIC | нет прямого router API |
| UNKNOWN | недостаточно evidence |

Test status / Hardware status для всех строк этой волны: **NOT RUN**.

Дополнительно к baseline оркестратора найдены: `swapKernel`, `MigrateBlack`, `noise`/`mask` beans, `udp_hop`, `XRayTestService`, `MyTileService`, `WidgetProvider`, bundled string `Xray-Core v 26.2.6`, geosite tags asset, GitHub self-update URL, WhiteList LTE-mode copy, auto fastest-key-in-subscription.

Proprietary API base URL strings **намеренно не переносятся в код**. Cabinet — optional provider.

---

## 1. Profiles / BlackKey

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Add Key / BlackKey | `libapp.so`: `Add Key`, `BlackKey`, `Black Key` | STATIC_CONFIRMED | URL → validate → download sub → parse → save | same UX | `profiles`, `subscription` | P0 | NOT RUN | NOT RUN |
| Import keys / QR | `libapp.so` qr; AssetManifest qr | STATIC_CONFIRMED | QR/import flow | paste URL + optional LAN QR | `profiles` | P0 | NOT RUN | NOT RUN |
| Multiple profiles / subscriptions | `subscription_item.dart`, `_subscriptions` | STATIC_CONFIRMED | list, delete, refresh | same | `profiles` | P0 | NOT RUN | NOT RUN |
| Copy key | orchestrator baseline; string `getBlackKey` | INFERRED | copy secret to clipboard | copy redacted; full secret only on explicit reveal | `profiles` | P1 | NOT RUN | NOT RUN |
| Deep-link import | `telegram.me/blacktemple_space_bot?start=` | STATIC_CONFIRMED | Telegram start payload | optional; LAN pairing preferred | `pairing` | P2 | NOT RUN | NOT RUN |
| Active profile | `active profile` | STATIC_CONFIRMED | one active | one active | `profiles` | P0 | NOT RUN | NOT RUN |
| Secret redaction | product rule | INFERRED | n/a | never log/API full key | `auth`, diagnostics | P0 | NOT RUN | NOT RUN |

## 2. Key lifecycle

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Change key | `/keys/change`, `ChangeKeyRequest/Response`, `[CabinetAPI] changeKey` | STATIC_CONFIRMED | cabinet call then apply | `KeyManager.changeKey` with test-then-activate | `keys` | P0 | NOT RUN | NOT RUN |
| Change country | `/keys/country`, `Select country` | STATIC_CONFIRMED | country list | `CountryCatalog` | `countries` | P1 | NOT RUN | NOT RUN |
| swapKernel | `[CabinetAPI] swapKernel` | STATIC_CONFIRMED | protocol/kernel swap via cabinet | `change protocol` if provider supports | `protocols`, provider | P2 | NOT RUN | NOT RUN |
| MigrateBlack | `MigrateBlack`, `MigrateBlackDialog` | STATIC_CONFIRMED | account/key migration | provider optional | `provider` | P2 | NOT RUN | NOT RUN |
| Fastest key in subscription | UI string auto-select fastest key when VPN on and pinged | STATIC_CONFIRMED | auto on connect | AUTO mode | `servers`, `keys` | P0 | NOT RUN | NOT RUN |
| Rollback working key | product rule + changeKey FAILED logs | INFERRED | don't break VPN | last-known-good | `keys`, `xray` | P0 | NOT RUN | NOT RUN |

Entities are separate: subscription / key / server / country / protocol.

## 3. Auto server selection

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Auto / rotate / force new | `Auto server`, `Rotate servers`, `Selecting a server`, `force new connection` | STATIC_CONFIRMED | background rotate | AUTO, MANUAL, FAILOVER, ROTATE | `servers` | P0 | NOT RUN | NOT RUN |
| Non-ICMP health | `generate_204` URLs, TCP/HTTP checks in strings | STATIC_CONFIRMED | mixed probes | TCP connect + proxy health + cooldown | `diagnostics` | P0 | NOT RUN | NOT RUN |

Не агрессивный background ping (CPU роутера).

## 4. Country catalog

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BlackCountry list | `BlackCountry`, `Updated BlackCountry List`, `decodeBlackCountry` | STATIC_CONFIRMED | remote list + cache | `CountryCatalog` + last-known-good | `countries`, `remotelists` | P1 | NOT RUN | NOT RUN |

## 5. Protocols and transports

Do **not** mark SUPPORTED.

| Feature | Evidence | Confidence | Android behavior | Router equivalent | parsed | generated | Xray accepts | QEMU | KN-1011 | Priority |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| VLESS | `vless://`, `vless_fmt.dart` | STATIC_CONFIRMED | parse/share | generator | planned | planned | NOT RUN | NOT RUN | NOT RUN | P0 |
| VMess | `vmess://`, xray_config.json | STATIC_CONFIRMED | parse | generator | planned | planned | NOT RUN | NOT RUN | NOT RUN | P0 |
| Trojan | `trojan://` | STATIC_CONFIRMED | parse | generator | planned | planned | NOT RUN | NOT RUN | NOT RUN | P0 |
| Shadowsocks | libapp + geosite_tags | STATIC_CONFIRMED | parse | generator | planned | planned | NOT RUN | NOT RUN | NOT RUN | P1 |
| SOCKS | template inbound 10808 | STATIC_CONFIRMED | local inbound | optional LAN proxy | planned | planned | NOT RUN | NOT RUN | NOT RUN | P1 |
| WireGuard | `wireguard_bean` | STATIC_CONFIRMED | parse/account | Xray WG outbound if version supports | planned | planned | NOT RUN | NOT RUN | NOT RUN | P2 |
| Hysteria/Hysteria2 | `hysteria2://`, `hy2steria_settings_bean` | STATIC_CONFIRMED | parse | generator if Xray supports | planned | planned | NOT RUN | NOT RUN | NOT RUN | P2 |
| AmneziaWG | `AmneziaWG` + Play/App Store URLs | STATIC_CONFIRMED | account/UI mention | **not P0**; no engine evidence on router | no | no | n/a | n/a | n/a | P3 |
| TCP/WS/gRPC/XHTTP/HTTP Upgrade/mKCP/QUIC | libgojni + beans | STATIC_CONFIRMED | stream settings | capability-aware generator | planned | planned | NOT RUN | NOT RUN | NOT RUN | P1 |
| TLS / REALITY / XTLS Vision | libapp REALITY, XTLS, tls_settings_bean | STATIC_CONFIRMED | stream | generator | planned | planned | NOT RUN | NOT RUN | NOT RUN | P0 |
| noise / mask / udp_hop | corresponding beans | STATIC_CONFIRMED | advanced | Advanced only | planned | planned | NOT RUN | NOT RUN | NOT RUN | P2 |

Android bundled core string: `Xray-Core v 26.2.6`. Router pin is independent (`v26.3.27` lock).

## 6. WhiteList special provider mode

Not routing allowlist.

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| WhiteList profile | `WhiteList`, `WhiteListPage`, `WhiteListSlot`, `hasBlacklistedProfile` | STATIC_CONFIRMED | special provider key / LTE mode copy | `ProviderSpecialMode` capability `whitelist_mode` | `provider`, `keys` | P2 | NOT RUN | NOT RUN |
| Manual / schedule times | `Manual mode active`, `encodeWhiteListTimeFrom/To` | STATIC_CONFIRMED | schedule + manual override | schedule + WAN condition + manual | `remotepolicy` | P2 | NOT RUN | NOT RUN |
| Hide if unsupported | product rule | INFERRED | page `WhiteListNotEnablePage` | UI hides capability | web | P2 | NOT RUN | NOT RUN |

Не hardcode proprietary WhiteList без API contract.

## 7. Connection control

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Connect / Disconnect | CONNECT/DISCONNECT, `XrayVpnService` | STATIC_CONFIRMED | VpnService | daemon connect | `connection` | P0 | NOT RUN | NOT RUN |
| restartVpn | `restartVpn` in dex+libapp | STATIC_CONFIRMED | restart tunnel | Restart VPN (Xray only) | `supervisor` | P0 | NOT RUN | NOT RUN |
| restartWithNewConfig | dex + tun2socks start/stop logs | STATIC_CONFIRMED | stop tun, new if, start Xray | candidate test → atomic swap | `xray`, `routing` | P0 | NOT RUN | NOT RUN |
| Auto connect boot | product + Android service | INFERRED | always-on VPN | Entware init start | `platform/entware` | P0 | NOT RUN | NOT RUN |

## 8. Tunnel / capture

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hev-socks5-tunnel | `libhev-socks5-tunnel.so`, JNI start logs | STATIC_CONFIRMED | default tun helper | not copied unless needed | `platform` | ANDROID_SPECIFIC | NOT RUN | NOT RUN |
| tun2socks | `libtun2socks.so`, OLD process path | STATIC_CONFIRMED | fallback | not copied unless needed | `platform` | ANDROID_SPECIFIC | NOT RUN | NOT RUN |
| Xray TUN inbound | `xray_config_with_tun.json` tag `tun` name `xray0` | STATIC_CONFIRMED | optional | candidate `xray-tun` | `routing` | P1 | NOT RUN | NOT RUN |
| TrafficCaptureEngine | architecture | INFERRED | VpnService | iptables/TPROXY/TUN TBD | `routing` | P0 | NOT RUN | NOT RUN |

## 9. Smart routing

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Modes Smart / All / Selected | product UX; `custom-route`, routing_bean | STATIC_CONFIRMED / INFERRED | three modes | same three | `routing` | P0 | NOT RUN | NOT RUN |
| domain / CIDR / geoip / geosite | `geoip:private`, `geosite:vk`, `geosite:yandex`, `geosite:category-gov-ru` | STATIC_CONFIRMED | Xray routing | Xray routing, no custom geo engine | `routing`, `geodata` | P0 | NOT RUN | NOT RUN |
| geosite_tags.json | Flutter asset, thousands of tags | STATIC_CONFIRMED | picker | catalog from installed dat | `geodata` | P1 | NOT RUN | NOT RUN |

## 10. Geodata

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Implementation component | Priority | Test status | Hardware status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| geoip.dat / geosite.dat | libgojni strings; `geosite_installed_url` | STATIC_CONFIRMED | bundled/update | `GeodataManager` on disk | `geodata` | P0 | NOT RUN | NOT RUN |
| Independent update | product | INFERRED | app update vs geo | separate lifecycle | `geodata` | P0 | NOT RUN | NOT RUN |

## 11. Remote lists and policy

All `x-*` keys listed by orchestrator are **STATIC_CONFIRMED** in `libapp.so` (arm64/armeabi/x86_64). Additional prefs: `pref_xray_burst_*`, `pref_xray_memory_saver_enabled`, `pref_xray_memory_limit_mb`.

| Feature | Evidence | Confidence | Router equivalent | Component | Priority |
| --- | --- | --- | --- | --- | --- |
| RemoteListManager | `file_url`, Loyalsoldier/runetfreedom/Chocolate4U in dex | STATIC_CONFIRMED | ETag/TTL/atomic/rollback | `remotelists` | P1 |
| RemotePolicyManager | full `x-*` set | STATIC_CONFIRMED | schema allowlist | `remotepolicy` | P1 |
| x-telegram-ips / x-whatsapp-ips | libapp | STATIC_CONFIRMED | list files | `remotelists` | P1 |
| x-pokaz-key / x-contacts / x-support-chat-url | libapp | STATIC_CONFIRMED | UI/provider only | provider/web | P2 |
| x-apple-direct | libapp | STATIC_CONFIRMED | routing hint if useful on router | `routing` | P2 |

Test/hardware: NOT RUN.

## 12. DNS / QUIC / fragment / mux / sniffing / sockopt / policy

| Feature | Evidence | Confidence | Router equivalent | Component | Priority |
| --- | --- | --- | --- | --- | --- |
| FakeDNS / DNS direct | libapp FakeDNS, x-fake-dns, x-dns-direct; DoH URLs 1.1.1.1 / 8.8.8.8 | STATIC_CONFIRMED | Xray DNS, no extra daemon | `dns` | P0 |
| Block QUIC | x-block-quic | STATIC_CONFIRMED | setting + capture | `routing` | P1 |
| Fragment | fragment_bean, x-fragment-* | STATIC_CONFIRMED | Advanced generator | `xray` | P1 |
| Mux / XUDP | mux_bean, x-mux-* | STATIC_CONFIRMED | safe defaults off | `xray` | P1 |
| Sniffing | sniffing_bean; template destOverride http/tls/quic | STATIC_CONFIRMED | generator | `xray` | P0 |
| TFO / TCP nodelay / domain strategy | x-tcp-fast-open, x-tcp-no-delay, x-domain-strategy | STATIC_CONFIRMED | capability-aware | `xray`, `platform` | P1 |
| Xray policy / memory saver / burst | policy_bean, x-policy-*, x-memory-saver, burst prefs | STATIC_CONFIRMED | `XrayRuntimePolicy` Advanced | `xray` | P1 |
| Local SOCKS 10808 / HTTP 10809 | template JSON | STATIC_CONFIRMED | optional, not WAN | `xray` | P1 |

## 13. LAN / per-device

| Feature | Evidence | Confidence | Android behavior | Router equivalent | Component | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| Allow LAN | `Allow LAN` | STATIC_CONFIRMED | LAN to local proxies | LAN clients through VPN/direct | `routing` | P0 |
| Hotspot / share VPN WiFi | `Hotspot` dex+libapp | STATIC_CONFIRMED | Android hotspot | LAN/WiFi client routing | `routing` | ANDROID_SPECIFIC |
| Per-app routing | orchestrator; no Android apps on router | ANDROID_SPECIFIC | per-app | **per-device** IP/MAC/hostname/alias | `routing` | P0 |

`ProviderDevice` ≠ `LanClient`.

## 14. Logging / memory / health

| Feature | Evidence | Confidence | Router equivalent | Component | Priority |
| --- | --- | --- | --- | --- | --- |
| Logs | xray-log-, XraySettingsScreen | STATIC_CONFIRMED | `/opt/blacktemple-kn/logs/` rotating + redaction | `diagnostics` | P0 |
| Memory monitor | `syncXrayMemoryToNative`, `getXrayMemoryLimitMb`, ChatCmd | STATIC_CONFIRMED | `/proc` RSS CPU, no invented numbers | `diagnostics` | P0 |
| Ping / diagnosis | generate_204, ipwho.is | STATIC_CONFIRMED | split latency vs proxy vs internet | `diagnostics` | P0 |
| XRayTestService | dex class | STATIC_CONFIRMED | xray run -test | `xray` | P0 |

## 15. Cabinet / billing / devices / news / support / TV

| Feature | Evidence | Confidence | Router equivalent | Component | Priority |
| --- | --- | --- | --- | --- | --- |
| Cabinet JWT | CabinetAPI, refresh_token, Bearer | STATIC_CONFIRMED | optional provider | `provider` | P2 |
| Cabinets list/roles/countries | getAllCabinets, getRoles, getCountries | STATIC_CONFIRMED | optional | `provider` | P2 |
| Devices create/delete | createDevice, deleteDevice | STATIC_CONFIRMED | ProviderDevice | `provider` | P2 |
| Pay / tariff / balance / daily debit | pay(sum), tariff, balance, daily debit | STATIC_CONFIRMED | display only, no netns access | `provider` | P2 |
| News | orchestrator; not strongly isolated in strings this scan | INFERRED | optional notifications | `news` | P2 |
| Support chat + commands | ChatCmd, attachment, socket.io string | STATIC_CONFIRMED | SupportCommand allowlist, default off | `support` | P2 |
| TV pairing | `TV pairing`, `TV code`, `tvreg_` telegram start | STATIC_CONFIRMED | LAN pairing token | `pairing` | P2 |

## 16. Quick Tile / widget / app update

| Feature | Evidence | Confidence | Router equivalent | Component | Priority |
| --- | --- | --- | --- | --- | --- |
| Quick Settings Tile | `MyTileService`, `TileBlacktemple` | STATIC_CONFIRMED | mobile Web / PWA shortcut | `web` | ANDROID_SPECIFIC |
| Home widget | `WidgetProvider` | STATIC_CONFIRMED | same | `web` | ANDROID_SPECIFIC |
| App update | `Checking for update: GET https://api.github.com/repos/BLACKTEMPLE-SPACE/Blacktemple.apk/releases/latest` | STATIC_CONFIRMED | GitHub Releases for **this** project, channels stable/dev, no blind latest | `updater` | P1 |

## 17. Extra Android-only (do not port)

| Feature | Evidence | Confidence | Note |
| --- | --- | --- | --- |
| Flutter + Rive + Lottie + Ubuntu/Roboto fonts | native libs, FontManifest, lotti json | STATIC_CONFIRMED | forbidden in router UI |
| MMKV / Hive | libmmkv, Hive strings | STATIC_CONFIRMED | JSON files instead |
| JNI Xray | libgojni.so | STATIC_CONFIRMED | external process instead |
| iOS tun2socks buffer copy | string "iOS only" | STATIC_CONFIRMED | ignore |

## Coverage summary

| Area | Matrix rows | Implementation this wave |
| --- | --- | --- |
| Baseline §7.1–7.34 | covered | docs + contracts only |
| Extra APK findings | covered | none in runtime |
| Black-box UI confirmation | 0 | NOT RUN |
