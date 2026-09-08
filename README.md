# BlackTemple KN

Публичный open-source менеджер VPN для роутеров **Keenetic + Entware + Xray-core**.

Сложность внутри, простота снаружи:

```text
добавил BlackKey
↓
нажал Подключить
↓
работает
```

Это **не** порт Android-приложения. Это clean-room реализация наблюдаемого функционального поведения для Entware.

## Целевое железо (P0)

| Параметр | Значение |
| --- | --- |
| Модель | Keenetic KN-1011 |
| SoC | MediaTek MT7621 |
| CPU | MIPS 1004Kc, MIPS32r2, little-endian, soft float |
| Entware | 2025.05 |
| Arch | `mipsel-3.4_kn` |
| Сборка | `GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0` |

## Что уже есть в этом репозитории

- AI-first структура для параллельных агентов
- Clean-room capability matrix по reference APK `blacktemple1-3-12.apk`
- Замороженные контракты v0 (OpenAPI + JSON Schema)
- Windows toolchain: `build.ps1`, `tools/elfcheck`, `tools/ipkpack`
- Минимальный `blacktempled` hello-service (MIPSLE ELF + тестовый IPK)

## Чего здесь нет и не будет в git

- APK, декомпилированный код, графические assets, шрифты, Rive
- Реальные BlackKey, токены, пароли, private API secrets
- Слепое копирование Android TUN/hev/tun2socks архитектуры

Локальные исследовательские материалы: `.research-local/` (gitignore).

## Сборка на Windows 11

Требования: PowerShell, Go, Node.js, Git, GitHub CLI. WSL/Docker не нужны.

```powershell
.\bootstrap.ps1
.\build.ps1
```

Первый IPK:

```text
out/blacktemple-kn_0.1.0-dev_mipsel-3.4_kn.ipk
```

## Документы

- [AGENTS.md](AGENTS.md) — правила агентов
- [docs/ai/ORCHESTRATION.md](docs/ai/ORCHESTRATION.md) — оркестрация волн
- [docs/research/APK-FEATURE-MATRIX.md](docs/research/APK-FEATURE-MATRIX.md) — capability matrix
- [docs/architecture/overview.md](docs/architecture/overview.md) — архитектура
- [docs/hardware/KN-1011.md](docs/hardware/KN-1011.md) — железо

## Лицензия

Код проекта: [MIT](LICENSE).

Сторонние компоненты (Xray-core и geodata) имеют собственные лицензии. См. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
