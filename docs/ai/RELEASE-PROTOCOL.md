# Release protocol

Stable **нельзя** назвать DONE без:

- MIPS build PASS
- IPK PASS
- QEMU PASS
- KN-1011 PASS
- `go run ./tools/gherkincheck` PASS
- restart PASS
- key change PASS
- geodata PASS
- list update PASS
- rollback PASS
- routing PASS
- DNS PASS
- resource measurements

## Channels

- `stable`
- `dev`

Никакого blind `latest` install. Updater bot может открыть issue/PR candidate, но не катит stable lock автоматически.

## Не смешивать жизненные циклы

Application, Xray, geodata, remote lists, subscription, remote policy — отдельные version/cache/last-known-good/rollback.

## Артефакты GitHub Release

```text
install.sh
manifest.json
checksums.sha256
blacktemple-kn_VERSION_mipsel-3.4_kn.ipk
blacktemple-kn_VERSION_mipsel-3.4.ipk
blacktemple-kn_VERSION_mips-3.4.ipk
```
