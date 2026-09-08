# R0 bootstrap evidence

Date: 2026-09-08

## Commands

```text
gh auth status
python .research-local\scan_apk.py
gofmt -w src tools
powershell -File .\build.ps1
```

## Frontend

```text
vitest: 1 passed
vite dist gzip html+js+css = 5765 bytes (limit 256000)
```

## Go

```text
go test ./src/... ./tools/... PASS
```

## ELF

```text
elf class=ELFCLASS32 data=ELFDATA2LSB machine=EM_MIPS type=ET_EXEC dynamic=false
PASS out\bin\blacktempled
size bytes: 6750401
```

## IPK

```text
out\blacktemple-kn_0.1.0-dev_mipsel-3.4_kn.ipk
size bytes: 2413612
sha256: 2a8240081212ac3920d68302fd6df0822dc3407ad33464e7c32a76c4b7bcc79d
```

## Not run

- QEMU
- KN-1011
- Xray download into IPK
- VPN connect
