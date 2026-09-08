# C-contract-gap: XrayProfileModel vs generator

Frozen schema: `contracts/schemas/xray-profile.schema.json`  
(`id`, `protocol`, `name`, `server`, `port`, `transport`, `security`, `country`).

R4 generator cannot emit a working VLESS outbound from the frozen object alone. Extra fields are passed internally as `xray.ConfigSecrets` and `xray.OutboundParams`. Schema was not edited.

## Required extension (orchestrator / later freeze)

| Field | Type | Where | Why |
| --- | --- | --- | --- |
| `uuid` | string (UUID) | ConfigSecrets | VLESS user id |
| `password` | string | ConfigSecrets | Trojan/SS later; redacted in logs |
| `privateKey` | string | ConfigSecrets | REALITY/WG client private material; never log |
| `flow` | string | OutboundParams | P0 default `xtls-rprx-vision` on TCP |
| `sni` / `serverName` | string | OutboundParams | TLS and REALITY |
| `publicKey` | string | OutboundParams | REALITY server public key |
| `shortId` | string | OutboundParams | REALITY |
| `fingerprint` | string | OutboundParams | uTLS; generator defaults `chrome` |
| `spiderX` | string | OutboundParams | REALITY |
| `path` | string | OutboundParams | ws / xhttp |
| `host` | string | OutboundParams | ws / xhttp |
| `serviceName` | string | OutboundParams | grpc |
| `alpn` | string[] | OutboundParams | TLS |
| `mode` | string | OutboundParams | xhttp (`auto` when path/host set) |

Recommended schema additions (do not apply in R4): `uuid`, `flow`, `sni`, `realityPublicKey`, plus transport extras. Keep secrets out of user-edited JSON; profile remains internal.

## R4 behavior without schema change

- Input: frozen `Profile` + `ConfigSecrets` + `OutboundParams`
- P0 outbound: VLESS + `tls` or `reality` (schema `xtls-vision` maps to TLS + vision flow)
- Inbound: SOCKS `127.0.0.1:11080` or `127.0.0.1:0` (ephemeral); LAN bind rejected
- Transports emitted: `tcp` / `ws` / `grpc` / `xhttp` only
- Not SUPPORTED on KN-1011 until hardware PASS
