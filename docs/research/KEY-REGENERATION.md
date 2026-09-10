# Key regeneration — sanitized APK contract

Status: **BLOCKED_CONTRACT_NOT_PROVEN**

This document records only what is already in git research and ADRs.
It does not copy proprietary hosts, tokens, UUIDs, Authorization headers,
or real BlackKey material.

## Proven (STATIC_CONFIRMED names only)

| Item | Evidence | Proven? |
| --- | --- | --- |
| Trigger / action name | `[CabinetAPI] changeKey` in APK strings | name only |
| Path fragment | `/keys/change` | fragment only — not a full URL |
| Type names | `ChangeKeyRequest` / `ChangeKeyResponse` | names only |
| Cabinet auth family | Cabinet JWT / `refresh_token` / Bearer (cabinet, not proven for this call) | not bound to changeKey |
| Core VPN independence | ADR-007: cabinet is optional | yes |

## Not proven (must not be invented)

- Full HTTPS endpoint (scheme + host + path)
- HTTP method
- Request field names and types
- Response shape (share URI vs subscription URL vs JSON vs other DTO)
- Whether the old key becomes invalid
- Failure status codes
- Rate-limit behavior
- Whether a router daemon may call cabinet without a user JWT

ADR-007: observed host strings exist in the APK; publishing or calling that
proprietary API is out of scope until a confirmed contract is frozen.

`keys.KeyChanger` remains the generic port. Production default is
`UnconfiguredChanger` → `ErrProviderNotConfigured`.

R7 does **not** hardcode `/keys/change` or a cabinet base URL.

## Production decision

```text
KEY REGENERATION CONTRACT = NOT PROVEN
KEY REGENERATION = BLOCKED_CONTRACT_NOT_PROVEN
```

Generic transactional ChangeKey (parse, persist, fail-closed, no netfilter)
is tested with a fake adapter. No live provider mutation in this wave.
