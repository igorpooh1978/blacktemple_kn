# B contract gap (R4)

Domain layer for profiles / subscription / keys / servers / countries can proceed
without OpenAPI edits. Gaps that later waves should reopen with the orchestrator:

| Topic | Frozen contract | Domain implemented | Gap |
| --- | --- | --- | --- |
| Import | `POST /api/v1/profiles` + `ImportKeyRequest` | `profiles.Service.Import` | HTTP wiring is Agent A; 501 today |
| Refresh | none | `Service.Refresh` | no operation in OpenAPI |
| Candidate select / rotate / change server | `server.mode` in config schema only | `SelectCandidate`, `ChangeServer`, `Rotate`, `SelectServerMode` | no HTTP ops |
| Change key | provider-interfaces `ChangeKey` capability name | `keys.KeyChanger` port; never calls `/keys/change` | no request/response schema; no URL by design |
| Rollback / last-known-good | `runtime-state.lastKnownGood` has `profileId`, `xrayConfigPath`, `savedAt` | domain LKG is `profileId` + `keyId` + `serverId` | no `keyId`/`serverId` on the frozen object; `xrayConfigPath` belongs to Xray wave |
| Entities | `xray-profile.schema.json` is a flat generator blob | Profile, Subscription, Key, Server, Country, ConnectionCandidate are separate | schema is generator input, not the store model |
| Countries | none in OpenAPI | `countries.Catalog` | no catalog endpoint; remote BlackCountry payload still `NOT OBSERVED` |
| Secret policy | "never echoed back" on `blackKey` | redacted `String()` / JSON / errors | listProfiles response schema is unspecified beyond "redacted" |

No OpenAPI or JSON Schema files were modified.
