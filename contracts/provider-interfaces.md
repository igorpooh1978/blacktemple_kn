# Provider interfaces (freeze)

Go interfaces to be implemented in later waves. No proprietary URLs here.

```text
Provider
  Name() string
  Capabilities() CabinetCapability

CabinetCapability
  Auth
  Balance
  Tariffs
  Devices          // ProviderDevice, not LanClient
  Countries
  ChangeKey
  News
  Support
  Pairing
  SpecialModes     // includes whitelist_mode if advertised

ListSource
ListDescriptor
ListVersion
ListCache
```

Core VPN must run if Provider is `none`.
