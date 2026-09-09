# R6 contract gap: capture.engine vs hybrid-iptables

Frozen schema: `contracts/schemas/config.schema.json`  
Path: `properties.capture.properties.engine.enum`

Current frozen values:

```text
unspecified
transparent-iptables
xray-tun
```

R6 runtime / ADR-011 name:

```text
hybrid-iptables
```

This wave does **not** edit `contracts/`. Agents must not silently rewrite the enum.

## Why it is a gap

ADR-009 listed candidates `transparent-iptables` and `xray-tun`. KN-1011 evidence selected a **hybrid** of IPv4 TCP REDIRECT + IPv4 UDP TPROXY on iptables/xtables. That is not TUN, and it is more specific than a generic "transparent iptables" label. Using a new runtime identifier avoids implying nft, a single REDIRECT path, or TUN.

## Suggested later mapping (orchestrator / later freeze)

Pick one, do not apply in R6:

1. **Add enum value** `hybrid-iptables` (preferred; matches ADR-011 / runtime).
2. **Alias**: store `transparent-iptables` in JSON and treat it as `hybrid-iptables` at runtime, documenting the alias in the schema description.

Until then:

- Runtime code may use `hybrid-iptables` internally.
- Persisted config that must validate against the frozen schema should keep `unspecified` or map only with an explicit documented alias — do not invent a third on-disk value that fails schema validation.
- Do not mark capture `SUPPORTED`.
