# R6 capture.engine mapping (not a schema freeze)

Frozen schema: `contracts/schemas/config.schema.json`  
Path: `properties.capture.properties.engine.enum`

Current frozen values (unchanged):

```text
unspecified
transparent-iptables
xray-tun
```

Runtime implementation on KN-1011:

```text
hybrid-iptables
```

## Mapping

```text
persisted contract:     capture.engine = transparent-iptables
runtime implementation: hybrid-iptables
```

`transparent-iptables` is the engine family / user-config value.
`hybrid-iptables` is the selected KN-1011 implementation (TCP REDIRECT + UDP TPROXY).

For Auto / `unspecified`, the runtime selector may choose `hybrid-iptables`.

This wave does **not** edit `contracts/`. No enum addition is required in R6.
Do not mark capture `SUPPORTED`.
