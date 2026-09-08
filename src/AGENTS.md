# src/

Go daemon and libraries.

- Production: `CGO_ENABLED=0`.
- No DI framework, ORM, CQRS, event bus.
- Xray is not imported as a library.
- Secrets never logged.
- JSON atomic writes only (`config` package in later waves).
- Do not edit `contracts/` from this tree without orchestrator assignment.
