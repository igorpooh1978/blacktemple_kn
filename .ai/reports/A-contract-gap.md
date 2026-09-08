# Agent A contract gaps (R4)

OpenAPI `contracts/openapi/blacktemple-kn.v0.yaml` was not modified.

## CSRF token header

Frozen OpenAPI has no CSRF cookie/header and no `securitySchemes`.

R4 protection for state-changing requests:

- session cookie `btkn_session` is `HttpOnly` + `SameSite=Lax`
- `Secure` only when the request is TLS (`r.TLS != nil`)
- cross-site POST is rejected when `Origin` or `Referer` is present and its host does not match `Host`

A dedicated `X-CSRF-Token` header is **not** required for this LAN cookie model. Adding it would be an OpenAPI change. If a later wave needs double-submit for non-browser clients, extend the contract first.

Missing `Origin`/`Referer` is allowed (LAN `curl` / same-site UI). SameSite still blocks cookie on cross-site POST.

## GET /api/v1/status auth

Frozen OpenAPI has no auth on `GET /api/v1/status`. Handler stays **unauthenticated** (session-optional). Status JSON is redacted (no secrets). Requiring a session would be a contract break.

## Session overlay not in OpenAPI

OpenAPI defines no security scheme. Overlay applied:

| Endpoint | Auth |
| --- | --- |
| `POST /api/v1/auth/setup` | unauthenticated; only when no password exists (`409` if initialized) |
| `POST /api/v1/auth/login` | unauthenticated |
| `POST /api/v1/auth/logout` | session required → `401` |
| `POST /api/v1/connection` | session required → `401`; nil `ConnectionService` → `501` |
| `GET`/`POST /api/v1/profiles` | session required → `401`; nil `ProfileService` → `501` |

`GET /api/v1/profiles` requiring a session is a security overlay, not in the YAML.

## Extra status codes

Not listed on every operation in OpenAPI, used for validation/abuse:

- `400` invalid JSON / short password / unknown `op`
- `403` CSRF Origin/Referer mismatch
- `429` login rate limit (30/min/IP)

## Login response body

`200` is frozen as “session cookie set” with no schema. Body is `{}`.
