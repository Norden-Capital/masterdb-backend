# masterdb-backend
Backend for MasterDB, handling email validation, bounce management, deduplication, suppression lists, and contact segmentation.

## Build & run

Stack: Spring Boot 4.1.2, Java 21, Maven (wrapper included), PostgreSQL 16 + Flyway.

### Build and test

No Docker needed: the tests start an embedded PostgreSQL 16 and run Flyway against it.

```bash
./mvnw clean verify
```

### Run locally

Start Postgres (and optionally pgAdmin) with Docker, then the app on the host:

```bash
docker compose up -d db          # Postgres on 127.0.0.1:5432
./mvnw spring-boot:run           # API on http://localhost:8080
curl http://localhost:8080/actuator/health
```

`docker compose up -d pgadmin` opens pgAdmin on http://localhost:5050 (local only).

### Configuration

| Variable | Default (local dev only) |
| --- | --- |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/masterdb` |
| `SPRING_DATASOURCE_USERNAME` | `masterdb` |
| `SPRING_DATASOURCE_PASSWORD` | `masterdb-local-dev` |

Schema changes go in `src/main/resources/db/migration` as Flyway scripts
(`V1__description.sql`, ...). Hibernate only validates the schema.

### API conventions

Every endpoint lives under `/api/v1`. These rules hold for every module; the code is in
`src/main/java/ca/nordencapital/masterdb/web/`.

#### Errors

Every error, from a controller, from Spring MVC, or from the container's `/error` forward,
is `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)):

```json
{
  "title": "Bad Request",
  "status": 400,
  "detail": "The request has invalid fields.",
  "instance": "/api/v1/contacts",
  "code": "VALIDATION_FAILED",
  "errors": [
    { "field": "email", "message": "must be a well-formed email address" }
  ],
  "timestamp": "2026-11-06T17:03:34.933Z",
  "requestId": "3f2b9c1e-8a8d-4c7e-9a43-0f4b8d1c2e55"
}
```

- Clients switch on `code`; `title` and `detail` are for people and may change.
- `instance` is the path only, never the query string. Rejected values are never echoed back.
- `errors` (`field` + `message`) only appears with `VALIDATION_FAILED`.
- A 500 always says "An unexpected error occurred. Quote the requestId when reporting it."
  The exception and stack trace go to the server log with the same `requestId`, never to the client.

| `code` | Status | When |
| --- | --- | --- |
| `VALIDATION_FAILED` | 400 | Bean validation on a body or a parameter, wrong type (`?size=abc`), missing required parameter, bad `page`/`sort`, `BadRequestException.validation(...)` |
| `MALFORMED_JSON` | 400 | Body missing, not JSON, or the wrong JSON shape |
| `BAD_REQUEST` | 400 | `BadRequestException` and other client errors |
| `UNAUTHORIZED` / `FORBIDDEN` | 401 / 403 | Reserved for auth (M1) |
| `NOT_FOUND` | 404 | Unknown route, `NotFoundException` |
| `METHOD_NOT_ALLOWED` | 405 | Wrong HTTP method (the `Allow` header lists the right ones) |
| `NOT_ACCEPTABLE` | 406 | `Accept` the endpoint cannot produce |
| `CONFLICT` | 409 | `ConflictException` |
| `CONTENT_TOO_LARGE` | 413 | Upload or body over the limit |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Wrong `Content-Type` |
| `TOO_MANY_REQUESTS` | 429 | Reserved for rate limits |
| `SERVICE_UNAVAILABLE` | 503 | Reserved |
| `INTERNAL_ERROR` | 500 | Anything unexpected |

In code, throw `NotFoundException`, `ConflictException` or `BadRequestException`
(package `web.error`). Their message becomes `detail`, so write it for the user and keep
internals out of it. Anything else becomes a generic 500. Never build error bodies by hand.

#### Request ID

- The `X-Request-Id` request header is reused when it is 1 to 64 characters of
  `[A-Za-z0-9-]`; otherwise (missing or unsafe) the server generates a UUID.
- It comes back as the `X-Request-Id` response header on every response, appears as
  `requestId` in every error body, and is on every log line as `[<id>]`.

#### Request log

One line per request: `GET /api/v1/status 200 3ms requestId=...`. The path only: no query
string, headers or bodies, because emails travel in them. `/actuator/health` is not logged.

#### Pagination

List endpoints take `@ParameterObject PageParams` and return `PageResponse<T>`:

| Param | Default | Rules |
| --- | --- | --- |
| `page` | `0` | Zero-based; negative → 400 `VALIDATION_FAILED` |
| `size` | `25` | Clamped to 1..100 (never an error) |
| `sort` | per endpoint | `field` or `field,asc\|desc`, repeatable (`?sort=lastName&sort=createdAt,desc`). Only the fields the endpoint whitelists; anything else → 400 `VALIDATION_FAILED` |

```json
{ "items": [ ... ], "page": 0, "size": 25, "totalItems": 1234, "totalPages": 50 }
```

`size` is the page size used (after clamping), not the number of items on this page.

```java
private static final Set<String> SORTABLE = Set.of("createdAt", "email");

@GetMapping
PageResponse<ContactDto> list(@ParameterObject PageParams params) {
    Pageable pageable = params.toPageable(SORTABLE, Sort.by("createdAt").descending());
    return PageResponse.from(repository.findAll(pageable), ContactDto::from);
}
```

#### JSON

Dates are ISO-8601 strings in UTC (`2026-11-06T12:00:00Z`), never numeric timestamps; use
`Instant` in DTOs. Fields that are `null` are left out of the response.

### Deploy

Every push to `main` runs `.github/workflows/ci-cd.yml`: build and test, push the
image to `ghcr.io/norden-capital/masterdb-backend`, then deploy over SSH to
`/opt/masterdb` on the VPS. The server is prepared once with `deploy/vps-setup.sh`.

Repository secrets: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`, `POSTGRES_PASSWORD`.
