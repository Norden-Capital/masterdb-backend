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
./mvnw spring-boot:run           # API on http://localhost:8080 (profile "local")
curl http://localhost:8080/actuator/health
```

`docker compose up -d pgadmin` opens pgAdmin on http://localhost:5050 (local only).

### API docs (local only)

Swagger UI and the OpenAPI JSON are **off by default and always off on the server**
(`docker-compose.yml` sets `APP_DOCS_ENABLED=false`). There, every docs path answers
`404` with the normal error body, as if it did not exist.

`./mvnw spring-boot:run` starts with the `local` profile (`application-local.yml`, set in
`pom.xml` as `spring-boot.run.profiles`), which switches them on:

| What | URL |
| --- | --- |
| Swagger UI | http://localhost:8080/api/docs |
| OpenAPI JSON | http://localhost:8080/api/v3/api-docs |

Running the jar some other way (IDE, `java -jar`): add the profile
(`--spring.profiles.active=local`) or set `APP_DOCS_ENABLED=true`.

### Configuration

| Variable | Default (local dev only) |
| --- | --- |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/masterdb` |
| `SPRING_DATASOURCE_USERNAME` | `masterdb` |
| `SPRING_DATASOURCE_PASSWORD` | `masterdb-local-dev` |
| `APP_DOCS_ENABLED` | `false` (`true` in the `local` profile) |
| `PROXY_SECRET` | none: **required in production** (the app refuses to start without it, or with under 32 characters). In the `local` profile, unset = check off |
| `APP_CORS_ALLOWED_ORIGINS` | `https://db.nordencapital.ca` (the `local` profile adds `http://localhost:3000`) |
| `BOOTSTRAP_OWNER_EMAIL`, `BOOTSTRAP_OWNER_PASSWORD`, `BOOTSTRAP_OWNER_NAME` | none, optional: the first account (see "Users & owner bootstrap"). Unset = no account and a warning |

### Only the website may call the API

The browser never calls this server. It calls `/api/...` on the website, whose server
(the Route Handler `app/api/[...path]/route.ts` in masterdb-frontend) forwards the
request here with the header `X-Proxy-Secret: <PROXY_SECRET>`.
`web/security/ProxySecretFilter` refuses every request without the right value with
401 `PROXY_SECRET_INVALID` (same answer whether the header was missing or wrong;
constant-time comparison; the value is never logged). Only `/actuator/health` is open,
for the deploy check. The same value lives in three places: the GitHub secret
`PROXY_SECRET` (written to the server's `.env` by the deploy), the Vercel variable
`PROXY_SECRET`, and `.env.local` of masterdb-frontend on a developer PC.

Fail closed: the jar's default is `app.proxy.required: true`, so a server without the
secret does not start (and the deploy stops earlier, with a clear message, when the
GitHub secret is empty). Only the `local` profile and the tests set `required: false`.
To try the check locally, set `PROXY_SECRET` before `./mvnw spring-boot:run`.

`web/security/CorsConfig` lets browsers call the API only from
`APP_CORS_ALLOWED_ORIGINS` (GET, POST, PUT, PATCH, DELETE, credentials allowed for the
M1 login cookie). Refusals are 403 problem+json.

### Users & owner bootstrap

People who sign in live in `users` (`V1__users.sql`, code in `auth/`). Login, 2FA,
permissions and invites come later, each with its own migration.

| Column | Rule |
| --- | --- |
| `id` | bigint identity, internal only (joins). Never in the API |
| `public_id` | random uuid: the only id the API ever shows |
| `email` | stored trimmed + lowercased; unique index on `lower(email)`, so `Jane@X.com` and `jane@x.com` can never both exist, even when written by hand in SQL. Chosen over `citext`: no extension to install, and Hibernate's schema validation understands varchar |
| `full_name` | required |
| `password_hash` | `{bcrypt}$2a$12$...`; null only while invited. An `ACTIVE` account must have one (check constraint) |
| `status` | `ACTIVE` / `INVITED` / `DISABLED` (check constraint) |
| `is_owner` | at most one row, by a partial unique index; the Owner must be `ACTIVE`. The Owner sees everything; other people will get per-user grants (modules × actions) in a separate table |
| `failed_login_attempts`, `locked_until`, `last_login_at` | for the login step |
| `created_at`, `updated_at` | timestamptz, `Instant` in Java |

**Passwords** (`auth/password/PasswordConfig`): only `spring-security-crypto`, not the
full Spring Security starter yet. A `DelegatingPasswordEncoder` whose default is BCrypt
cost 12: every hash starts with `{bcrypt}`, so a stronger algorithm (Argon2id) can be
added later and old hashes keep working. BCrypt over Argon2id for now: no extra
BouncyCastle dependency and no per-login memory budget to tune next to Postgres, for a
few staff accounts that also have mandatory 2FA. BCrypt uses at most 72 bytes of a
password. A hash with an unknown prefix never matches (no exception).

**The first Owner** (`auth/bootstrap/OwnerBootstrap`) is created at startup when **all**
of these hold:
- the `users` table is empty (otherwise the only log line is `bootstrap skipped: users exist`, and the variables are ignored for good);
- `BOOTSTRAP_OWNER_EMAIL` and `BOOTSTRAP_OWNER_PASSWORD` are set (otherwise a WARN line and no account; there is **no default password**);
- the email looks valid and the password has at least 14 characters (and at most 72 bytes); otherwise an ERROR line and no account.

`BOOTSTRAP_OWNER_NAME` is optional (default `Owner`). The account is `ACTIVE` and the
Owner. It runs in one transaction behind a Postgres advisory lock, so two instances
starting together create one Owner; the unique indexes back that up. The password is
never logged; the email only masked: `owner created: j***@nordencapital.ca (id <uuid>)`.

On the server the three values are GitHub secrets that the deploy writes to
`/opt/masterdb/.env` (single-quoted, so the deploy refuses values containing `'`, `\`
or a line break) and `docker-compose.yml` passes to the container. They are optional:
unlike `PROXY_SECRET`, an empty value does not stop the deploy, because the password
secret should be deleted once the Owner exists. After that, the next deploy removes it
from the server's `.env` too.

Locally: set the three variables before `./mvnw spring-boot:run` against an empty local
database (`docker compose up -d db`), or create nothing and see the warning.

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
| `UNAUTHORIZED` / `FORBIDDEN` | 401 / 403 | Reserved for auth (M1); `FORBIDDEN` also for a refused CORS origin |
| `PROXY_SECRET_INVALID` | 401 | The request did not come through the website (`X-Proxy-Secret` missing or wrong) |
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

### Backups

The database is backed up every night on the VPS, and every Sunday a restore of the
newest backup is tested automatically. The files are in `deploy/backup/`;
`deploy/vps-setup.sh` installs them on a new server.

| What | Where |
| --- | --- |
| Dumps | `/var/backups/masterdb/masterdb-YYYYmmdd-HHMMSS.dump` (root only: folder 700, files 600) |
| Format | `pg_dump -Fc`: compressed, restored with `pg_restore` |
| When | Daily at 03:15 server time (Europe/Berlin), up to 10 min later at random. Missed runs (server off) catch up at boot |
| Kept | The newest 14 dumps. Old ones are deleted only after a new dump has been written and checked, so a failing backup never deletes good ones. Manual runs count towards the 14 |
| Restore test | Sundays at 04:00: restores the newest dump into a throwaway container and compares `flyway_schema_history` with the live DB. Prints `PASS` or `FAIL` |
| Scripts | `/usr/local/sbin/masterdb-backup`, `/usr/local/sbin/masterdb-restore-test`, `/usr/local/sbin/masterdb-backup-status` (writes `status.json`) |
| Status | `/var/backups/masterdb/status.json`, rewritten after every backup and restore test (see below) |
| Timers | `masterdb-backup.timer`, `masterdb-restore-test.timer` (units in `/etc/systemd/system/`) |

**The dumps are on the same server as the database.** If the VPS is lost, so are they.
A copy somewhere else is still to be set up (M0 follow-up).

All commands below run as root on the VPS (`ssh root@<vps>`).

#### Check that backups are running

```bash
systemctl list-timers 'masterdb-*'           # NEXT / LAST run of both timers
journalctl -u masterdb-backup -n 20          # last backup: "OK: masterdb-....dump, <size>, ..." and "kept N dump(s)"
journalctl -u masterdb-restore-test -n 20    # last restore test: ends with PASS or FAIL
systemctl --failed                           # a failed backup shows up here as masterdb-backup.service
ls -lh /var/backups/masterdb                 # the dumps; the newest should be from last night
```

Run either one by hand at any time (safe, read-only for the live database):

```bash
systemctl start masterdb-backup && journalctl -u masterdb-backup -n 5 --no-pager
masterdb-restore-test
```

A `FAIL` from the restore test saying the row counts differ right after a deploy that
added a migration is expected (the dump is older than the migration): run
`systemctl start masterdb-backup`, then `masterdb-restore-test` again.

#### status.json: the hook for the app

After every run (successful or not) both scripts update `/var/backups/masterdb/status.json`
through `masterdb-backup-status`. **This file is the future integration point for the app:**
a later Backups page (run now, pause, delete a backup, change the schedule, restore) will
read its state from here, while the scripts and timers stay the engine that does the work.
It holds no secrets and no data from the database. Example:

```json
{
  "lastBackup": { "startedAt": "2026-11-06T17:45:05Z", "finishedAt": "2026-11-06T17:45:07Z", "ok": true,
                  "file": "masterdb-20261106-184505.dump", "sizeBytes": 2503, "durationMs": 1491, "error": null },
  "retentionDays": 14,
  "lastRestoreTest": { "at": "2026-11-06T17:45:07Z", "ok": true,
                       "detail": "PASS: masterdb-20261106-184505.dump restored, flyway_schema_history rows 0 = live 0, 1 tables, 11s" },
  "schedule": { "backup": ["*-*-* 03:15:00"], "restoreTest": ["Sun *-*-* 04:00:00"] },
  "backups": [ { "file": "masterdb-20261106-184505.dump", "sizeBytes": 2503, "createdAt": "2026-11-06T17:45:06Z" } ],
  "updatedAt": "2026-11-06T17:45:18Z"
}
```

- Times are UTC (ISO-8601). `backups` is newest first and is re-read from the folder on every write.
- On a failed backup, `ok` is `false`, `file`/`sizeBytes` are `null` and `error` says why
  (details in `journalctl -u masterdb-backup`). `detail` of the restore test is its PASS/FAIL line.
- `retentionDays` is the number of dumps kept; with one dump a day that is days.
- `schedule` is read from the timers (`OnCalendar`, drop-in overrides included), so it stays right
  if the schedule is changed with `systemctl edit masterdb-backup.timer`.
- Written atomically (temp file + rename), so a reader never sees half a file. Mode 644, but the
  folder is root-only (700): the backend container cannot read it yet. Giving the app access
  (e.g. a read-only mount of this one file) is part of building the Backups page.

```bash
jq . /var/backups/masterdb/status.json      # pretty-print it on the VPS
```

#### Restore manually: into a scratch database first

Always look at a backup in a separate database before touching the live one. The
scratch database lives in the same Postgres container, next to `masterdb`, and
the app never sees it.

1. Pick the dump (newest is last):
   ```bash
   ls -lh /var/backups/masterdb
   DUMP=/var/backups/masterdb/masterdb-20261106-031702.dump    # your file name
   ```
2. Create an empty scratch database and restore into it:
   ```bash
   docker exec masterdb-postgres createdb -U masterdb masterdb_restore
   docker exec -i masterdb-postgres pg_restore -U masterdb -d masterdb_restore \
     --no-owner --exit-on-error < "$DUMP"
   ```
   No output means it worked.
3. Look around:
   ```bash
   docker exec -it masterdb-postgres psql -U masterdb -d masterdb_restore
   #   \dt                                   list tables
   #   select count(*) from flyway_schema_history;
   #   \q                                    quit
   ```
4. Remove the scratch database when done:
   ```bash
   docker exec masterdb-postgres dropdb -U masterdb masterdb_restore
   ```

The scratch database needs about as much disk as the live one. `df -h /` shows what is free.

#### Restore over the live database (emergency only)

Use this when the live data is damaged or lost. It does **not** delete the damaged
database: it renames it out of the way, so you can still go back to it. Do the
scratch restore above first to be sure the dump is the one you want.

1. Pick the dump (as above) and stop the backend, so nothing writes while you work:
   ```bash
   DUMP=/var/backups/masterdb/masterdb-20261106-031702.dump    # your file name
   cd /opt/masterdb && docker compose stop backend
   ```
2. Rename the damaged database (the date in the name is today's):
   ```bash
   docker exec masterdb-postgres psql -U masterdb -d postgres -c \
     "select pg_terminate_backend(pid) from pg_stat_activity where datname = 'masterdb' and pid <> pg_backend_pid()"
   docker exec masterdb-postgres psql -U masterdb -d postgres -c \
     "alter database masterdb rename to masterdb_damaged_$(date +%Y%m%d)"
   ```
3. Create a new empty `masterdb` and restore the dump into it. `--single-transaction`
   means it either fully works or leaves the new database empty:
   ```bash
   docker exec masterdb-postgres createdb -U masterdb -O masterdb masterdb
   docker exec -i masterdb-postgres pg_restore -U masterdb -d masterdb \
     --no-owner --exit-on-error --single-transaction < "$DUMP"
   docker exec masterdb-postgres psql -U masterdb -d masterdb -c "select count(*) from flyway_schema_history"
   ```
4. Start the backend again and check it:
   ```bash
   docker compose start backend
   curl -s http://127.0.0.1:8080/actuator/health        # {"status":"UP"...}
   ```
   Everything written after the dump was taken is not in the restored database.
5. When you are sure the restored data is right (days later, not minutes), remove the
   damaged copy:
   ```bash
   docker exec masterdb-postgres psql -U masterdb -d postgres -l                      # lists masterdb_damaged_...
   docker exec masterdb-postgres dropdb -U masterdb masterdb_damaged_20261106          # its exact name
   ```

**Going back** (the restore was the wrong choice): stop the backend, rename the new
`masterdb` to `masterdb_restored_<date>`, rename `masterdb_damaged_<date>` back to
`masterdb`, start the backend.

**New server** (the VPS is gone): set it up with `deploy/vps-setup.sh`, deploy once
(CI) so the containers exist, copy a dump into `/var/backups/masterdb/` (from the
off-site copy), then steps 1 to 4 above. Do not skip step 2: the first deploy has
already created a nearly empty `masterdb` (Flyway), and it has to move out of the way.

### Deploy

Every push to `main` runs `.github/workflows/ci-cd.yml`: build and test, push the
image to `ghcr.io/norden-capital/masterdb-backend`, then deploy over SSH to
`/opt/masterdb` on the VPS. The server is prepared once with `deploy/vps-setup.sh`.

Repository secrets: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`, `POSTGRES_PASSWORD`, `PROXY_SECRET`.
Optional: `BOOTSTRAP_OWNER_EMAIL`, `BOOTSTRAP_OWNER_NAME`, `BOOTSTRAP_OWNER_PASSWORD`
(the first account; delete the password one once the Owner exists).
