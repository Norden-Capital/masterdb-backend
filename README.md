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

Repository secrets: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`, `POSTGRES_PASSWORD`.
