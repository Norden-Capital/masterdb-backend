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
| `ENCRYPTION_KEY` | none: **required in production** (64 hex characters; encrypts 2FA secrets; the app refuses to start without it). In the `local` profile, unset = a random key per run. **Never change it once set** |
| `RESEND_API_KEY` | none, optional: emails (invitations, password resets) through Resend. Unset = the app runs and every email is a WARN line instead. The `local` profile and the tests never send |
| `NAMECHEAP_CLIENT_IP` | `147.93.4.107`: the server's public IPv4, sent as `ClientIp` on every Namecheap call; must be whitelisted in Namecheap |
| `NAMECHEAP_API_URL` | `https://api.namecheap.com/xml.response` (tests point it at a local fake) |
| `APP_DNS_RESOLVERS` | `1.1.1.1,8.8.8.8`: public resolvers the DNS health checks ask |
| `APP_DNSBL_RESOLVERS` | empty = the server's own resolver: used only for blocklist (DNSBL) lookups in server health (Spamhaus refuses public resolvers) |
| `APP_MAIL_FROM` | `MasterDB <no-reply@nordencapital.ca>` (the domain is verified in Resend) |
| `APP_FRONTEND_URL` | `https://db.nordencapital.ca` (`local`: `http://localhost:3000`): the website, for links in emails |
| `APP_AUTH_SESSION_IDLE_TIMEOUT`, `APP_AUTH_SESSION_ABSOLUTE_TIMEOUT` | `12h`, `7d` (see "Authentication") |
| `APP_AUTH_LOCKOUT_MAX_ATTEMPTS`, `APP_AUTH_LOCKOUT_DURATION` | `5`, `15m` |
| `APP_AUTH_RATE_LIMIT_PER_MINUTE`, `APP_AUTH_RATE_LIMIT_PER_HOUR` | `10`, `50` login attempts per client address |

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

Requests that carried the right secret are marked (`ProxySecretFilter.isVerified`); only
those may name the visitor's address in `X-Client-IP` (see "Authentication").

`web/security/CorsConfig` lets browsers call the API only from
`APP_CORS_ALLOWED_ORIGINS` (GET, POST, PUT, PATCH, DELETE, credentials allowed for the
M1 login cookie). Refusals are 403 problem+json.

### Users & owner bootstrap

People who sign in live in `users` (`V1__users.sql`, code in `auth/`). Login and
sessions: see "Authentication". 2FA, permissions and invites come later, each with its
own migration.

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

**Passwords** (`auth/password/PasswordConfig`): a `DelegatingPasswordEncoder` whose default is BCrypt
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

### Authentication

Login, logout and sessions (M1.2) and mandatory two-factor sign-in (M1.3): Spring
Security, stateless, with our own session cookie.

#### Endpoints

| Call | Open? | Answer |
| --- | --- | --- |
| `POST /api/v1/auth/login` `{email, password}` | yes | 200 `{"state":"TWO_FACTOR_REQUIRED"}` or `{"state":"TWO_FACTOR_SETUP_REQUIRED"}` + `Set-Cookie: md_preauth=...`. **Never a session by itself.** Failures: see below |
| `POST /api/v1/auth/login/2fa` `{code}` | `md_preauth` | an authenticator code or a recovery code → 200 `{"state":"AUTHENTICATED","user":{publicId,email,fullName,isOwner}}` + `Set-Cookie: md_session=...` |
| `POST /api/v1/auth/2fa/setup` | `md_preauth` (setup step) | 200 `{secret, otpauthUri, issuer, account}`: the QR code's content (`otpauth://totp/MasterDB:<email>?...`). Again = a new secret |
| `POST /api/v1/auth/2fa/setup/confirm` `{code}` | `md_preauth` (setup step) | the first code from the app → 200 `{"state":"AUTHENTICATED","user":{...},"recoveryCodes":[10 codes]}` + `md_session`. The codes are shown **this once** |
| `POST /api/v1/auth/logout` | session | 204, the session is revoked and the cookie deleted (`Max-Age=0`) |
| `GET /api/v1/auth/me` | session | 200 `{publicId,email,fullName,isOwner}` |

**Everything else needs a session (fail closed)**, except `GET /api/v1/status`,
`/actuator/health`, the API docs paths (404 unless docs are on) and `/error`. So an
endpoint added later is protected unless `web/security/SecurityConfig` opens it on
purpose. Without a session: 401 `UNAUTHENTICATED` (a cookie that did not work is deleted
in the same answer); signed in but not allowed: 403 `FORBIDDEN` (used from M1.4 on). Even
unknown routes answer 401 to signed-out callers.

#### Two-factor (M1.3)

- **Mandatory for everyone.** A right password opens a *login challenge*
  (`login_challenges`, `V3__two_factor.sql`): token in the cookie `md_preauth`
  (`HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth; Max-Age=600`), SHA-256 in the
  DB, 10 minutes, 5 wrong codes, single use. Only the code starts the session.
- **First sign-in without 2FA** (the Owner after the first deploy, every invited user):
  `TWO_FACTOR_SETUP_REQUIRED` → `/2fa/setup` (QR) → `/2fa/setup/confirm` with the first
  code → signed in, with 10 recovery codes (`xxxxx-xxxxx`), shown once.
- **TOTP** (RFC 6238, SHA1, 6 digits, 30 s; Google Authenticator, 1Password, ...):
  ±1 step of drift; **each step is accepted once** (`users.totp_last_used_step`), so a
  code cannot be replayed.
- **At rest:** the secret AES-256-GCM encrypted with `ENCRYPTION_KEY`
  (`crypto/SecretCipher`, bound to the user id); recovery codes as HMAC-SHA256 with a key
  derived from `ENCRYPTION_KEY`, so a database copy alone cannot brute-force them.
- **Guessing:** wrong codes count against the same 5-strikes account lock as wrong
  passwords, and a right password alone does **not** reset that count (only a full
  sign-in does). Code attempts have their own per-address rate limit (10/min, 50/h).
- Errors: 401 `INVALID_TWO_FACTOR_CODE` (wrong or reused code), 401
  `LOGIN_CHALLENGE_INVALID` (no, expired or used-up challenge: sign in again), 429
  `ACCOUNT_LOCKED`, 429 `RATE_LIMITED`.
- **`ENCRYPTION_KEY` must never change** once 2FA is in use: every enrolled authenticator
  would stop working (then reset everyone's 2FA, M1.5).

#### Permissions (M1.4)

Per-user grants on **module × action**, a permission is written `MODULE:ACTION`
(`CONTACTS:EXPORT`). Table `user_permissions` (`V4__user_permissions.sql`).

| Module | Actions |
| --- | --- |
| `DASHBOARD` | VIEW (added in M2, `V7__dashboard_permission.sql`: existing non-owner accounts got it) |
| `CONTACTS`, `SEGMENTS`, `SUPPRESSION` | VIEW, CREATE, EDIT, DELETE, EXPORT |
| `VALIDATION` | VIEW, RUN, EXPORT, DELETE |
| `SERVERS` | VIEW, CREATE, EDIT, DELETE, RUN (`V12__servers.sql`; replaced the unused `VALIDATION_SERVERS`, whose grants moved over) |
| `MTA` | VIEW, CREATE, EDIT, DELETE, RUN (`V12__servers.sql`; nobody gets it automatically) |
| `USERS` | VIEW, CREATE, EDIT, DELETE |
| `ACTIVITY_LOG` | VIEW, EXPORT |
| `BACKUPS` | VIEW, RUN, DELETE |
| `SETTINGS` | VIEW, EDIT |
| `DNS` | VIEW, CREATE, EDIT, DELETE, RUN (`V8__dns_namecheap_account.sql`; nobody gets it automatically) |

- **The Owner holds every permission** and needs no rows.
- Any action on a module implies its VIEW (saved with it).
- Controllers declare `@RequiresPermission(module = ..., action = ...)`; without it the
  answer is 403 `FORBIDDEN` (signed out stays 401). Changes apply on the next request.
- `GET /api/v1/auth/me` returns `permissions` (effective, sorted) so the UI can hide what
  the user cannot do. `GET /api/v1/permissions/catalogue` lists modules, actions and the
  presets **Viewer / Operator / Admin** (they only fill the editor; nothing links a user
  to a template).

#### DNS management

Namecheap account, domains, managed DNS records and DNS health (`dns/` package, V8–V11).

| Call | Permission |
| --- | --- |
| `GET /api/v1/dns/namecheap/account` (never the key, only `apiKeySet`) | DNS:VIEW |
| `PUT` it (key write-only, blank = keep) / `DELETE` it | DNS:EDIT / DNS:DELETE |
| `POST /api/v1/dns/namecheap/account/test` (getList; 200 with `ok` + `code`) | DNS:RUN |
| `GET /api/v1/dns/domains` (`q`, `source`, `expiry`, `health`, sort) / `GET …/{id}` | DNS:VIEW |
| `POST /api/v1/dns/domains` (by hand) / `GET /api/v1/dns/namecheap/domains` / `POST /api/v1/dns/domains/import` | DNS:CREATE |
| `DELETE /api/v1/dns/domains/{id}` | DNS:DELETE |
| `GET …/{id}/dns-settings`, `…/snapshots`, `…/snapshots/{sid}` | DNS:VIEW |
| `PUT …/{id}/dns-settings`, `GET …/records/preview`, `POST …/records/apply`, `GET …/snapshots/{sid}/restore-preview`, `POST …/snapshots/{sid}/restore` | DNS:EDIT |
| `GET …/{id}/health` / `POST …/{id}/health/check` | DNS:VIEW / DNS:RUN |

- Namecheap failures answer **424** with `NAMECHEAP_IP_NOT_WHITELISTED`, `NAMECHEAP_INVALID_KEY`,
  `NAMECHEAP_ERROR` or `NAMECHEAP_UNREACHABLE` (not 502: every 5xx detail is replaced by a
  generic text, and the user needs the reason). No account = 409 `NAMECHEAP_NOT_CONFIGURED`.
- Writes: `setHosts` replaces every record, so a write is always getHosts → merge (every
  unmanaged record kept) → preview with a `token` → apply with the token (409
  `DNS_CHANGED_SINCE_PREVIEW` if Namecheap changed) → snapshot → setHosts → getHosts to verify.
  Unsafe cases are 409 `DNS_WRITE_REFUSED`.
- Health: daily at 04:15 UTC (`app.dns.health-cron`) for every domain, plus "Re-check".

#### Server management

VPS servers reached over SSH, their health, their link to a domain, and the mail server
(MTA) on them (`servers/` package, V12 on). SSH is Apache Mina SSHD (`servers/ssh/`), with
BouncyCastle for ed25519.

**SSH key, never passwords.** MasterDB has ONE ed25519 key pair (`ssh_identity`, made on
the first `GET /api/v1/servers/ssh-key`). The private key is stored in OpenSSH format,
AES-GCM encrypted with `ENCRYPTION_KEY` (context `ssh:identity`), decrypted in memory only to
log in, never returned and never logged. The API shows the public key, its fingerprint and a
one-line command that appends it to `~/.ssh/authorized_keys` on the VPS (idempotent). The
SSH client uses only that key: no passwords, no `~/.ssh/config`, no keys or known_hosts from
the backend's home folder.

**Host keys: trust on first use, then strict.** "Connect" opens a connection only far enough
to read the host key (no login). With no trusted key yet the server becomes `KEY_PENDING`
and the fingerprint is shown once; "Trust" (with that exact fingerprint) pins the full key
and tests the login. After that every connection must present exactly the pinned key; no
prompt is ever shown again. A different key blocks the server (`KEY_CHANGED`, activity
`SERVER_HOST_KEY_CHANGED`, nothing is sent to it) until **the Owner** accepts the new key.
A new IP or SSH port forgets the pinned key. The login test reads `/etc/os-release` and
whether the user is root or has passwordless sudo (needed for the MTA).

| Call | Permission |
| --- | --- |
| `GET /api/v1/servers/ssh-key` → `{publicKey, fingerprint, installCommand, createdAt}` | SERVERS:VIEW |
| `GET /api/v1/servers` (`q` name/IP, `connection`, `expiry` EXPIRED/DAYS_14/DAYS_30; sort name, ip, expiresOn, createdAt, connectionStatus) / `GET …/{id}` | SERVERS:VIEW |
| `POST /api/v1/servers` `{name, ip, sshPort=22, sshUser=root, expiresOn, notes?, domainId?}` → 201 | SERVERS:CREATE |
| `PUT /api/v1/servers/{id}` (same body) | SERVERS:EDIT |
| `DELETE /api/v1/servers/{id}` (MasterDB only; nothing changes on the VPS) | SERVERS:DELETE |
| `POST …/{id}/connect` → `{outcome, message, server}`: KEY_PENDING, CONNECTED, AUTH_FAILED, UNREACHABLE or KEY_CHANGED (always 200) | SERVERS:RUN |
| `POST …/{id}/host-key/trust` `{fingerprint}` (first use only; 409 otherwise) | SERVERS:CREATE |
| `POST …/{id}/host-key/replace` `{fingerprint}` (**Owner only**, only while KEY_CHANGED) | SERVERS:EDIT + Owner |

- Only public IPv4 addresses (`app.servers.allow-private-ips`, true only in the `local`
  profile and the tests); one server per IP + port; one server per domain.
- Errors: 409 `SERVER_HOST_KEY_CHANGED` (blocked), 409 `SERVER_NOT_READY` (no trusted key
  yet), 424 `SSH_FAILED` (unreachable, key refused, timeout; `detail` says which).
- Activity: `SSH_KEY_CREATED`, `SERVER_ADDED`, `SERVER_UPDATED`, `SERVER_DELETED`,
  `SERVER_CONNECTED`, `SERVER_HOST_KEY_TRUSTED`, `SERVER_HOST_KEY_CHANGED`,
  `SERVER_HOST_KEY_REPLACED`, `SERVER_HEALTH_CHECKED`.
- Tests never reach a real server: `testsupport/FakeSshServer` is an embedded Mina SSH
  server on 127.0.0.1 with scripted answers (it never runs a shell).

**Health (job 2, `servers/health/`, V13).** Per check: OK, WARNING, PROBLEM, ERROR
(couldn't tell) or NOT_CHECKED, with the reason; the server's `healthStatus` is PROBLEM, else
ERROR, else WARNING, else OK. Re-check on demand, and every server daily at 04:30 UTC
(`app.servers.health-cron`).

| Check | How |
| --- | --- |
| SSH | logs in with MasterDB's key (one session, which also runs the port 25 test) |
| PORT25 | **on the VPS**, over SSH: bash `/dev/tcp` to `gmail-smtp-in.l.google.com`, `mta5.am0.yahoodns.net`, `outlook-com.olc.protection.outlook.com` port 25, 10 s each; OK on the first `220` greeting |
| PTR | from the backend (public resolvers, like DNS health): reverse DNS of the IP must be the linked domain's mail host |
| DNSBL | from the backend: Spamhaus ZEN, Barracuda, SpamCop, PSBL, UCEPROTECT L1, Mailspike. NXDOMAIN = not listed; 127.0.0.x = listed (Spamhaus codes named: SBL, CSS, XBL, DROP, PBL); 127.255.255.252/254/255 = Spamhaus **refused** the query and anything outside 127/8 = unreadable: both are ERROR, never "clean" |
| EXPIRY | WARNING within 14 days, PROBLEM once past |

| Call | Permission |
| --- | --- |
| `GET /api/v1/servers/{id}/health` → `{serverId, status, checkedAt, checks:[{check, status, detail, found}]}` | SERVERS:VIEW |
| `POST /api/v1/servers/{id}/health/check` (up to ~40 s when port 25 is blocked) | SERVERS:RUN |

The list takes `health` (OK, WARNING, PROBLEM, ERROR, UNCHECKED) and sorts by `healthStatus`.
`APP_DNSBL_RESOLVERS` picks the resolvers for blocklist lookups; empty (default) = the
server's own resolver. Spamhaus refuses public resolvers such as 1.1.1.1 and 8.8.8.8 (and
may refuse a busy shared one): then the DNSBL row says so instead of guessing.

**Domain link and probe identity (job 3, V14).** A server may be linked to one domain (one
server per domain). While linked:
- the domain's **mail IP is the server's IP**: `GET …/dns-settings` returns it as `mailIp` with
  `mailServer {publicId, name, ip}`, a typed `mailIp` is ignored (and comes back when the
  server is unlinked), and the managed records (A, SPF) and DNS health use it;
- the DNS module's **PTR check is on** (`dns/health/PtrExpectations`): the server's IP must
  resolve to its HELO host; server health checks the same;
- the server has a **probe identity** for Validation: `heloHost` and `mailFrom`, set to
  `mail.<domain>` and `postmaster@<domain>` when a domain is linked, editable, always on the
  domain or a host under it.

| Call | Permission |
| --- | --- |
| `PUT /api/v1/servers/{id}/identity` `{heloHost, mailFrom}` (400 off the domain, 409 `SERVER_NOT_READY` without a domain) | SERVERS:EDIT |

Activity: `SERVER_IDENTITY_CHANGED`.

**Install MTA (job 4, `mta/`, V15).** Ported from the old app's MTA plan (`MtaPlans.mtaScript`):
Postfix, Dovecot IMAP and OpenDKIM (selector `mail`, port 8891 milter), plus optional
Roundcube webmail with one mailbox, on Ubuntu 22.04 / 24.04 or AlmaLinux 8 / 9 / 10.

- **A background job in the database** (`mta_installs`): the page starts it and polls; closing
  the page changes nothing. One active job per server. At startup, jobs that were `QUEUED` or
  `RUNNING` become `INTERRUPTED` (the backend restarted); run the install again.
- **Steps, each a root script safe to repeat** (`bash -s`, through `sudo -n` for a non-root
  user): check the OS, packages (`apt-get` never prompts; waits for the dpkg lock), host name =
  the server's HELO host, Postfix settings (`postconf -e`), DKIM key, OpenDKIM config, start
  services, [webmail], read back the DKIM public key, hand it to DNS. Progress is
  `stepsDone / stepsTotal` exactly as finished; no estimate.
- **DKIM key made ON the server** (`opendkim-genkey -b 2048`, only if none exists). Only the
  public key is read back (from `mail.txt`); MasterDB never holds the private key.
- **DNS is never written silently**: the public key becomes the domain's DKIM setting
  (activity `DNS_SETTINGS_CHANGED`), the domain's A/MX/SPF already use the linked server's IP,
  and writing goes through the DNS module's preview → confirm → snapshot → write.
- **Log**: each output line goes through `mta/LogScrubber` (the mailbox password, any PEM
  private-key block, `password=`/`token=`/`api_key=`-style values) before it is stored; the
  newest 256 KB are kept. The mailbox password is sent once, inside the script on stdin, and
  is never stored.

| Call | Permission |
| --- | --- |
| `GET /api/v1/mta/candidates` → servers with `ready` / `reason` and their last install | MTA:VIEW |
| `POST /api/v1/mta/installs` `{serverId, webmail?, webmailLogin?, webmailPassword?}` → 202 job | MTA:CREATE (MTA:EDIT too if the server already has an MTA) |
| `GET /api/v1/mta/installs/{id}?logFrom=n` → status, steps, `stepsDone/stepsTotal`, log from `n`, `logLength`, DKIM public key | MTA:VIEW |
| `GET /api/v1/mta/installs?serverId=` → the server's last 20 installs | MTA:VIEW |

Errors: 409 `MTA_INSTALL_RUNNING`, 409 `SERVER_NOT_READY` (not connected, no root/sudo, no
linked domain, unsupported OS). A server can't be deleted while an install runs. Activity:
`MTA_INSTALL_STARTED`, `MTA_INSTALL_FINISHED`.

#### Dashboard (M2.4)

`GET /api/v1/dashboard/summary` (DASHBOARD:VIEW): counted from the database at the call,
only numbers that exist today:

```json
{"generatedAt":"…","users":{"total":5,"active":2,"invited":2,"disabled":1},
 "openSessions":2,"activity":{"last24Hours":7,"last7Days":8}}
```

Open sessions use the same rule as sign-in (not revoked, before the absolute end, seen within the
idle limit, account ACTIVE). The last backup is **not** included: its `status.json` is in a
root-only folder on the server, outside the container.

#### Users, invitations, my account (M1.5)

| Call | Permission | What |
| --- | --- | --- |
| `GET /api/v1/users?q=&status=&page=&size=&sort=` | USERS:VIEW | search email/name, filter ACTIVE/INVITED/DISABLED, sort email, fullName, status, createdAt, lastLoginAt |
| `GET /api/v1/users/{id}` | USERS:VIEW | + effective permissions, recovery codes left, open sessions |
| `POST /api/v1/users/invites` `{email, fullName?, permissions[]}` | USERS:CREATE | 201; emails a link valid **72 h, once**; 409 if the email exists |
| `POST /api/v1/users/{id}/invite/resend` | USERS:CREATE | new link, the old one stops working |
| `DELETE /api/v1/users/{id}/invite` | USERS:DELETE | removes the never-used account |
| `POST /api/v1/users/{id}/disable` · `/enable` | USERS:EDIT | disable ends all their sessions |
| `POST /api/v1/users/{id}/2fa/reset` | USERS:EDIT | enrol again at next sign-in; sessions end |
| `PUT /api/v1/users/{id}/permissions` `{permissions[]}` | USERS:EDIT | replaces the grants |
| `GET /api/v1/users/{id}/sessions` · `DELETE .../sessions/{sid}` · `DELETE .../sessions` | USERS:VIEW / EDIT | list, end one, end all |
| `POST /api/v1/invites/check` `{token}` · `/accept` `{token, fullName, password}` | none (the token) | 410 `LINK_INVALID` for any unusable link; accept continues with `TWO_FACTOR_SETUP_REQUIRED` + `md_preauth` |
| `POST /api/v1/account/password` `{currentPassword, newPassword}` | signed in | 400 `CURRENT_PASSWORD_INCORRECT` (counts towards the lock); success ends every other session |
| `GET /api/v1/account/sessions` · `DELETE /api/v1/account/sessions/{sid}` · `POST /api/v1/account/sessions/revoke-others` · `POST /api/v1/account/logout-everywhere` | signed in | own sessions (`current` marks this one) |
| `GET /api/v1/account/2fa` · `POST /api/v1/account/2fa/recovery-codes` `{code}` | signed in | status; new codes after a current code |

Rules no permission lifts: **the Owner is never the target** of an admin action (403);
**nobody acts on their own account** through `/users` (409); **a non-owner can only grant or
remove permissions they hold** (403). Passwords: at least 12 characters, at most 72 bytes,
not the email (`auth/password/PasswordPolicy`). Email links carry the token after `#`
(`/accept-invite#...`, `/reset-password#...`), never in a query string; table
`account_tokens` (`V5__account_tokens.sql`) keeps only its SHA-256. Invitation, accept and
reset calls share a per-address rate limit (`link` bucket, 10/min, 50/h).

#### Forgot / reset password (M1.6)

| Call | Answer |
| --- | --- |
| `POST /api/v1/auth/password/forgot` `{email}` | **always** 202 with the same message, account or not. Only an ACTIVE account gets an email, at most one a minute; the email leaves after the request, off its thread (`app.mail.async`), so the timing does not tell either |
| `POST /api/v1/auth/password/reset/check` `{token}` | 200 `{expiresAt}` or 410 `LINK_INVALID` |
| `POST /api/v1/auth/password/reset` `{token, password}` | 204; the link (30 min, `app.auth.reset-ttl`) works once, the newest one only; **every session ends**, a lock is lifted. It does not sign in, and never skips 2FA |

#### Email (Resend)

`mail/`: `AccountMails` builds the invite and reset emails (clean HTML + text, no images,
no tracking, times in Toronto time); `MailConfig` picks the sender:

| Where | Sender | What happens |
| --- | --- | --- |
| production with `RESEND_API_KEY` | `ResendMailSender` | `POST https://api.resend.com/emails`; success = INFO `email sent: to=j***@... id=...`; failure = one ERROR line with status and Resend's error name, never the key, body, link or Resend's message |
| production without the key | `LogMailSender` (WARN) | app starts; WARN at startup and `email not sent (RESEND_API_KEY not set) ... link=https://.../accept-invite#AbCd…` per email |
| `local` profile | `LogMailSender` | nothing sent; the **full** link is logged so you can click it |
| tests | `LogMailSender` / a capturing test sender | nothing sent; link token masked |

Sending never throws: an invite is created even if its email fails, and can be resent.

#### Login failures

| Situation | Answer |
| --- | --- |
| Unknown email, wrong password, invited or disabled account | 401 `INVALID_CREDENTIALS`, **the same body for all**, never which one. Each costs one BCrypt comparison (against a dummy hash when there is no usable one), so the timing is about the same too |
| 5 wrong passwords in a row (`APP_AUTH_LOCKOUT_MAX_ATTEMPTS`) | 429 `ACCOUNT_LOCKED` with `Retry-After`, `retryAfterSeconds` and `lockedUntil`, for 15 minutes (`users.locked_until`). While locked the password is **not checked**, so the answer is the same whether it was right. A success resets the count; the end of a lock starts a fresh count. Made-up emails are locked the same way (in memory), so "locked" does not reveal which emails exist |
| More than 10 attempts a minute or 50 an hour from one address | 429 `RATE_LIMITED` with `Retry-After`, before the body is read |
| Empty or oversized fields | 400 `VALIDATION_FAILED` (values never echoed) |

429 rather than 423 for the lock: 423 is WebDAV's "resource locked for editing"; 429 with
`Retry-After` is what clients and proxies already understand as "come back later". The
code tells the two 429s apart.

#### Sessions

- **Opaque token, not a JWT.** The cookie holds 32 random bytes (256 bits, base64url).
  `user_sessions` (`V2__user_sessions.sql`) stores only their SHA-256, plus `public_id`,
  `user_id`, `created_at`, `last_seen_at`, `expires_at`, `revoked_at`, `ip` and
  `user_agent` (cut to 255). Every request looks the row up anyway, so a JWT would only
  add a signing key to guard and rotate. With the row as the single truth, revoking it,
  disabling the user or expiry takes effect on the very next request.
- **Lifetime:** idle 12 h (`last_seen_at`, written at most once a minute), absolute
  7 days (`expires_at`). A disabled user's sessions stop working at once.
- **Cookie** `md_session`: `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`, **no
  `Domain`**: the browser keeps it for exactly the host that set it, `db.nordencapital.ca`
  (through the website's proxy). `Secure` is off only in the `local` profile
  (`app.auth.cookie.secure`), because http://localhost:8080 is not HTTPS.
- The active-sessions page and "log out everywhere" (M1.5) only need to set `revoked_at`.

#### Client address

The login rate limit, `user_sessions.ip` and the audit lines need the visitor's address,
but every request arrives from Vercel. The website's proxy therefore sends `X-Client-IP`
(from Vercel's `x-real-ip`, which Vercel sets itself) and drops any `X-Client-IP` /
`X-Forwarded-For` the caller sent. `web/security/ClientIp` believes `X-Client-IP` **only
when the same request had the right proxy secret**; otherwise it uses the connection's
address (Caddy overwrites an outside `X-Forwarded-For`, and Tomcat accepts the header only
from the local proxy). A raw `X-Forwarded-For` is never read.

#### CSRF

The cookie is `SameSite=Lax`, so browsers do not send it on cross-site POSTs. On top of
that, the website's proxy (`app/api/[...path]/route.ts` + `lib/proxy-guards.ts` in
masterdb-frontend) refuses any write whose `Origin` or `Sec-Fetch-Site` is not this site
with 403 `CSRF_REJECTED`, before forwarding. The backend cannot check `Origin` itself (the
proxy drops it), and no browser can reach the backend directly (proxy secret), so Spring
Security's CSRF tokens are off.

#### Audit log lines

INFO, with the masked email, the user and session public ids, the client address and the
request id; never a password, token or hash:

```
login succeeded: j***@nordencapital.ca user=<uuid> session=<uuid> ip=203.0.113.7 requestId=...
login failed (wrong password): j***@nordencapital.ca attempts=2 ip=... requestId=...
login failed (unknown account): n***@example.com ip=... requestId=...
login failed (wrong password), account locked: j***@... attempts=5 until=... ip=... requestId=...
login refused, account locked: j***@... until=... ip=... requestId=...
login rate limit reached: ip=... retryAfter=42s requestId=...
logout: j***@nordencapital.ca user=<uuid> session=<uuid> ip=... requestId=...
```

The reason in brackets is for the server log only; the API never says it.

#### Activity log (M1.8)

Table `activity_log` (`V6__activity_log.sql`): time, `action`, actor and target (public id +
email; a made-up email from a failed sign-in is stored **masked**), client address, user
agent, request id and small JSON `details` (never a password, token, code or hash). No
foreign keys: entries outlive the accounts. Written in the same transaction as the action
(`activity/ActivityLog`), so an action that fails leaves no entry.

Recorded: `LOGIN_SUCCEEDED`, `LOGIN_FAILED` (with a reason), `ACCOUNT_LOCKED`, `LOGOUT`,
`TWO_FACTOR_ENROLLED`, `TWO_FACTOR_RESET`, `RECOVERY_CODE_USED`, `RECOVERY_CODES_REGENERATED`,
`USER_INVITED`, `INVITE_RESENT`, `INVITE_CANCELLED`, `INVITE_ACCEPTED`, `USER_DISABLED`,
`USER_ENABLED`, `PERMISSIONS_CHANGED` (added / removed), `PASSWORD_CHANGED`,
`PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET`, `SESSION_REVOKED`, `SESSIONS_REVOKED`,
`ACTIVITY_EXPORTED`.

| Call | Permission |
| --- | --- |
| `GET /api/v1/activity?action=&user=&q=&from=&to=&page=&size=&sort=occurredAt,asc` | ACTIVITY_LOG:VIEW |
| `GET /api/v1/activity/export?...same filters` → `text/csv` (UTF-8 BOM, at most 100,000 rows, cells starting with `= + - @` are prefixed with `'`) | ACTIVITY_LOG:EXPORT; the export is itself logged |

Retention: entries older than `app.activity.retention` (365 days) are deleted daily at
03:40 UTC (`ActivityQuery.prune`).

#### Filter order

RequestIdFilter → RequestLoggingFilter → CORS → ProxySecretFilter → LoginRateLimitFilter →
docs-off filter → Spring Security (session cookie, access rules) → controllers.

#### Try it locally

Without Docker (embedded PostgreSQL, empty at every start, `local` profile, port 8080):

```bash
./mvnw -q test-compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=test
java -cp "target/test-classes;target/classes;$(cat target/cp.txt)" ca.nordencapital.testsupport.LocalDevServer
```

(`;` separates the classpath on Windows, `:` elsewhere.) Set `BOOTSTRAP_OWNER_EMAIL` /
`_PASSWORD` in the environment first to get an Owner. Emails are not sent locally: the
invite / reset link is printed in full in the log. Then run the frontend with
`BACKEND_URL=http://localhost:8080` and any `PROXY_SECRET` (the check is off locally).

Or with Docker: `./mvnw spring-boot:run` (the `local` profile: no proxy secret, cookie not `Secure`). Create
the first account with the `BOOTSTRAP_OWNER_*` variables, then sign in through the frontend
pointed at `http://localhost:8080`.

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
