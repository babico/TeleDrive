# Security Policy

> **Scope:** vulnerability reporting, trust boundaries, network exposure, secret handling, and security validation for the TeleDrive fork.
> **Do not report vulnerabilities or post credentials in public issues.**

## 1. Report a vulnerability privately

Use the repository's [GitHub Security tab](https://github.com/babico/TeleDrive/security) and private vulnerability reporting when available. Include the affected release or commit, operating system, minimal reproduction steps, expected/observed impact, and carefully redacted logs.

Do **not** submit active credentials, session files, database connection URLs, Telegram messages or exploitable details in a public issue. If private reporting is unavailable, contact the repository maintainer through an appropriately private channel rather than exposing an unpatched exploit.

## 2. Threat model and trusted components

TeleDrive is primarily a **single-owner or small-team** application with server-enforced admin, operator and viewer roles. The WebUI can manage Telegram accounts, target channels, local source paths, credential issuance and metadata state. Treat this authority as sensitive.

The host OS administrator, Docker daemon, host user managing mounted files, SQL server administrator, reviewed Python/database drivers and Telegram itself are **trusted boundaries**. TeleDrive does not sandbox a malicious host administrator who can modify mounts or binaries while the service runs.

Telegram Saved Messages and ordinary cloud channels are **not end-to-end encrypted**. Encrypt sensitive payloads separately if Telegram must not see their contents.

## 3. Secrets and credentials

Treat all of the following as secrets:

| Secret | Consequence if exposed |
| --- | --- |
| Telethon `*.session`, Telegram API ID/hash, login codes and 2FA | User-account and channel access |
| `config.yaml`, `.env`, WebUI user passwords | Administrative control and deployment information |
| SQL URL and SQL backups | Object manifests, references, jobs and potentially encrypted credential metadata |
| `config/s3-master.key` and S3 access keys | S3 key decryption and object API access |

Store secrets in protected volumes or a secrets manager with restrictive file permissions. Never commit them, print them to CI logs, or paste them into bug reports. When a secret is compromised, rotate/revoke it using the applicable Telegram, WebUI or S3 credential controls; review the dependent backups and sessions.

## 4. Network exposure

The default Docker Compose deployment uses **one container with two loopback-bound host mappings** (the service itself binds `0.0.0.0` inside the container):

| Interface | Default host binding | Authentication |
| --- | --- | --- |
| WebUI / REST | `127.0.0.1:8080` | Token login (admin/operator/viewer) via httpOnly cookie or Bearer token; scoped REST Bearer API keys |
| S3 | `127.0.0.1:9000` | Scoped S3 SigV4 access/secret keys |

Do not expose either endpoint over untrusted plaintext HTTP. For remote access, use an HTTPS reverse proxy or VPN, set `web.allowed_hosts` appropriately in `config/config.yaml`, use strong unique passwords, and restrict firewall access.

`.env` can override the host-side mapping with `TELEDRIVE_BIND_ADDRESS`, `TELEDRIVE_WEB_PORT` and `TELEDRIVE_S3_PORT`. Setting `TELEDRIVE_BIND_ADDRESS=0.0.0.0` publishes the WebUI/REST and S3 listeners on the LAN; this is acceptable **only on trusted private networks** — every host on that network can then reach the login page and the S3 gateway. On untrusted networks keep the default loopback binding and tunnel.

The unified server dispatches by its actual socket-local listener port, **not** by client-supplied Host or forwarding headers. REST Bearer tokens are not interchangeable with S3 SigV4 keys. S3 master-key material must not be embedded in URLs or requests.

## 5. WebUI authentication model

- **Cookie-only browser sessions:** the browser UI authenticates exclusively with the httpOnly, SameSite=Lax `teledrive_session` cookie set by `POST /api/v1/auth/login`; no session token is stored in `localStorage` or other browser storage. The cookie carries the `Secure` flag whenever TLS is configured (`TELEDRIVE_SSL_CERTFILE`), and sessions expire after seven days.
- **Hashed session tokens:** session tokens are persisted only as SHA-256 digests; a database leak does not directly expose usable tokens.
- **Password hashing:** WebUI passwords are stored as salted PBKDF2-HMAC-SHA256 hashes (260,000 iterations). Legacy salt+SHA-256 hashes still verify and are transparently upgraded to PBKDF2 on the next successful login.
- **Login throttling:** repeated failed logins (per username and client) are throttled using `web.auth_failure_limit` and `web.auth_failure_window_seconds` (default 5 failures per 300 seconds).
- **Role-based access control:** enforced server-side on all `/api/v1/admin/*` endpoints:

| Capability | admin | operator | viewer |
| --- | --- | --- | --- |
| Read listings, redacted config and logs | Yes | Yes | Yes |
| Storage/job operations, channels, versions, recovery | Yes | Yes | No |
| User management, API keys, S3 credentials, config writes, quotas, website publishing, physical GC | Yes | No | No |

- **CSRF protection:** state-changing endpoints (login/logout, configuration, user, credential, storage-job and session management) require the `X-TeleDrive-CSRF: 1` header plus a same-origin `Origin` check, whether the caller authenticated with the session cookie or with HTTP Basic. API keys are scoped per route and need the header only where documented.
- **One permission model:** every API route has exactly one permission, derived from the live route table. A session and HTTP Basic both resolve to a local `users` row, and that row's role grants a fixed set of permissions: **admin** holds every permission; **operator** holds all data/storage permissions but not user, key, credential, GC, quota, website or config-write administration; **viewer** holds read (`GET`/`HEAD`) permissions only. The path gate and the permission map must both pass. Bearer API keys keep their own independently issued per-route scopes.
- **HTTP Basic is a local-user credential:** it verifies username + PBKDF2 password against the `users` table, honours `enabled` and applies the user's real role — there is no unconditional admin path. Unknown users and the retired configuration password are refused with `401`, and failed attempts share the login throttle.
- **Default administrator:** the first start inserts the hardcoded local account `admin`/`admin` only when no `admin` row exists; change it immediately (the default is public knowledge, and the WebUI forces the change). An existing `admin` row — password hash, role and enabled flag — is never overwritten. Configuration is not an authentication source: `web.user`/`web.password` are no longer service settings and never authorise a request.

## 6. Database, files and runtime defenses

`state.database_url` accepts synchronous SQLAlchemy dialects without a hardcoded vendor whitelist. Review and pin additional driver packages, use database TLS where available, and scope the SQL principal to the intended schema/database. Initial schema creation/migrations may need DDL privileges; reduce privileges after migrations when operationally feasible.

The Docker default includes non-root execution, dropped Linux capabilities, `no-new-privileges`, a read-only root filesystem, a read-only `/uploads` mount, protected secret files, source/session/log/SQL path allowlists, non-regular and symlink checks, upload leases and atomic claims, rate limiting, Host validation, CSRF protection, security headers and credential redaction.

A SQL snapshot alone cannot restore lost Telegram payloads or S3 master keys. Independent originals and rehearsed recovery are required. Physical Telegram garbage collection remains disabled pending the [production recovery and safety controls](IMPLEMENTATION_STATUS.md#41-physical-telegram-garbage-collection-disabled).

## 7. Security testing and release evidence

The [Security and Regression workflow](../.github/workflows/quality-security.yml) covers Python compilation/regression, `pip check`, Bandit, `pip-audit`, Docker image build, Trivy and application listener smoke tests. The WebUI authentication and RBAC contract (`tests/web/test_auth_rbac.py`: cookie sessions, hashed tokens, PBKDF2 with legacy migration, throttling, role policy, CSRF) is part of that regression suite. GitHub Actions are pinned to immutable revisions; Dependabot monitors Python, Docker and Actions dependencies.

A successful scanner run is **not** permission to expose the administration UI publicly or a substitute for owner-approved production penetration testing. Consult the [CI and Test Guide](CI_WORKFLOWS.md) and distinguish test-channel E2E from actual production data.
