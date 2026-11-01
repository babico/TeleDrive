# Access model

The complete authorization model: who can be a caller, how each caller is
authenticated on each listener, what a role or key actually grants, how S3
credentials and policies combine, where key material lives, and which trust
boundaries TeleDrive does **not** cross. It is verified against
[`web/permissions.py`](https://github.com/babico/TeleDrive/blob/main/web/permissions.py),
[`web/deps.py`](https://github.com/babico/TeleDrive/blob/main/web/deps.py),
[`teledrive/api_keys.py`](https://github.com/babico/TeleDrive/blob/main/teledrive/api_keys.py)
and the S3 gateway modules; policy-level statements belong in
[Security policy](policy.md).

## 1. Identities

There are three credential types, and they are not interchangeable.

| Identity | Wire form | Stored as | Scope |
| --- | --- | --- | --- |
| WebUI/REST session | httpOnly `teledrive_session` cookie, or `Authorization: Bearer td_sess_...` | SHA-256 digest in `user_sessions`, tied to a `users` row | Role-derived endpoint permissions, 7-day expiry, revocable server-side |
| REST API key | `Authorization: Bearer td_live_...` | SHA-256 digest plus non-secret prefix in `api_credentials` | Exactly the scopes it was issued with; optional absolute expiry (max 10 years) |
| S3 credential | SigV4 `Credential=<access key>/...`, or a presigned query | Access key in clear, secret Fernet-encrypted in `storage_s3_credentials` | `s3:*` permission strings, optional expiry, independently revocable |

A session user is a **person**. An API key is a **delegated program**: it is
not a user, gets role `api-key`, and never passes through the role map
(`require_auth` checks it first and returns). An S3 credential is an
**independent principal**: it has no user row, no role, and no access to the
WebUI or REST JSON API. A Basic header is ignored as if absent; there is no
Basic code path and no configuration password.

First boot inserts `admin`/`admin` only when no `admin` row exists. The row is
never overwritten, cannot be renamed, and the UI forces a password change
while the shipped default still verifies. Deleting the row is the documented
lockout recovery.

## 2. CSRF and origin rules

Every state-changing WebUI/REST handler calls `_same_origin(request)` before
doing work:

1. The request must carry `X-TeleDrive-CSRF: 1`. A missing header is HTTP 403.
2. If an `Origin` header is present, its host must equal the request `Host`.
   A mismatched or unparsable origin is HTTP 403. An absent `Origin` (common
   for non-browser clients) passes step 2 but not step 1.

This applies to the browser session flow and to authenticated API-key calls;
the login and logout handlers enforce it too. The rule exists because a
cookie-authenticated browser can be made to submit a
cross-site form; requiring a custom header that a cross-origin form cannot
set is the primary defence, and the origin check catches a browser that does
send one. GET/HEAD reads do not require the header.

The reverse-proxy mode (`TELEDRIVE_TRUSTED_PROXY`) changes only two things:
`Secure` cookies are set when `X-Forwarded-Proto: https`, and login throttles
use the leftmost **public** `X-Forwarded-For` address. Without the flag that
header is ignored entirely, so an untrusted client cannot mint or dodge a
throttle bucket.

## 3. Role to permission derivation

`PermissionRegistry` is built from the **live** FastAPI route table via
`route_views()`, so the catalog cannot drift from the routes. Every
`/api/*` route gets one permission: a curated name for the nine REST bearer
endpoints, otherwise `"<method>:<path template>"`. Public routes (health,
login page, static assets, shares, website, docs) get none.

`ROLE_PERMISSION_RULES` is the only source of human authority:

| Role | Rule | Current snapshot |
| --- | --- | --- |
| `admin` | Every permission in the registry, including routes added later | 139 |
| `operator` | Every permission except the admin-only surfaces | 96 |
| `viewer` | Only `GET`/`HEAD` and the curated REST read names, outside admin-only surfaces | 44 |
| unknown/absent | Nothing (fail closed) | 0 |

The numbers are a snapshot of the current route table, not a contract; the
contract is the rule. The path gate (`_required_roles`) runs first and the
permission map second. Both must pass. An operator denied by the path gate
cannot be rescued by a permission, which is defence in depth rather than a
second policy.

### Admin-only surfaces

These require `admin` for every method, including reads:

- `/api/v1/admin/users` — user CRUD, roles, password reset, session revocation.
- `/api/v1/admin/keys` — API key issue/rotate/revoke and the permission catalog.
- `/api/v1/admin/s3/credentials` and the legacy `/admin/s3-credentials` — S3 secrets.
- `/api/v1/admin/storage/gc` — physical GC state, preview and collect.
- `/api/v1/logs`, `/api/logs` — the in-memory log buffer (object keys, paths, credential ids).
- `/api/v1/admin/audit` — the durable security trail.
- `/api/v1/admin/storage/shares` — listing and revoking share tokens, which are themselves credentials.
- Mutating Telegram session routes (`/telegram-session`, `/request-code`, `/verify-code`) — binding an account is owning the backend.
- `/api/v1/admin/storage/buckets/*/quota` and `/*/website` — quota changes can reject uploads, and `public_read` publishes anonymously.
- `PUT /api/v1/config` — deployment configuration writes.

Reads outside those surfaces are available to viewer/operator according to
the permission map (for example bucket listings and object reads).

## 4. API-key delegation ceiling

A key is a subset of the authority that minted it, enforced in both
dimensions:

| Ceiling | Rule | Failure it prevents |
| --- | --- | --- |
| Permissions | A key may create/rotate/revoke only scopes it already holds (`_require_within_delegation`). | A key scoped to one mint route creating a fully privileged key. |
| Lifetime | A child key's expiry must be `<=` the parent's; a parent with an expiry cannot mint a non-expiring child (`_require_within_lifetime`). | Revoking a short-lived parent while a permanent descendant keeps working. |

`admin:*` is a real wildcard over the live route table, resolved at issue and
check time, so a route added later cannot retroactively widen an existing key.
Legacy grouped scopes (`buckets:read`, `objects:write`, ...) expand to their
endpoint sets so old keys keep working; new keys should use per-endpoint
names. `admin:*` cannot be combined with other scopes.

Some surfaces refuse an API key entirely (`_require_interactive_session`):
issuing, editing, revoking or revealing an **S3 credential**, **presigning**
an object URL, and **writing configuration**. Each either creates or returns
a durable secret; delegating it would bypass the ceiling. A key that holds
the share-create permission can create a share link (that permission is the
grant), but listing/revoking all tokens stays admin-role-only.

## 5. S3 authentication and resource policy

S3 has its own authenticator. A request is accepted only after SigV4
verification of a stored credential:

- Header-signed requests must be within **900 seconds** of server time.
- Presigned queries must declare `X-Amz-Expires` in **1..604800 seconds**,
  are rejected on repeated query parameters, and are expired against the
  signed timestamp.
- SigV2, unsigned mutable presigns and anonymous payload writes are refused.
  AWS-chunked streaming is accepted only in its signed/trailer modes.
- The credential's `permissions` list is checked against the operation's
  `s3:` action. A revoked or expired credential fails closed before any
  catalog read.

### Policies, ABAC and ACLs

After signature + credential scope, resource authorization is evaluated in
this order:

1. **Explicit `Deny`** in the bucket policy wins.
2. **Explicit `Allow`** grants the request and bypasses the ACL layer.
3. Otherwise the **ACL intersection** applies: a stored bucket/object ACL may
   only narrow the credential's own scopes; it never expands them. A resource
   with no stored ACL keeps the unrestricted baseline.

The policy grammar is a strict subset of AWS. Anything it cannot evaluate
honestly is rejected at write time with 400/501 rather than ignored, because
silently dropping a clause would widen access. `Principal: "*"` is rejected:
a policy can only address S3 credentials, not session/API-key callers, which
have their own model. ABAC conditions read `aws:PrincipalTag/*`,
`s3:ExistingObjectTag/*`, `aws:SourceIp` and the ListBucket defaults
(`s3:prefix`, `s3:max-keys`, `s3:delimiter`). Omitting those defaults once let
a `Deny` on `s3:prefix` block `?prefix=a` but allow a bare listing, so the
defaults are now always populated.

Public access is off by default. Website hosting answers anonymously only
when an admin has enabled the bucket's `public_read` gate, and only for
current ready heads. The gate is an admin API decision, never an S3
credential permission.

## 6. Encryption key handling

| Mode | Key holder | Where the key lives | What the server sees |
| --- | --- | --- | --- |
| `none` (default) | nobody | — | Plaintext payloads. |
| SSE-C | the client | Request memory only | Plaintext while processing; ciphertext at rest in Telegram. |
| `storage.encryption: envelope` | the deployment | Master key file/env; per-object wrapped data key in SQL | Plaintext while processing; ciphertext at rest. |

SSE-C chunks are AES-256-GCM with a fresh 12-byte nonce and an AAD binding the
immutable object id and chunk ordinal. Only the AWS-published key-MD5
fingerprint is stored, returned or compared; the key is never persisted,
logged or echoed. Range reads decrypt only overlapping chunks; multipart
binds one key for the upload; `UpdateObjectEncryption` re-encrypts in a
bounded pass. A wrong key fails GCM authentication rather than returning
bytes.

Envelope encryption reuses the S3 master key: HKDF-SHA256 derives a KEK with a
distinct info string, one DEK is generated per object and wrapped with
AES-256-GCM using the object id as AAD, and only the wrapped DEK is stored.
A database dump alone yields ciphertext for S3 credential secrets and the
settings document. Rotating the master key makes old reads fail closed with a
named error. Envelope is opt-in because encrypted objects are excluded from
deduplication, replication and content search; the capability set is reported
by `teledrive/storage/envelope.py::capabilities()` rather than left implicit.

Client-side encryption (`web/static/teledrive-crypto.js`) is a fourth,
separate option: the browser derives an AES-GCM key from the user's
passphrase and uploads opaque bytes, so even envelope-enabled TeleDrive sees
only ciphertext. The passphrase is unrecoverable by design.

## 7. What is logged, and who can read it

| Store | Contents | Access | Retention |
| --- | --- | --- | --- |
| In-memory `LOG_BUFFER` | Recent request/audit lines, including object keys and request paths | admin only (`/api/v1/logs`, `/api/v1/logs/stream`) | Bounded (1500 entries), lost on restart |
| Rotating file log | Same categories, scrubbed | Host filesystem access | Rotation policy on disk |
| `security_audit_events` | Security events: credential/API-key issue, rotate, revoke, reveal; config writes; user changes; GC start/finish; presign; share creation | admin only (`/api/v1/admin/audit`) | Append-only; pruned by age by the caller |
| S3 request middleware | Method, path, access-key **id**, status, duration | same log surfaces | in-memory/file |

`security_audit_events` never stores a secret: values matching TeleDrive's
own token shapes (`td_live_`, `td_sess_`, Fernet, PBKDF2, Telethon session)
are replaced with `[redacted]`. The log buffer and file additionally redact
share tokens and database URLs. The audit writer swallows its own failures on
purpose — an audit write must not be able to fail the operation it describes.

## 8. Trust boundaries

Trusted:

- the host OS administrator, Docker daemon and anyone who can edit mounted
  files or the running image;
- the SQL server administrator and the database connection;
- the reviewed Python and database drivers;
- Telegram as the remote store, for **availability** and for the integrity of
  message identity.

Not trusted by the application, but not defended against either:

- a caller who already has the master key **and** the database;
- a malicious host administrator (they can read process memory and replace
  binaries);
- an attacker who controls the Telegram account or channel;
- network observers on plaintext HTTP (use TLS or a tunnel).

**Telegram is not end-to-end encrypted.** Ordinary cloud chats, channels and
Saved Messages are visible to Telegram, and TeleDrive's server sees plaintext
payloads unless SSE-C was used by the client, envelope encryption is on, or
the client encrypted before upload. S3 credential secrets and the settings
document are encrypted at rest; object **metadata** (bucket, key, size,
timestamps, tags) remains readable in SQL by anyone with database access.

## 9. Explicitly out of scope

These are not claimed and should not be inferred from a green test run:

- protection from a compromised host, hypervisor, Docker daemon or database
  administrator;
- end-to-end confidentiality against Telegram;
- hiding object names, sizes or access patterns from a database reader;
- multi-tenant isolation. The role model is for one owner/small team; it is
  not a tenancy boundary between mutually hostile customers;
- physical GC safety. Deletion remains owner-gated; the access model protects
  authority, not the irreversibility of Telegram message deletion;
- availability or DDoS resistance. Login throttling is per username+client,
  not a global rate limiter;
- a formal third-party security audit, and production penetration testing.
  See [Security policy](policy.md) for the evidence that does exist.

## 10. Where to change the model

A new admin surface goes in `_ADMIN_ONLY_PREFIXES` (or the enumerated
session/quota/website sets) in `web/permissions.py`, is added to
`tests/meta/test_route_surface.py` in the same commit, and gets a behaviour
test. Do not add an ad-hoc `if role != "admin"` in a handler: the path gate
and the role map must agree, and the surface test only sees the central
classification. A new delegation rule belongs in `web/deps.py` next to
`_require_within_delegation` / `_require_within_lifetime`, with a test that
attempts the escape, not merely the happy path.
