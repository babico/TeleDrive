# Security policy

This is a policy, not a tutorial. It states how to report a vulnerability,
what is supported, what counts as a security issue here, how credentials must
be handled, how the service may be exposed, and what review evidence exists.
The access model itself is described in [Access model](model.md).

## 1. Responsible disclosure

Use the repository's [private vulnerability reporting](https://github.com/babico/TeleDrive/security/advisories/new)
or the GitHub Security tab. If that is unavailable, contact the maintainer
through a private channel — never a public issue.

Include:

- affected release tag or commit SHA, and deployment mode (Docker/bare metal);
- the exact endpoint, listener and role/credential used;
- minimal reproduction steps and expected vs observed behaviour;
- redacted logs or a proof of concept that does not contain live secrets;
- impact: confidentiality, integrity, availability, or a safety gate.

Do **not** include session files, API hashes, bot tokens, login codes, 2FA
passwords, SQL URLs, S3 secrets, master-key contents, share tokens, original
media identifiers or unredacted production logs. A report that contains a live
credential should be rotated immediately, before triage.

We aim to acknowledge a report, confirm scope, and agree on a disclosure
timeline with the reporter. There is no bug bounty.

## 2. Supported versions

| Version | State | Security fixes |
| --- | --- | --- |
| `v1.0.9` | Current release line | Yes |
| `v1.0.8` (tag `7d2aa77`) | Previous release | Yes |
| `v1.0.7` | Previous release | Critical fixes only, when practical |
| `main` after the current tag | Development | No support guarantee; it is not a release |

The version is in `pyproject.toml`. A fix is only claimed for the SHA it was
verified on; see [Project status](../project/status.md) for the per-release
exact-SHA rule. A fork that changes authentication, the S3 gateway or the
container wiring is responsible for its own review.

## 3. In scope

- Authentication and authorization on both listeners: session cookie,
  `td_sess_` bearer, API keys, S3 SigV4 and presigned URLs.
- The role-to-permission map, admin-only surfaces, and the API-key delegation
  and lifetime ceilings.
- CSRF/origin enforcement, login throttling, session revocation, and the
  first-boot administrator bootstrap.
- Secret handling: S3 credential encryption, the SQL settings document, the
  master key, SSE-C key handling, envelope key wrapping.
- Bucket policies, ACLs, ABAC, Public Access Block, object lock, website
  hosting gates and share links — including any way to widen access rather
  than narrow it.
- Path allowlists, symlink/non-regular-file handling, upload leases, and
  anything that lets a caller read or write outside an approved root.
- Container hardening: non-root execution, dropped capabilities, read-only
  root, that no shipped default exposes the UI beyond loopback.
- The durable audit trail: events that should be recorded and are not, or
  secrets that reach it.

## 4. Explicitly out of scope

- A malicious host administrator, Docker daemon operator or database
  administrator. These can read process memory and replace binaries.
- Telegram's own confidentiality. Telegram is not end-to-end encrypted and
  the server sees plaintext unless the client used SSE-C, the deployment
  enabled envelope encryption, or the browser encrypted before upload.
- Object metadata privacy. Bucket names, keys, sizes and timestamps are
  readable by anyone with database access.
- Physical deletion of Telegram media. It is owner-gated and disabled; a
  report that it is disabled is not a vulnerability.
- Denial of service, volumetric attacks, and global rate limiting. Login
  throttling is per username+client by design.
- Multi-tenant isolation between mutually hostile customers.
- Findings that require the master key **and** the database, or that require
  modifying the deployment's own configuration file.
- Scanner output without a demonstrated impact path.

## 5. Credential handling rules

Treat every item below as a secret with the stated blast radius.

| Secret | If exposed |
| --- | --- |
| Telethon `*.session`, Telegram API ID/hash, login codes, 2FA | Full control of the storage user and its channel |
| `config/config.yaml`, `.env`, SQL settings document | Deployment layout, API hashes, session strings, paths |
| `config/s3-master.key` / `TELEDRIVE_S3_MASTER_KEY` | Decrypts S3 credential secrets and the settings document |
| SQL URL and SQL backups | Manifests, jobs, object metadata, encrypted credential blobs |
| WebUI passwords, session tokens, API keys | Administrative or delegated API authority |
| S3 access/secret keys, presigned URLs, share tokens | Object data for the lifetime/permissions of the credential |

Rules:

1. Keep secrets in protected volumes or a secrets manager, mode `0600`, owned
   by the container uid. Never commit them, print them in CI, or paste them
   into an issue.
2. The master key is mandatory for S3 credentials and the SQL settings
   document. Back it up separately from the database; a database dump alone
   must not be sufficient to decrypt secrets.
3. On suspected exposure, revoke/rotate through the owning control: S3
   credential revoke/reissue, API key revoke/rotate, user password reset and
   session revocation, Telegram session delete, master-key replacement
   (which fails old reads closed). Review dependent backups and sessions.
4. An S3 credential is not interchangeable with an API key or a session.
   Do not put one in a URL; presigned URLs are the supported way to delegate
   a single object read.
5. Client-side encrypted objects are unrecoverable without the passphrase.
   That is a feature, not a support case.

## 6. Network exposure

The default Compose deployment publishes two **loopback** host mappings; the
process binds `0.0.0.0` inside the container.

| Listener | Default host binding | Authentication |
| --- | --- | --- |
| WebUI / REST | `127.0.0.1:8080` | Session cookie or Bearer session; scoped API keys |
| S3 | `127.0.0.1:9000` | SigV4 access/secret or presigned query |

Do not expose either listener over untrusted plaintext HTTP. For remote
access use an HTTPS reverse proxy or VPN, set `web.allowed_hosts` to the
public hostname, keep the proxy's `Host` header unchanged (SigV4 signs it),
and restrict the firewall. With `TELEDRIVE_TRUSTED_PROXY=1` the app honours
`X-Forwarded-Proto` for Secure cookies and trusts the leftmost public
`X-Forwarded-For` for throttles; enable it only when a proxy you control
actually sets those headers.

`TELEDRIVE_BIND_ADDRESS=0.0.0.0` publishes both listeners on the LAN. That is
acceptable only on a trusted private network: every host there can reach the
login page and the S3 gateway. Never publish the administration UI directly
to the internet without TLS and a deliberate exposure review.

## 7. Security-review evidence

The project records reviews as a ledger rather than claiming "reviewed". Each
document states what was fixed, what was declined on purpose, and what remains
someone else's job.

| Document | Scope | Outcome |
| --- | --- | --- |
| [Full-codebase review 2026-10-31](../project/reviews/review-2026-10-31.md) | Six independent read-only reviewers: storage core, S3 data plane, web/API, persistence, S3 test realism, web/meta/e2e test realism | Correctness bugs fixed (envelope copy, object-lock default retention, GC re-verify fence, dedup/GC race, unique Telegram identities); false positives dropped; remaining test-realism items listed. |
| [API review](../project/reviews/api-review.md) | Seven waves over 25 endpoints — the authority surface | 64 real defects fixed before the 1.0.8 tag, including four takeovers; one finding disproved with evidence. Per-endpoint fix status is in the document. |
| [Audit 2026-10-29](../project/reviews/audit-2026-10-29.md) | TODO/docs/roadmap claims against the tree | Bucket-delete orphan tables, MySQL writes, duplicate permission catalogs, schema race and indexes closed; the audit keeps its own pre-fix state visible. |
| [Codebase review](../project/reviews/codebase-review.md) | Whole-tree structural review at `054af3a` | Fifteen refactor findings; the closed ones carry commit evidence, the open ones are tracked in the [roadmap](../project/roadmap.md). |

Automated evidence: the CI 1 `security` job runs Bandit, `pip-audit`, the
authentication/RBAC tests, the SigV4 defence suite, the fail-closed S3 suite
and the workflow-contract meta-tests; CI 3 builds and scans the image with
Trivy. GitHub Actions are pinned to full commit SHAs and Dependabot monitors
Python, Docker and Actions dependencies. Details are in
[CI and tests](../reference/ci.md).

A green scanner or a finished review is **not** permission to expose the
administration UI publicly, and it is not a substitute for owner-approved
production penetration testing or the acceptance gates in
[Project status](../project/status.md).
