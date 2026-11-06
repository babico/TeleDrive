# Handoff 09 — S3 submodes, IAM/STS and KMS boundaries

**State:** Delivered in v1.0.10 for the implemented submodes (versioning null-slot, ACL/policy/lock fences, lifecycle transitions, governance bypass scope); the identity/KMS/STS backlog below remains a design record. **Do not** treat operation inventory 114/0/2 as complete AWS parity.

## Submode backlog (follow actual current code)

| Surface | Existing | Implement / prove next |
| --- | --- | --- |
| Versioning | Enabled and Suspended code, immutable history | Exact AWS null-version overwrite/delete behavior, suspended delete-marker interactions, MFADelete only if an actual second factor + credentials exists. Test COPY, multipart, REST and admin all the same. |
| Object Lock | GOVERNANCE, COMPLIANCE, legal hold, default retention | Per-version immutable enforcement on REST/S3/public shares/local jobs/copy/explicit delete/GC; true governance bypass requires permission plus explicit header; no COMPLIANCE shorten/release even for admin. AWS regulatory WORM guarantee cannot extend to direct Telegram owner deletion outside service. |
| Lifecycle | AbortIncompleteMultipartUpload and Expiration | NoncurrentVersionExpiration/Transition, delete-marker cleanup, archive transition through real ColdBlobStore, deterministic evaluator, crash replay, retained-version protection. |
| ACL | Credential CanonicalUser grants, ownership modes | Header and grant grammar, canned ACL strictness, ACL intersection and PAB/ownership precedence; ensure ALL cross-tenant routes and presigned URLs are covered. Public ACL semantics require a product decision; do not silently enable public access. |
| Bucket policy | Deny/Allow, access-key principals and limited condition operators | Explicit mapping of principals to actual TeleDrive identities, expanded common condition operators, IP/tag/time semantics, deny precedence, cache invalidation, auditable compile, public principal gated by deliberate public-mode design. No AWS global account impersonation. |

## Identity vocabulary (explain before building)

- **AWS IAM** = Identity and Access Management: users/roles and policies specifying who may call actions on resources. TeleDrive already has local roles, API-key scopes and bucket policy but **not** an AWS IAM control plane.
- **AWS STS** = Security Token Service: short-lived access key + secret + security token (e.g. AssumeRole). To emulate, implement a real issuing, expiry, revocation, role-scoped authorization and SigV4 session-token verifier; never accept token headers then ignore them. S3 Express `CreateSession` is a distinct bucket-scoped session flow, not a general STS replacement.
- **AWS KMS / S3 SSE-KMS** = provider-managed cryptographic key service and S3-managed data encryption by a KMS key. TeleDrive currently has **SSE-C** (client provides encryption key) and opt-in **SSE-S3-like envelope** (deployment keeps the KEK). This is **not** SSE-KMS.

## Decision path

1. Keep current scoped S3 credentials + SSE-C + envelope as default.
2. If external key custody matters, define a `KeyProvider` interface (local KEK / AWS KMS / Vault-compatible provider) with per-object envelope key wrap/unwrap, IAM-equivalent access policy, rotation, failure/revocation and audit. Only advertise `aws:kms` when a genuine external KMS backend and authorization paths are proven.
3. If clients require STS, create a separate temporary credentials issuer bound to local roles/policies and signed `x-amz-security-token`, with cross-process SQL revocation. Don't return real AWS ARN or account IDs for nonexistent AWS accounts.
4. Add a machine-tested parameter-level compatibility ledger with `SUPPORTED`, `REJECTED`, `UNVERIFIED` per option, not just each API operation; link each entry to tests/CI.
5. Prioritize broad-catch audit, router split, shared JS helpers, configurable /data and /uploads, shared fixtures, migration/rollback notes and documentation consistency checks after correctness work.

## Acceptance

Boto3 + AWS CLI + rclone + Cyberduck + independent SDK; signed/unsigned, malformed, over-limit, retry, crash/restart, race, authorization, cross-surface parity. Real PostgreSQL/MySQL for write races. Document intentionally missing AWS infrastructure; no fabricated success codes.

**References:** https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html and https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html.
