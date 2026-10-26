# Metadata-Backed S3 Parity Plan

> **Stance change.** The by-design partials assumed a rule of "never
> emulate AWS semantics without AWS infrastructure." But TeleDrive
> already trusts an external service (Telegram) with the payload
> itself — the deployment is *inherently* not "ideal AWS". That is not
> a reason to stop being honest; it is a reason to redefine honest:
>
> **An emulated feature is honest when (1) it has real SQL state,
> (2) every path that could violate it enforces it, and (3) the state
> is observable through the corresponding GET API.** The backing is
> TeleDrive metadata rather than AWS infrastructure — the contract is
> real, enforced and inspectable, not pretended.
>
> The only features that stay by-design are the ones with **no honest
> backing at all**: billing (request payment) and transfer
> acceleration. Everything else in the 37 partials has a
> metadata-backed path below.

Inventory: 19 supported / 37 partial (by design) / 60 unsupported.
This plan converts up to 35 of the 37 into supported operations, in
dependency order. Each phase is independently shippable.

---

## Phase A — GC-integrated deletes ("delete means delete") 

**Converts:** DeleteObject, DeleteObjects, AbortMultipartUpload,
Get/Put/DeleteBucketLifecycle(+Configuration) — 7 partials.

The GC owner gate already exists as `storage_gc_state` + the collect
pipeline. What is missing is wiring the delete APIs to it:

- **DeleteObject ?versionId** and **DeleteObjects per-entry VersionId**:
  today the version is logically revoked (`storage_removed_versions`)
  and its media waits for a manual collect. New behavior: when GC is
  ENABLED, the revoked version is enqueued into a
  `storage_gc_queue` (object_id, enqueued_ns, reason) consumed by the
  existing collect re-verification path — so an enabled GC turns
  version deletes into physical deletion with the same fail-closed
  candidate checks (alias, head, intent, retention) as the manual
  flow. GC disabled = today's behavior (journal retention).
- **DeleteObject without VersionId** stays a delete-marker write
  (AWS versioned semantics) — but with GC enabled, the key's
  non-current versions become collect candidates after an
  owner-configurable grace period (`storage.gc_grace_seconds`,
  default 24h — protects against fat-finger deletes).
- **AbortMultipartUpload**: with GC enabled, abort physically deletes
  the staged part media (enqueue each part object) instead of leaving
  orphan protection pending.
- **Lifecycle Expiration rules**: extend the rule grammar beyond
  AbortIncompleteMultipartUpload with `Expiration` (Days, Prefix,
  ExpiredObjectDeleteMarker). A scheduler evaluates rules daily:
  matching objects get `removed_versions` entries (logical expiry,
  immediate) and GC-queue entries (physical, only when GC enabled and
  past grace). Rule state itself is already SQL
  (`BucketLifecycleStore`); add the evaluator + a `last_evaluated_ns`
  column for idempotent scheduling.

**Enforcement points:** delete/version-delete/batch-abort handlers,
lifecycle evaluator, gc collect re-verification (grace check).
**Observability:** GET ?lifecycle returns the full rule set; GET
/api/v1/admin/storage/gc already reports the queue depth.

## Phase B — Bucket versioning states 

**Converts:** GetBucketVersioning, PutBucketVersioning — 2 partials.

- `storage_buckets` gains `versioning_state` ('ENABLED' default,
  'SUSPENDED').
- **PutBucketVersioning** accepts Enabled (idempotent) and Suspended
  (transition; MFADelete still rejected — no MFA backing).
- **Write path:** in SUSPENDED buckets, `catalog.publish` replaces
  the key's version journal instead of appending: the previous
  current version gets a `removed_versions` entry in the same
  transaction (AWS: a suspended bucket keeps old versions, but new
  PUTs overwrite without creating versions; DELETE removes the head
  without a marker). `delete_marker` in suspended buckets = plain
  head removal + revocation of the current version.
- GET ?versioning reports the true state.

**Enforcement:** publish/delete CAS branches; version listing
continues to show pre-suspension history.

## Phase C — Object Lock: retention & legal hold — DONE

**Converted:** GetObjectLockConfiguration, GetObjectRetention,
GetObjectLegalHold + the P2-B write ops (PutObjectLockConfiguration,
PutObjectRetention, PutObjectLegalHold) — 6 operations promoted.

This is the highest-security-value phase: real WORM semantics backed
by SQL truth.

- `storage_objects` gains `retention_until_ns` and `legal_hold`
  (bool); `storage_buckets` gains `object_lock_enabled` +
  `default_retention` (mode/days) so PutObject/CreateMultipartUpload
  can accept the lock headers.
- **Enforcement on EVERY delete path** — the critical part:
  `delete_version`, batch per-entry deletes, Phase A's GC queue
  consumer and the manual collect re-verification all refuse locked
  versions (`ObjectLocked` error in S3 shape). Compliance mode is
  immutable: once set, `retention_until_ns` can only be extended
  (checked in the same SQL transaction as the write).
- GET ?retention / ?legal-hold / ?object-lock return the real state.

**Guardrail:** enabling object lock on a bucket is a one-way decision
(AWS semantics) — enforced by rejecting `object_lock_enabled`
transitions to false.

## Phase D — ACL grants on S3 credentials — DONE

**Converted:** GetBucketAcl, GetObjectAcl + promoted PutBucketAcl,
PutObjectAcl — 4 operations promoted.

Per the researched P2-C design (owner already reviewing):

- `storage_bucket_acl_grants` (bucket, grantee access key, permission
  READ/WRITE/FULL_CONTROL) and `storage_object_acl_grants` (same +
  exact key).
- **Enforcement is a fail-closed INTERSECTION**: effective credential
  scopes = own scopes ∩ (owner grants ∪ bucket grants ∪ matching
  object grants). ACLs can only NARROW; never expand. Public/group/
  email grantees stay rejected — that is the private-only line.
- Put/Get/Delete Acl parse and return AWS-shaped
  AccessControlPolicy XML with CanonicalUser = access-key owner IDs.

## Phase E — Public Access Block, policy status, ownership controls — DONE

**Converted:** GetPublicAccessBlock, PutPublicAccessBlock,
GetBucketPolicyStatus, GetBucketOwnershipControls — 4 operations
promoted.

On top of Phase D's grant store:

- `storage_buckets.public_access_block` (four booleans, default all
  true). Put accepts the real configuration; the grant-resolution
  path consults it: BlockPublicAcls=true rejects any attempt to add a
  grant the owner did not author (everything already is owner-only,
  so PAB becomes a forward-looking guard for Phase I website mode).
- GetBucketPolicyStatus computes IsPublic from the actual grants +
  PAB flags (today: hardcoded false).
- OwnershipControls stays BucketOwnerEnforced — that IS the real
  model — but now reads from bucket metadata rather than a constant.

## Phase F — Notifications and logging 

**Converts:** GetBucketNotification(Configuration) — 2 partials;
promotes the write ops.

- `storage_notification_configs` (bucket, event list, destination
  URL, secret ref) + `storage_event_outbox` (event type, bucket, key,
  version, payload JSON, attempts, next_retry_ns). Every catalog
  mutation (publish, delete marker, version revoke, multipart
  complete) writes outbox rows in the SAME transaction.
- A retry worker delivers webhooks with exponential backoff (no
  SQS/SNS destinations — HTTP(S) only, honestly documented).
- `storage_logging_configs` (target bucket + prefix): the existing
  audit-log stream is delivered into the target bucket as objects on
  a schedule (reusing the storage engine itself).

## Phase G — Replication API surface — DONE

**Converted:** GetBucketReplication + PutBucketReplication,
DeleteBucketReplication — 3 operations promoted.

The storage engine ALREADY does cross-account replication
(`storage.replica_account`, `storage_replica_chunks`, digest-verifying
repair). Map the S3 API onto it:

- `storage_replication_configs` (bucket, destination = a second
  TeleDrive credential/account label, prefix filters). Get/Put/Delete
  ?replication read and write it.
- The engine's replication decision per object consults the bucket's
  config instead of only the global setting; the existing repair
  endpoint becomes the AWS-shaped reconciliation.
- Destination is a TeleDrive account, not an AWS bucket ARN —
  documented in the response as a TeleDrive-specific Role string.

## Phase H — CORS grammar widening — DONE

**Converted:** GetBucketCors, PutBucketCors — 2 operations promoted.

- Accept wildcard-subdomain origins (`https://*.example.com`),
  expose-headers, max-age, and the full method list; keep the
  fail-closed allowlist validation and the 64 KiB bound.
- `storage_cors_rules` validation table gains pattern-compilation for
  origin matching (compiled per rule, cached).

## Phase I — Website hosting 

**Converts:** GetBucketWebsite — 1 partial; promotes the writes.

- `storage_website_configs` (index document, error document) per
  bucket, gated by a per-bucket `public_read` flag (an explicit,
  audited owner decision — the same trust level as the existing
  public share links).
- A `/site/{bucket}/...` route serves current objects for
  public_read buckets with website semantics (index/error documents).
  Objects remain private unless the flag is set; share-link routes
  are unaffected.

## Phase J — Tagging scope (deferred journal) 

**Converts:** Get/Put/DeleteObjectTagging — 3 partials.

- Keep the write fence (staged manifests stay non-addressable by
  VersionId), but accept tagging writes against the CURRENT head's
  *pending* generation: tags are journaled
  (`storage_pending_tags`) and applied transactionally at publish —
  `attach_uncommitted` already proves the pattern.
- Result: every tagging write either lands on a published version or
  is applied at the moment its target publishes; nothing addresses
  raw staging.

## Phase K — SSE decision (owner call required) 

**Converts:** GetBucketEncryption + upload headers — 1 partial + scope.

Envelope encryption (config-held master key, per-object data keys) is
the only honest SSE here, and it CONFLICTS with content-addressed
dedup, cross-account replication and content search (all operate on
plaintext). A deployment chooses one or the other:
`storage.encryption = none | envelope`. With envelope enabled:
- chunks stored encrypted, checksums verify ciphertext,
- dedup/replication/search disable themselves (documented),
- Get/Put ?encryption read/write the real config.

**Recommendation:** ship Phases A–J first; revisit SSE only if a
threat model demands encrypted-at-rest Telegram payloads.

## Kept by-design (no honest backing)

- **GetBucketRequestPayment** — billing does not exist; Payer stays
  BucketOwner. No metadata can create money.
- **GetBucketAccelerateConfiguration** — no alternate network path
  exists. Suspended is the truth.

---

## Execution order and expected inventory

| Phase | Effort | Partial→Supported |
| --- | --- | --- |
| A GC deletes + lifecycle | M | 7 |
| B versioning states | S | 2 |
| C retention/legal hold | M | 3 (+5 unsupported later) |
| D ACL grants | M | 2 (+4 unsupported later) |
| E PAB/status/ownership | S | 3 |
| F notifications/logging | M | 2 (+4 unsupported later) |
| G replication surface | M | 1 (+2 later) |
| H CORS grammar | S | 2 |
| I website | M | 1 (+2 later) |
| J tagging journal | S | 3 |
| K SSE envelope | L | 1 (owner decision) |

After A–J: **35 of 37 by-design partials resolved**, inventory lands
at **54 supported / 2 partial (by design) / 60 unsupported**, with the
unsupported group also shrinking (ACL/notification/replication/
website/lock writes promote from section 4). K optionally brings it
to 55/1/60.

Each phase ships behind the same discipline: SQL state first,
enforcement on every violating path second, GET observability third,
adversarial tests fourth — then the spec row flips from "by design"
to Supported with the metadata backing documented.
