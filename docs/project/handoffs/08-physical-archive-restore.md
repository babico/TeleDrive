# Handoff 08 — Actual archive bytes, RestoreObject and lifecycle

**State:** Delivered in v1.0.10 — `ColdBlobStore`, the durable archive/restore state machine, real `RestoreObject` and the lifecycle extensions shipped. This page is kept as the design record.

## Current implementation to preserve

- `teledrive/s3/tiering.py` sets SQL `storage_class` = `ARCHIVE_ACCESS` or `DEEP_ARCHIVE_ACCESS` based on policy. It explicitly says **no Telegram chunk moves**.
- `teledrive/s3/restore.py` validates `RestoreRequest`, and `web/s3_gateway/objects.py` writes `restore_until_ns`, returns 202 and allows reads within that window. This is a real access gate but **not** actual cold storage retrieval.

## Implementation phases

**Phase A — cold storage provider and object manifest.** Implement `ColdBlobStore` with a real durable cold volume or independently-addressed remote object endpoint (minimum local filesystem provider, later optional S3 backend). Each archived immutable version receives a sealed archive manifest: source object/version, chunk lineage, bytes, whole SHA256, encryption metadata, target URI, verified receipt, state, creation and restore timestamps. Require atomic write + fsync + hash-verified readback before marking `archived`. Preserve archived historical versions and dedup aliases. No credentials or KEKs in archive logs.

**Phase B — migration and durable restore workers.** Add resumable state machine `HOT -> ARCHIVING -> ARCHIVED -> RESTORING -> RESTORED_TEMP -> ARCHIVED`, idempotency key, worker lease, generation fences and restart recovery. `RestoreObject` queues a *real* copy from cold backend to a bounded hot/staging cache, exposes `x-amz-restore: ongoing-request="true"` during work, returns 202 on acceptance, and lets GET succeed only after whole SHA256 verification. Expiry must clear the staged copy, not archive data. `Expedited/Standard/Bulk` are priority queues **only if scheduling behavior differs**; document that no AWS speed/price SLA is implied. Maintain correct existing `STANDARD` InvalidObjectState behavior.

**Phase C — actual hot footprint reduction.** Never automatically delete Telegram messages as a consequence of a tier transition. The user controls physical GC via the existing toggle/typed confirmation. Only after verified independent archive and all current alias/retention/reference fences, make the archived Telegram source eligible for the owner's explicitly initiated GC path. Missing cold backend or corrupt archive must block deletion. If hot Telegram data is retained, state plainly that the archive is an additional verified copy, not cost-saving eviction.

**Phase D — S3 lifecycle integration.** Extend rule engine for transitions, NoncurrentVersionExpiration, NoncurrentVersionTransitions and ExpiredObjectDeleteMarker, preserving Object Lock/legal-hold rules. Lifecycle expiry is logical while GC is off. Keep the bucket/version race atomic; selected `VersionId` restored into its own generation, never the current HEAD by accident.

## Failure tests

Cold backend unavailable; corrupted archive; partial upload; interrupted read; lost ACK; retry after SQL commit; two workers restoring one version; restart between archive verified and source deletion; expired restore cache; mixed SSE-C/envelope; dedup aliases, replicated bytes, default COMPLIANCE lock; HTTP HEAD/GET/read conditions. Run SQLite unit, real PostgreSQL/MySQL concurrency, Docker fault injection, real Telegram dedicated-test-channel snapshot; do **not** use owner original data.

**Pass** requires independently verified cold bytes, return of exact SHA256/range across restore, accurate `RestoreObject` and `x-amz-restore` states, no permanently unreadable object after any fault. Keep AWS Glacier marketing terms out of the implementation contract.

**AWS reference:** https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html.
