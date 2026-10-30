# S3 API Specifications and Compatibility Matrix

> **Scope:** TeleDrive's S3-compatible listener over the shared SQL catalog and USER MTProto engine with historical same-channel Bot-media reads only, **not** AWS S3. **Last reviewed:** 2026-10-21 against the development default branch. **Target:** P2 Advanced S3 planning; this document does not assert production certification or update the released v1.0.7 binary.
>
> **Canonical operation inventory:** [AWS S3 REST API, 2006-03-01, operation list](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations_Amazon_Simple_Storage_Service.html). This matrix enumerates **all 116 operations** on that AWS S3 service-reference page as reviewed. AWS S3 Control, S3 Tables, S3 on Outposts, S3 Files and future additions are **separate services**, not silently included in this list. This is a protocol/API coverage inventory, not a claim to implement every possible request parameter, header, mode or AWS service.

## 1. Read the status correctly

| Status | Meaning |
| --- | --- |
| ✅ Supported | Implemented for the explicitly documented TeleDrive contract and backed by focused regression coverage; **not** a claim of complete AWS parity. |
| 🟡 Partial | Route/behavior exists, but significant AWS options, response fields or state transitions are deliberately restricted. Treat unsupported variants as unsupported. |
| ❌ Unsupported | No supported TeleDrive contract; do not rely on that AWS method. It may be rejected as NotImplemented (501) **or** require additional fail-closed routing tests; do not assume every selector currently returns the same error. |
| Not verified | Client, deployment configuration or optional parameter is untested; never upgrade an operation's status merely because another client happens to succeed. |

**Inventory totals:** 114 supported, 0 partial (0 by code, 0 by design), 2 unsupported; **116 AWS S3 operations**. Count operations, not request permutations. Partial operations are **not** fully supported; section 3 classifies each partial by *why* it is partial. These statuses describe development code and tests, not a fresh CI run or independently validated production setup.

**Machine-readable inventory:** [116-operation JSON manifest](../teledrive/s3/operation_manifest.json) is checked against every row of this matrix in [fail-closed route tests](../tests/s3/test_s3_route_guard.py). Supported AWS subresources are explicitly allowlisted before the signer, SQL and Telegram transports can mutate data; unknown selectors cannot silently become normal bucket/object operations. This addresses a P2-0 subtask, **not** the entire protocol parity gate.

**Implementation evidence:** [gateway router](../web/s3.py), [S3 protocol modules](../teledrive/s3/), [S3 tests](../tests/), [CI guide](CI_WORKFLOWS.md), [implementation/production status](IMPLEMENTATION_STATUS.md). On a new code SHA, rerun its own CI rather than recycling a historical green status. No new test execution was performed solely to prepare this inventory.

## 2. Platform contract and parameter-level specifications

| Specification area | TeleDrive behavior / boundary | Evidence or next step |
| --- | --- | --- |
| Deployment and object identity | Web/REST port 8080 and S3 port 9000 in **one default container**; S3, REST and explicitly queued local-file jobs share the catalog, SQL heads, versions and Telegram chunk payloads. | [Unified architecture](IMPLEMENTATION_STATUS.md#2-architecture-and-unified-storage-contract), [integration tests](../tests/web/test_unified_service.py) |
| Authentication | Scoped persisted S3 keys and **AWS Signature V4** header signing; access-key secrets encrypted at rest in SQL via an external master key. REST Bearer credentials are **not** S3 credentials. | [SigV4](../teledrive/s3/sigv4.py), [credentials](../teledrive/s3/credentials.py), [auth tests](../tests/s3/test_s3_sigv4_defense.py) |
| Signature variants | Query presigns with expiry **1–604,800 seconds**, limited methods and stricter checksum-bound PUT/multipart POST rules. SigV2, STS/session tokens and aws-chunked streaming are not implemented. | [SigV4 code](../teledrive/s3/sigv4.py), [presigned tests](../tests/s3/test_s3_presigned.py), [multipart presigns](../tests/s3/test_s3_presigned_complete.py) |
| Browser POST | Restricted SigV4 policy forms; checksum-pinned, maximum **20 MiB form** and policy expiry within **15 minutes**; not arbitrary AWS POST policy clauses. | [POST policy](../teledrive/s3/post_policy.py), [POST tests](../tests/s3/test_s3_post_policy.py) |
| Addressing/regions | Path-style endpoint is the documented client default; limited configured virtual-host addressing exists. Bucket location reports us-east-1-compatible empty constraint. ListBuckets supports paginated bucket inventory scoped to this private us-east-1 region, with immutable SQL CreationDate. No AWS multi-region, Access Point ARN or directory-bucket routing. | [gateway](../web/s3.py), [virtual-host tests](../tests/s3/test_s3_vhost.py), [location tests](../tests/s3/test_s3_bucket_location.py) |
| Object payloads | PUT/GET/HEAD with immutable manifest, Telegram USER MTProto chunks (historic Bot chunks can be read by original message ID in the same user-authorized channel), SHA-256 integrity and byte-range GET. Default REST/S3 single-transfer upload ceiling is **2 GiB**, configurable via `web.rest_max_upload_bytes` in `config/config.yaml`; actual deploy/Telegram limits apply. | [gateway](../web/s3.py), [storage tests](../tests/storage/test_storage_engine.py) |
| ETag | TeleDrive single PUT returns a SHA-256-derived ETag; multipart has its own ETag representation. **Never assume AWS single-part MD5 ETag equality.** | [gateway](../web/s3.py), [multipart](../teledrive/s3/multipart.py), [contract tests](../tests/s3/test_s3_contract.py) |
| Checksums on upload | Integrity validation for signed SHA-256, SHA-1, Content-MD5, CRC32, CRC32C and CRC64NVME on implemented PUT/UploadPart paths. When `x-amz-checksum-mode: ENABLED` is supplied for an object GET/HEAD, return the actual immutable full-object SHA-256 checksum; GetObjectAttributes can expose the same digest as `ChecksumSHA256` with `FULL_OBJECT` semantics. **Not** a guarantee of all SDK trailer/checksum algorithms or AWS multipart composite checksums. | [checksum helper](../teledrive/s3/checksums.py), [additional checksum tests](../tests/s3/test_s3_additional_checksums.py) |
| Read preconditions | Selected If-Match, If-None-Match, If-Modified-Since and If-Unmodified-Since for GET/HEAD; byte ranges supported. | [conditions](../teledrive/s3/conditions.py), [tests](../tests/s3/test_s3_conditions.py) |
| Write preconditions | Signed If-Match/If-None-Match on bounded simple PUT/DELETE and multipart completion; date-based write preconditions and conditional explicit-version deletes are not implemented. | [write conditions](../teledrive/s3/write_conditions.py), [tests](../tests/s3/test_s3_conditional_writes.py) |
| Metadata | Selected signed HTTP metadata and x-amz-meta-* persisted per version, limited to **2 KiB serialized**; metadata and copy directives restricted. | [object metadata](../teledrive/s3/object_metadata.py), [metadata tests](../tests/s3/test_s3_metadata.py) |
| Versioning and delete markers | Each publish retains a version; GET/HEAD and tags may select a published VersionId, list versions and delete markers. Only **Enabled** accepted for Get/PutBucketVersioning; no Suspended/null-version/MFADelete semantics. DeleteObjects cannot select individual VersionIds. | [versioning](../teledrive/s3/versioning.py), [version/read/delete tests](../tests/s3/test_s3_bucket_versioning.py), [marker tests](../tests/s3/test_s3_delete_markers.py) |
| Bucket/object tags | Bucket tags support the AWS general-purpose bucket 50-tag limit with case-sensitive UTF-16-length-validated keys/values, atomic replacement, scoped permissions, verified request integrity and get/delete; object tags remain limited to 10 per immutable version. | [tagging](../teledrive/s3/tagging.py), [tag tests](../tests/s3/test_s3_tagging.py) |
| Bucket CORS | Restricted origin/method/header CORS rules, max **100** rules, **64 KiB** config. CORS is not authentication. | [CORS](../teledrive/s3/cors.py), [tests](../tests/s3/test_s3_cors.py) |
| Public access | **Private only.** Get/PutPublicAccessBlock expose/accept all four values as true. GetBucketPolicyStatus is read-only and always IsPublic=false because public grants/policies cannot be configured. Non-private ACLs and public bucket policies are **not** supported. | [public access module](../teledrive/s3/public_access.py), [tests](../tests/s3/test_s3_public_access_block.py) |
| Multipart | Durable staged parts, up to **10,000** part numbers, minimum **5 MiB** for non-final completed parts, size/part limits, guarded completion and abort. Completion atomically records an immutable object-version part snapshot (number/size/SHA-256/ETag); historical and copied multipart attributes have bounded 1–1,000 part pages and a read-only pre-upgrade SQL fallback. Failed/aborted/unused Telegram chunks remain protected until approved GC. | [multipart](../teledrive/s3/multipart.py), [tests](../tests/s3/test_s3_multipart.py), [recovery tests](../tests/s3/test_s3_recovery.py) |
| Copy | Local bucket/key and selected source-VersionId copy; signed source, permissions, metadata/tag directives, ETag and date-based source preconditions. UploadPartCopy and ranged CopyObject stage source bytes through Telegram exactly like UploadPart; presigned CopyObject binds the signed source header. | [gateway copy route](../web/s3.py), [tests](../tests/s3/test_s3_copy.py), [version copy](../tests/s3/test_s3_version_copy.py) |
| Unsupported write semantics | SSE-S3/SSE-KMS/SSE-C, retention/Object Lock, public ACLs, non-STANDARD tiers, request-payer, aws-chunked/trailer semantics and select copy conditions **must not be silently acknowledged**. | [fail-closed write checks](../web/s3.py), [tests](../tests/s3/test_s3_fail_closed.py) |
| Clients and operational proof | Boto3, AWS CLI and rclone scenarios exist, with **synthetic Telegram transport** for most storage integration tests; dedicated live Telegram E2E tests validate other actual payload paths. **Cyberduck, other SDKs and every SDK checksum mode remain unverified.** | [client tests](../tests/s3/test_s3_cli_compat.py), [CI guide](CI_WORKFLOWS.md) |
| Physical delete and lifecycle | Object deletion removes catalog visibility or version references; it **does not authorize deleting Telegram messages**. Only SQL-only AbortIncompleteMultipartUpload lifecycle rules are implemented; an hourly task marks old unfinished upload sessions aborted while retaining Telegram chunks. Object expiration/transitions and physical GC are not enabled. | [Lifecycle](../teledrive/s3/lifecycle.py), [lifecycle tests](../tests/s3/test_s3_lifecycle.py), [GC safeguards](IMPLEMENTATION_STATUS.md#41-physical-telegram-garbage-collection-disabled) |

### Quotas

Each bucket can carry an optional per-bucket quota: a maximum total size in bytes and/or a maximum object count. Quotas are enforced server-side on upload through both the S3 gateway and the REST API, and are configurable via the admin API (`GET`/`PUT /api/v1/admin/storage/buckets/{bucket}/quota` with `max_size_bytes` and `max_objects`; `null` disables a limit) or the Web UI **S3** page. Uploads that would exceed either limit are rejected.

## 3. Implemented and partially implemented AWS S3 actions

Every qualification below is part of the contract. Partial operations are
classified by **why** they are partial:

- **Partial — by code**: a genuinely closeable gap. The missing piece is
  implementable within the current architecture; it is tracked work, not a
  decision. Closing one is a normal feature increment.
- **Partial — by design**: the "gap" is a deliberate architectural decision —
  the immutable private-only model, owner-gated physical Telegram deletion,
  or AWS-external semantics that cannot honestly exist over Telegram.
  "Implementing" these would mean faking AWS behavior the platform does not
  have, so they stay fail-closed on purpose.

The [machine-readable manifest](../teledrive/s3/operation_manifest.json)
carries each partial's `gap_class` and is synchronized with this table by CI.

### 3.1 Supported — the full contract for this deployment class

| AWS S3 API operation | Status | Implemented scope |
| --- | --- | --- |
| [CreateBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html) | ✅ Supported | Creates a bucket in the shared catalog; re-creating an existing (owned) bucket is idempotent and answers 200, matching AWS us-east-1 semantics that clients such as rclone rely on during pre-upload bucket preparation. |
| [HeadBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html) | ✅ Supported | Authenticated existence check. |
| [DeleteBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html) | ✅ Supported | Requires an empty/deletable catalog bucket. |
| [ListBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html) | ✅ Supported | Private single-region us-east-1 contract: signed GET, creation date, owner ID, 1–10,000 max-buckets, prefix/region filters, HMAC-scoped continuation token and keyset pagination. AWS account quota APIs, multi-region and directory buckets do not exist in TeleDrive. |
| [GetBucketLocation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html) | ✅ Supported | Single-region us-east-1 contract: an empty LocationConstraint, exactly as AWS returns it for us-east-1. |
| [GetObjectAttributes](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html) | ✅ Supported | Documented private single-region general-purpose contract: signed ETag, ObjectSize, SHA-256 FULL_OBJECT Checksum, fixed STANDARD StorageClass, published historical VersionId, LastModified header, and immutable completed-multipart ObjectParts (selected part number/size/SHA-256). Supports signed MaxParts 1–1,000, PartNumberMarker 0–10,000, IsTruncated/NextPartNumberMarker and copied version snapshots. Non-MPU objects never fabricate parts; old SQL completion journals are read only and strictly checked. Fails closed on invalid/unsigned inputs and inconsistent history. AWS SSE-C, RequestPayer, directory buckets and provider-managed tiers are outside the TeleDrive contract. |
| [UploadPartCopy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html) | ✅ Supported | PUT ?uploadId&partNumber with a signed x-amz-copy-source: the source bytes are staged through Telegram exactly like a normal UploadPart (completion physically re-owns chunk rows per part). Inclusive x-amz-copy-source-range slices (signed), part numbers 1–10,000, and signed copy-source preconditions. |
| [ListParts](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html) | ✅ Supported | TeleDrive private general-purpose contract: scoped active uploads, SQL-bounded 1–1,000 part pages, part-number marker 0–10,000, sparse/replaced parts, accurate ETag, Size, LastModified, STANDARD StorageClass, IsTruncated/NextPartNumberMarker. Invalid/over-limit cursors and wrong-owner/inactive IDs fail closed without Telegram reads. AWS Owner/Initiator account identities, multipart composite checksums, other tiers/directory buckets remain outside the contract. |
| [ListMultipartUploads](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html) | ✅ Supported | TeleDrive private general-purpose contract: scoped active sessions, bounded SQL keyset pages 1–1,000, prefix, delimiter/CommonPrefixes, UTF-8 encoding-type=url, same-key UploadId cursors, Initiated/StorageClass and NextKeyMarker/NextUploadIdMarker. Completed, aborted and foreign-owner sessions excluded. AWS billing/requester pays, account ownership identities and directory buckets remain outside scope. |
| [GetBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html) | ✅ Supported | Reads bucket tags; missing tag set reports NoSuchTagSet. |
| [PutBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html) | ✅ Supported | Full general-purpose private-bucket tagging contract: 0–50 unique tags, 128/256 UTF-16-unit limits, signed checksum-verified XML, atomic replacement and correct HTTP 200; AWS billing/ABAC services not emulated. |
| [DeleteBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html) | ✅ Supported | Removes stored bucket tag set. |
| [DeleteBucketCors](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html) | ✅ Supported | Removes CORS configuration. |
| [GetBucketCors](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketCors.html) | ✅ Supported | Reads the exact stored rule set (up to 100 rules) as AWS-shaped XML. |
| [PutBucketCors](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html) | ✅ Supported | Full AWS CORS grammar within the 64 KiB bound: one `*` anywhere in the host (`*.example.com`, `api-*.example.com`) matching exactly one DNS label never a dot or scheme, the complete method set (GET/HEAD/PUT/POST/DELETE), AllowedHeader/ExposeHeader globs and MaxAgeSeconds with no artificial ceiling. CORS remains browser policy only — never authentication or authorization. |
| [GetBucketReplication](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketReplication.html) | ✅ Supported | Reads the bucket's real stored replication configuration (AWS-shaped XML) or an honest 404 `ReplicationConfigurationNotFoundError`. |
| [PutBucketReplication](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html) | ✅ Supported | Maps the S3 rules onto the EXISTING storage-engine cross-account replication: `Destination/Bucket` must name a configured TeleDrive credential set (not an AWS ARN), prefix filters are enforced per object at upload and repair, and overlapping enabled rules are rejected (one replica per chunk). DeleteMarkerReplication, ReplicaModifications, storage classes and metrics are rejected 501 rather than silently ignored; `Role` is stored as opaque metadata (no IAM). |
| [DeleteBucketReplication](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html) | ✅ Supported | Removes the stored configuration (204, idempotent); already-replicated chunks are left for the digest-verifying repair path, never deleted implicitly. |
| [GetBucketNotification](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketNotification.html) | ✅ Supported | Reads the bucket's real stored webhook notification configuration (AWS-shaped XML, empty document when disabled). |
| [GetBucketNotificationConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketNotificationConfiguration.html) | ✅ Supported | Same stored configuration; this is the modern name for the same resource. |
| [PutBucketNotification](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotification.html) | ✅ Supported | Stores a bounded webhook config (event subset documented in the module). Destinations must be owner-approved HTTP(S) URLs from `storage.notification_destinations`; SQS/SNS and unknown URLs are rejected, so this is a real webhook fan-out, not an AWS queue integration. Mutations enqueue outbox rows in the same SQL transaction and a retry worker delivers with exponential backoff + HMAC. |
| [PutBucketNotificationConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html) | ✅ Supported | Same contract as PutBucketNotification. |
| [GetBucketLogging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLogging.html) | ✅ Supported | Reads the real stored logging target (bucket + prefix) instead of a hardcoded empty document. |
| [PutBucketLogging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html) | ✅ Supported | Stores the audit-log delivery target. Delivery itself reuses the storage engine and is documented as a scheduled gap, not claimed as instant S3 log delivery. |
| [GetObjectTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html) | ✅ Supported | Current or published VersionId tags. The deferred journal is never exposed: a non-published version still answers NoSuchVersion, so staging remains unaddressable through tags. |
| [PutObjectTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html) | ✅ Supported | Tags a published version directly, or JOURNALs them for the current head's pending generation (`storage_pending_tags`) when not yet published. Grammar is strictly validated (10 tags, key/value bounds, no duplicates) before either path. The journal is applied in the SAME transaction as the head move at publish, so no window exists in which staging becomes addressable; a failed publish rolls back the tags with it. |
| [DeleteObjectTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html) | ✅ Supported | Same two-path contract as PutObjectTagging (published direct, pending journal). Journal rows are reclaimed on version revocation, physical GC collection and bucket deletion. |
| [GetBucketWebsite](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketWebsite.html) | ✅ Supported | Reads the bucket's real index/error document configuration or an honest 404 `NoSuchWebsiteConfiguration`. |
| [PutBucketWebsite](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html) | ✅ Supported | Stores index and error documents (strict 16 KiB bounded XML). `RedirectAllRequestsTo` and `RoutingRules` are rejected 501 rather than silently ignored. Writing this document never publishes anything: the anonymous `/site/{bucket}/` route stays inert until an admin turns on `public_read` for the bucket. |
| [DeleteBucketWebsite](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketWebsite.html) | ✅ Supported | Removes the config AND clears `public_read` in the same transaction, so deleting a site can never leave a publicly readable bucket behind. |
| [ListObjects](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html) | ✅ Supported | V1 listing with per-object `Owner` in `Contents` (deployment owner identity, as AWS V1 always includes), prefix, delimiter, marker, CommonPrefixes, encoding-type=url, bounded max-keys and NextMarker continuation (including CommonPrefix markers). |
| [ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html) | ✅ Supported | V2 listing with `fetch-owner` controlling the per-object `Owner` element, HMAC-scoped continuation, start-after, prefix, delimiter, CommonPrefixes, encoding-type=url, KeyCount and bounded max-keys. |
| [UploadPart](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html) | ✅ Supported | 1–10,000 part numbers, configured part-size bound, aws-chunked streaming part bodies with the same decoder and trailer verification as PutObject, and every supplied checksum verified before any Telegram send: SHA-256, Content-MD5, SHA-1, CRC32, CRC32C and CRC64NVME. |
| [ListObjectVersions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html) | ✅ Supported | Published versions and delete markers, prefix filtering, max-keys, key-marker/version-id-marker keyset pagination, delimiter grouping into CommonPrefixes (versions and prefixes share the max-keys budget exactly like AWS, NextKeyMarker carries the cut) and encoding-type=url. |
| [CompleteMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html) | ✅ Supported | Fenced, zero-reupload staged-part publication. Per-part `ChecksumSHA256` verification; COMPOSITE checksums (SHA-256 from staged part digests; CRC32/CRC32C/CRC64NVME from concatenated little-endian per-part values in one streaming pass) and FULL_OBJECT checksums (SHA-256/SHA-1/CRC32/CRC32C/CRC64NVME over the assembled bytes); the verified checksum is echoed in the result XML. Non-SHA declarations require an explicit x-amz-checksum-type. |
| [CopyObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html) | ✅ Supported | Catalog-local source/version copy with metadata/tag directives, ETag source preconditions, date-based copy-source conditions (if-(un)modified-since with AWS precedence), inclusive ranged copy-source (`bytes=first-last`, 416 on out-of-range; the destination is staged as a NEW payload through Telegram exactly like UploadPartCopy, with REPLACE metadata/tags applied on publish), and presigned CopyObject (SigV4 query authentication binding the signed source header and the signed empty-body digest — a leaked URL cannot be replayed against a different private source). |
| [DeleteObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html) | ✅ Supported | Creates a delete marker (versioned semantics) or deletes an explicit published VersionId. With physical GC enabled, revoked versions join the grace-fenced collection queue and their Telegram media is physically deleted once the grace passes; with GC disabled the media is retained as the recovery journal (documented deployment mode). |
| [DeleteObjects](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html) | ✅ Supported | Up to 1,000 entries with per-entry VersionId (AWS per-entry Deleted/Error semantics: unknown versions report NoSuchVersion inside a 200 response); per-entry version deletes join the GC collection queue exactly like DeleteObject. |
| [AbortMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html) | ✅ Supported | Logical abort of the session; with physical GC enabled the staged part media joins the grace-fenced collection queue instead of remaining as orphan protection. |
| [GetBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html) | ✅ Supported | Reads the bucket's full rule set: AbortIncompleteMultipartUpload and Expiration rules with prefix filters. |
| [GetBucketLifecycle](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycle.html) | ✅ Supported | Deprecated alias of GetBucketLifecycleConfiguration, served by the same handler. |
| [PutBucketLifecycle](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycle.html) | ✅ Supported | Deprecated alias of PutBucketLifecycleConfiguration, served by the same handler. |
| [PutBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html) | ✅ Supported | Signed strict XML with Disabled/Enabled rules: AbortIncompleteMultipartUpload (DaysAfterInitiation 1..3650) and Expiration (Days 1..3650, ExpiredObjectDeleteMarker, Prefix filter). The hourly evaluator expires due current objects with delete markers and — when physical GC is enabled — enqueues their media for grace-fenced collection. |
| [DeleteBucketLifecycle](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html) | ✅ Supported | Removes the bucket's SQL lifecycle configuration; AWS-conformant (removing rules never touches stored objects). |
| [GetBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html) | ✅ Supported | Reports the bucket's true persisted state: Enabled (the versioned-by-default store) or Suspended. |
| [PutBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html) | ✅ Supported | Enabled and Suspended transitions (persisted per bucket, metadata-backed). In Suspended buckets a new write replaces the current version — the superseded version retires from the journal in the same transaction — and DELETE removes the head without a marker (AWS unversioned-style semantics; pre-suspension history is retained). MFADelete is rejected (no MFA backing). |
| [GetObjectLockConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html) | ✅ Supported | Reads the bucket's true persisted Object Lock configuration or an honest 404 when never configured. |
| [PutObjectLockConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectLockConfiguration.html) | ✅ Supported | One-way enable (AWS semantics: lock cannot be disabled once enabled). DefaultRetention with COMPLIANCE/GOVERNANCE mode and Days 1..3650, applied to every new version at publish time; the default can only be extended, never shortened. |
| [GetObjectRetention](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectRetention.html) | ✅ Supported | Reads the retention (Mode + RetainUntilDate) of the current object or a selected published VersionId; honest 404 when no retention is set. |
| [PutObjectRetention](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectRetention.html) | ✅ Supported | Sets GOVERNANCE/COMPLIANCE retention with a future RetainUntilDate (extend-only for active COMPLIANCE); an empty Mode clears retention unless COMPLIANCE is active. Retained versions refuse explicit and batch version deletes (AccessDenied). |
| [GetObjectLegalHold](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLegalHold.html) | ✅ Supported | Reads the legal-hold status (ON/OFF) of the current object or a selected published VersionId. |
| [PutObjectLegalHold](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectLegalHold.html) | ✅ Supported | Toggles the legal hold. A held version refuses explicit and batch version deletes until the hold is released; the GC collector and lifecycle expiration never touch retained or held media. |
| [GetBucketAcl](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html) | ✅ Supported | Reads the bucket's stored ACL grant rows (AWS-shaped AccessControlPolicy, CanonicalUser = TeleDrive access keys); the caller's private canned ACL while no ACL has ever been written. |
| [PutBucketAcl](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html) | ✅ Supported | Replaces the bucket ACL from AccessControlPolicy XML (READ/WRITE/FULL_CONTROL grants to CanonicalUser access keys, validated as active credentials; email/group grantees rejected 501 — the private-only line). The owner retains an implicit FULL_CONTROL row; writing an ACL opts the bucket into the fail-closed intersection gate. |
| [GetObjectAcl](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html) | ✅ Supported | Reads the stored ACL of the current object (exact key); the caller's private canned ACL while no object ACL exists. |
| [PutObjectAcl](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectAcl.html) | ✅ Supported | Replaces the exact object key's ACL (READ/FULL_CONTROL only — WRITE is bucket-level). Object grants only ever affect their own key, never siblings or bucket-level actions. |
| [GetPublicAccessBlock](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html) | ✅ Supported | Reads the bucket's persisted four-flag Public Access Block (default all-true, like AWS). |
| [PutPublicAccessBlock](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html) | ✅ Supported | Persists any combination of the four flags — a deliberate owner decision. BlockPublicAcls=on pins ACL authoring to the stored ACL owner (a forward-looking guard over the Phase D grant store); there is no public path behind any flag value: grantees are always validated access keys, and email/group/public grantees are unwritable. |
| [GetBucketPolicyStatus](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html) | ✅ Supported | IsPublic is computed from the actual stored grants plus the PAB flags (IgnorePublicAcls implements the AWS ignore semantics). With validated access-key grantees the honest scan answers false — but it runs the real data. |
| [GetBucketOwnershipControls](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketOwnershipControls.html) | ✅ Supported | Reads the bucket's persisted object ownership state (BucketOwnerEnforced — the one real model: owner-scoped grants) from bucket metadata, not a handler constant. Ownership writes fail closed 501. |
| [PutBucketPolicy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html) | ✅ Supported | Stores a real IAM-style JSON policy (bounded 20 KiB, 50 statements). Deny always wins; a matching Allow short-circuits the ACL layer. Principals must be CanonicalUser = active TeleDrive access keys; `*`/AWS/Service/Federated are rejected 501 (the private-only line). Conditions are a validated allowlist (`s3:prefix`, `s3:max-keys`, `s3:delimiter`, `aws:SourceIp`, `s3:ExistingObjectTag/*`, `aws:PrincipalTag/*`, `s3:x-amz-acl`); unknown operators or keys are 400 rather than silently ignored. Compiled per bucket and cached, so evaluation cost is constant per request. |
| [DeleteBucketPolicy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html) | ✅ Supported | Removes the stored policy (204, idempotent). The ACL intersection gate resumes immediately. |
| [GetBucketPolicy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html) | ✅ Supported | Returns the exact stored policy document as JSON, or an honest 404 `NoSuchBucketPolicy`. |
| [GetBucketAbac](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAbac.html) | ✅ Supported | Reads the bucket's attribute-based-access-control state (enabled + mandatory tag conditions) as truthful JSON. |
| [PutBucketAbac](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAbac.html) | ✅ Supported | Stores ABAC settings: when enabled, `aws:PrincipalTag/*` and `s3:ExistingObjectTag/*` conditions become mandatory gates on data-plane actions. Principal tags live on the S3 credential; unknown keys are 400. |
| [PutBucketOwnershipControls](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketOwnershipControls.html) | ✅ Supported | Changes the real ownership model: `BucketOwnerEnforced` (default, object ACLs ignored), `ObjectWriter` (object ACL grants apply), `BucketOwnerPreferred` (ObjectWriter plus an automatic owner FULL_CONTROL grant on `x-amz-acl: bucket-owner-full-control` uploads). |
| [DeleteBucketOwnershipControls](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketOwnershipControls.html) | ✅ Supported | Resets ownership to `BucketOwnerEnforced` (204, idempotent). |
| [DeletePublicAccessBlock](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeletePublicAccessBlock.html) | ✅ Supported | Removes the stored PAB flags, returning the bucket to the all-true default (the most restrictive state), so deletion can never weaken protection. |
| [GetBucketAnalyticsConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAnalyticsConfiguration.html) | ✅ Supported | Reads one stored analytics configuration by `id`, or an honest 404 `NoSuchConfiguration`. |
| [PutBucketAnalyticsConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAnalyticsConfiguration.html) | ✅ Supported | Stores a bounded analytics configuration (prefix/tag filter, destination bucket + prefix that must exist, Daily/Weekly schedule). The report runner really writes a JSON Lines report into that destination through the storage engine; AWS's Parquet format is documented as a deviation, not faked. |
| [DeleteBucketAnalyticsConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketAnalyticsConfiguration.html) | ✅ Supported | Removes one configuration by `id` (204, idempotent). |
| [ListBucketAnalyticsConfigurations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketAnalyticsConfigurations.html) | ✅ Supported | Lists every stored analytics configuration id (complete and sorted; no continuation token needed). |
| [GetBucketInventoryConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketInventoryConfiguration.html) | ✅ Supported | Reads one stored inventory configuration by `id`, or an honest 404 `NoSuchConfiguration`. |
| [PutBucketInventoryConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketInventoryConfiguration.html) | ✅ Supported | Stores a bounded inventory configuration. `IncludedObjectVersions=All` really includes historical published versions; the runner writes a real gzip CSV with the AWS column shape (Bucket, Key, VersionId, IsLatest, Size, LastModifiedDate, ETag, StorageClass — ETag is the stored SHA-256, documented). ORC/Parquet are rejected 501. |
| [DeleteBucketInventoryConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketInventoryConfiguration.html) | ✅ Supported | Removes one inventory configuration by `id` (204, idempotent). |
| [ListBucketInventoryConfigurations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketInventoryConfigurations.html) | ✅ Supported | Lists every stored inventory configuration id (complete and sorted). |
| [GetBucketMetricsConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketMetricsConfiguration.html) | ✅ Supported | Reads one stored metrics configuration by `id`, or an honest 404 `NoSuchConfiguration`. |
| [PutBucketMetricsConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketMetricsConfiguration.html) | ✅ Supported | Stores a bounded metrics configuration. Metrics are computed from real catalog state (object count, bytes) and written as a JSON object into the destination; there is no CloudWatch backend, and that substitution is documented in the module. |
| [DeleteBucketMetricsConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketMetricsConfiguration.html) | ✅ Supported | Removes one metrics configuration by `id` (204, idempotent). |
| [ListBucketMetricsConfigurations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketMetricsConfigurations.html) | ✅ Supported | Lists every stored metrics configuration id (complete and sorted). |
| [RenameObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RenameObject.html) | ✅ Supported | `POST /{bucket}/{destination}?rename` with the source in the signed `x-amz-rename-source` header. Atomic: the head, manifest key and published-version key move in ONE SQL transaction, so no Telegram bytes are copied. A documented superset of AWS (which limits rename to directory buckets). Overwrite and conditional headers are rejected; object lock blocks it exactly like delete; ACL is enforced on source and destination. |
| [SelectObjectContent](https://docs.aws.amazon.com/AmazonS3/latest/API/API_SelectObjectContent.html) | ✅ Supported | `POST /{bucket}/{key}?select&select-type=2`. Reads the object through the storage engine and runs a bounded SQL subset (`SELECT`/`FROM S3Object`/`WHERE`/`LIMIT` with comparisons, AND/OR/NOT) over CSV or JSON, returning a real AWS binary event-stream (`Records`, `Stats`, `End`) with byte-exact framing. Parquet, non-SQL expression types and unsupported SQL are rejected rather than approximated; scan and event sizes are bounded. |
| [RestoreObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html) | ✅ Supported | Strict AWS XML validation, then `403 InvalidObjectState` — the AWS-conformant answer for an object that is already in an immediately readable class. The archive path is a single documented seam so a future tiering phase only changes one function. |
| [GetObjectAnnotation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAnnotation.html) | ✅ Supported | Reads one annotation by name from the separate annotation store (not tags, not user metadata), or an honest 404. |
| [PutObjectAnnotation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectAnnotation.html) | ✅ Supported | Creates or replaces one annotation on the current object. Names are a safe charset ≤128 bytes, values ≤1 KiB, ≤50 annotations per object; the store is independent from tagging. |
| [DeleteObjectAnnotation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectAnnotation.html) | ✅ Supported | Removes one annotation by name (204, idempotent). |
| [ListObjectAnnotations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectAnnotations.html) | ✅ Supported | Lists annotations with prefix filtering and HMAC-signed continuation tokens; bounded page sizes. |
| [PutBucketRequestPayment](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketRequestPayment.html) | ✅ Supported | Accepts exactly the one state that exists here, `Payer=BucketOwner`; `Requester` is rejected 501 because no requester-pays billing exists. The value is therefore writable without being a lie. |
| [PutBucketAccelerateConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAccelerateConfiguration.html) | ✅ Supported | Accepts exactly `Status=Suspended`; `Enabled` is rejected 501 because there is no edge network. Supports the single real state instead of pretending. |
| [GetBucketIntelligentTieringConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketIntelligentTieringConfiguration.html) | ✅ Supported | Reads one stored Intelligent-Tiering configuration by id, or an honest 404 `NoSuchConfiguration`. |
| [PutBucketIntelligentTieringConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketIntelligentTieringConfiguration.html) | ✅ Supported | Stores a bounded Smart-Tiering document (16 KiB, strict XML). AccessTier is limited to ARCHIVE_ACCESS / DEEP_ARCHIVE_ACCESS; unknown tier names are rejected. A scheduler really transitions `storage_class` from real access timestamps, and an archived object answers 403 InvalidObjectState until restored — so the tier label has an observable consequence. The Telegram chunks never move: this is an access gate in our catalog, explicitly not AWS Glacier. |
| [DeleteBucketIntelligentTieringConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketIntelligentTieringConfiguration.html) | ✅ Supported | Removes one configuration by id (204, idempotent). Objects already transitioned stay in their class until the next pass. |
| [ListBucketIntelligentTieringConfigurations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBucketIntelligentTieringConfigurations.html) | ✅ Supported | Lists every stored configuration id (complete and sorted). |
| [CreateBucketMetadataConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucketMetadataConfiguration.html) | ✅ Supported | Creates a V2 metadata configuration backed by TeleDrive's REAL SQL mutation journal (`storage_metadata_journal`), not AWS-managed Apache Iceberg/S3 Tables. A second create answers 409 `BucketMetadataConfigurationAlreadyExists`; that name is a TeleDrive code, not an AWS-documented error. |
| [CreateBucketMetadataTableConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucketMetadataTableConfiguration.html) | ✅ Supported | Creates the V1 configuration, retaining the client-supplied `S3TablesDestination` as an opaque label only — no S3 Tables bucket is provisioned or claimed. 409 on an existing configuration. |
| [GetBucketMetadataConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketMetadataConfiguration.html) | ✅ Supported | Returns the stored V2 configuration plus statistics computed from the real journal. Identifiers are TeleDrive-shaped (`teledrive:metadata:<bucket>`), never AWS ARNs; an absent configuration is 404 `NoSuchConfiguration`. Two honesty notes: `TableStatistics` (record count and oldest/newest timestamps) is a TeleDrive extension — boto3 drops it because it is not in the AWS shape, so read the raw XML to see it; and `TableStatus` is our own state, not an AWS table lifecycle. |
| [GetBucketMetadataTableConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketMetadataTableConfiguration.html) | ✅ Supported | Returns the V1 configuration and the same real journal statistics (TeleDrive extension, raw XML only); the V1 selector answers 405 when the bucket holds a V2 configuration. Absent configuration is 404 `NoSuchConfiguration`. |
| [DeleteBucketMetadataConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketMetadataConfiguration.html) | ✅ Supported | Deletes the configuration and its local journal rows (204, idempotent). Unlike AWS it leaves no managed table behind. |
| [DeleteBucketMetadataTableConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketMetadataTableConfiguration.html) | ✅ Supported | Deletes a V1 configuration (204, idempotent); answers 405 if the bucket holds a V2 configuration. |
| [UpdateBucketMetadataAnnotationTableConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UpdateBucketMetadataAnnotationTableConfiguration.html) | ✅ Supported | Toggles annotation journaling and stores the optional role; 404 `NoSuchConfiguration` when the configuration is missing. |
| [UpdateBucketMetadataInventoryTableConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UpdateBucketMetadataInventoryTableConfiguration.html) | ✅ Supported | Toggles inventory-table state over the same journal; 404 `NoSuchConfiguration` when the configuration is missing. |
| [UpdateBucketMetadataJournalTableConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UpdateBucketMetadataJournalTableConfiguration.html) | ✅ Supported | Sets the real retention window (Days 7 and above, or DISABLED); expired journal rows are trimmed in bounded batches. 404 `NoSuchConfiguration` when missing. |
| [PutBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html) | ✅ Supported | Stores only the empty `ServerSideEncryptionConfiguration` (the honest state for client-supplied keys). A default `AES256` (SSE-S3) or `aws:kms` rule is rejected 501: TeleDrive holds no server-side key for data the client did not encrypt. |
| [DeleteBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html) | ✅ Supported | Removes the stored bucket encryption document (204, idempotent). Object-level SSE-C keys are unaffected. |
| [GetBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html) | ✅ Supported | Reads the real stored bucket document, which can only be an empty rule set (SSE-C has no bucket-level default key); an honest 404 `ServerSideEncryptionConfigurationNotFoundError` when nothing is stored. |
| [UpdateObjectEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UpdateObjectEncryption.html) | ✅ Supported | `PUT ?encryption` re-encrypts every chunk of an existing object to a new customer key in one bounded streaming pass (old key in the `x-amz-copy-source-*` SSE-C headers when the object is already encrypted), then swaps all chunk references and the key fingerprint in one SQL transaction. Plaintext objects can be upgraded in place; a missing/wrong old key or an aliased object fails closed. |
| [PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html) | ✅ Supported | Size-bounded, checksum-verified upload with metadata/tags, conditional writes and version creation; aws-chunked streaming bodies decoded and verified (signed chunk-signature chains, unsigned-payload trailers, decoded-length accounting). Server-side encryption is supported **only** as SSE-C: a client-supplied AES-256 key encrypts each Telegram chunk with AES-256-GCM under a fresh nonce and an AAD binding it to its object identity and ordinal; the key is never persisted or logged. `x-amz-server-side-encryption: AES256/aws:kms` (SSE-S3/SSE-KMS) is rejected 501 because no server-side key exists, not silently ignored. SSE-C objects are excluded from content-addressed dedup and from the plaintext search index. |
| [GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html) | ✅ Supported | Full, byte-range and selected VersionId reads with ETag/date conditions. SSE-C objects require the same customer key on every read: a missing or wrong key is `400 InvalidRequest` before any plaintext is emitted, each overlapping chunk is GCM-authenticated before decryption, and the response never advertises a plaintext checksum or plaintext ETag. No archive/SSE-S3/KMS storage classes exist; those requests are rejected rather than emulated. |
| [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html) | ✅ Supported | Object metadata and selected VersionId/read preconditions. SSE-C HEAD verifies the key against the stored non-secret key-MD5 fingerprint and returns the AWS SSE-C response headers (algorithm + key MD5) without ever returning the key. Absent AWS headers describe features that do not exist here. |
| [CreateMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html) | ✅ Supported | Signed initiation with selected metadata. With SSE-C headers the upload is bound to that key fingerprint: every UploadPart, ListParts and CompleteMultipartUpload must present the same key or fails with `400 InvalidRequest`. Retention and storage-tier variants have no backing and fail closed. |
| [GetBucketRequestPayment](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketRequestPayment.html) | ✅ Supported | Returns the exact stored payer as AWS-shaped XML (`<Payer>BucketOwner</Payer>` for every bucket, because no requester-pays billing exists here). The renderer is the same document `PutBucketRequestPayment` accepts, and a real boto3 client reads `Payer == BucketOwner`. |
| [GetBucketAccelerateConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAccelerateConfiguration.html) | ✅ Supported | Returns `Status=Suspended` as AWS-shaped XML (`<Status>`, the element botocore's model declares — an earlier build emitted the internal enum name and boto3 parsed nothing). The renderer is the same document `PutBucketAccelerateConfiguration` accepts; `Enabled` is rejected 501 because there is no edge network. |
| [CreateSession](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateSession.html) | ✅ Supported | Refuses truthfully instead of pretending: a malformed session name is `400 InvalidBucketName`, an existing general-purpose bucket is `400 InvalidRequest` naming the required directory-bucket class, and any other well-formed name is the AWS-declared `404 NoSuchBucket`. TeleDrive has no S3 Express directory buckets, so no session can ever be issued. Signed requests are accepted under the real `s3express` SigV4 scope, which is pinned to this operation and `ListDirectoryBuckets`. |
| [ListDirectoryBuckets](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListDirectoryBuckets.html) | ✅ Supported | A deployment with zero directory buckets has a real AWS answer: `200` with an empty `ListDirectoryBucketsResult` — no `Buckets`, no `ContinuationToken`. That is permanent truth here, not a stub. `continuation-token` (1–1024 chars) and `max-directory-buckets` (1–1000) are validated and unknown parameters rejected with 400; signalled by the `s3express` scope, `max-directory-buckets`, or the `x-id` hint. |

> **Journal actor field.** Rows written by object tagging, annotation, ACL and rename record the acting access key. Rows written by internal catalog operations (publish, delete marker, version revocation, multipart completion) record an empty actor rather than a guessed one — the catalog layer does not know which credential a background scheduler or GC pass belongs to. An empty actor means "not attributed", never "anonymous".

### 3.2 Partial — by code (closeable gaps)

These are ordinary missing features; nothing architectural blocks them.

**Status:** none remain — every previously by-code partial has shipped
(ListObjects/V2 Owner elements, UploadPart checksum parity, ListObjectVersions
delimiter/encoding-type, CopyObject date conditions, ranged copy-source and
presigned CopyObject, CompleteMultipartUpload FULL_OBJECT and non-SHA
composite checksum modes). New gaps found in the field re-open this section.

### 3.3 Partial — by design (fail-closed architecture)

The design reason column names the decision that keeps the gap open;
the enforced-behavior column is the actual contract. The reasons and
what would unlock each of them:

**Resolution program:** [Metadata-Backed S3 Parity Plan](METADATA_PARITY_PLAN.md)
— the stance is that an emulated feature is honest when it has real
SQL state, enforcement on every violating path and GET observability.
Phases A–J convert 35 of these 37 partials to Supported with
metadata-backed work (GC-integrated deletes, versioning states, object
lock, ACL grants, PAB, notifications, replication surface, CORS
grammar, website mode, tagging journal); only RequestPayment and
Accelerate stay by-design (no honest backing exists).

| Design reason | Holds because | To fully support (recommendation) |
| --- | --- | --- |
| `private-only` | Public access, ACLs, bucket policies, SSE, requester-pays and transfer acceleration have no backing over a private single-owner Telegram gateway — implementing them naively would fake AWS semantics. | Implement a REAL authorization layer first: a bucket-policy engine (JSON policy → per-request evaluation against credential principals, mapped onto the existing per-credential permission scopes), then let ACL/policy writes configure it. SSE-S3 could be honest as server-side envelope encryption with a deployment-managed key (config-held master key, per-object data keys); SSE-KMS/SSE-C stay out. Website hosting needs an explicit public-exposure decision for the private model. |
| `gc-owner-gate` | RESOLVED (Phase A of the metadata parity plan): the owner toggle, grace-fenced collection queue and lifecycle evaluator shipped — deletes, aborts and expirations now physically reclaim media when GC is enabled. No operation carries this reason anymore. | Open the owner gates, then wire the GC planner end-to-end. Lifecycle expiration, AbortMultipartUpload media cleanup and "true" DeleteObject semantics become possible exactly then — the catalog side (delete markers, versions, tombstones) already exists. |
| `versioning-model` | RESOLVED (Phase B of the metadata parity plan): bucket versioning states shipped — Suspended is a real persisted mode with AWS-shaped write/delete semantics. | No operation carries this reason anymore. |
| `tagging-scope` | Unpublished READY staging is never addressable through VersionId, and SQL row locks fence concurrent physical metadata changes — deliberate write-fence safety. | Exposing staged manifests would weaken the write fence; the alternative is keeping it. Only worth relaxing if a concrete workflow needs tag edits on in-flight uploads. |
| `cors-grammar` | The restricted CORS rule grammar (bounded origins/methods, 64 KiB XML) is a security decision, not a parsing limit. | Widen the allowed origin/method grammar while keeping the allowlist fail-closed (e.g. safe wildcard subdomain matching). Pure code, low risk. |

| AWS S3 API operation | Status | Gap class | Design reason | Enforced behavior |
| --- | --- | --- | --- | --- |

## 4. Unsupported AWS S3 actions grouped for the roadmap

**All operations below are unsupported even when a similarly named REST admin endpoint or internal SQL function exists.** The identifiers specify planned workstreams, **not** commitments that every AWS feature will ship in P2. Security- or cloud-specific functionality may remain intentionally unsupported. Grouping is exhaustive for the reference inventory above.

### P2-C — Access control, ACLs, policies and ownership

Keep private-by-default security. Define either a tested private-only compatibility response or a real policy/ownership engine before advertising parity.

**To fully support:** build a real bucket-policy engine — JSON policy documents parsed into per-request rules evaluated against credential principals (the existing per-credential permission scopes become the principal model), with PutBucketPolicy/DeleteBucketPolicy writing the rule store and every S3 route consulting it before scope checks. ACL writes can then map onto the same engine; DeletePublicAccessBlock needs a deliberate public-exposure decision first. Best-effort candidate if the owner accepts exposing policy configuration on a private gateway.

**Researched design — ACL grants mapped onto S3 credentials (owner
decision pending).** TeleDrive S3 credentials already carry per-operation
scopes (s3:GetObject, s3:PutObject, …) enforced on every request; an ACL
layer can reuse them as the grant model without building the full policy
engine:

- **Principal mapping.** An ACL grantee `CanonicalUser` ID maps to an S3
  access key's owner identity (the HMAC-scoped ID already returned by
  ListBuckets/ListObjects `Owner`). Email/Group grantees and the
  `AllUsers`/`AuthenticatedUsers` groups stay unsupported — that is the
  private-only line, unchanged.
- **PutBucketAcl** parses `AccessControlPolicy` grants
  (READ/WRITE/FULL_CONTROL) and stores bucket-level credential grants in
  a new `storage_bucket_acl_grants` table (bucket, grantee access key,
  permission). `FULL_CONTROL` implies READ+WRITE. Owner retains implicit
  FULL_CONTROL; revocation is grant-row deletion.
- **PutObjectAcl** stores per-object grants the same way; object grants
  only ADD access to their exact key, never to siblings.
- **Enforcement is fail-closed intersection.** At authorization time the
  effective permission set of a credential becomes
  `own scopes ∩ (bucket grants ∪ object grants ∪ owner grants)`.
  A credential never gains an operation its scopes do not already carry;
  ACLs can only NARROW or delegate within existing scope. GetObject on an
  ACL-protected bucket therefore requires BOTH s3:GetObject scope AND a
  matching grant.
- **Reads.** GetBucketAcl/GetObjectAcl return the stored grants as
  AWS-shaped XML; DeleteBucketAcl/DeleteObjectAcl clear them.

This is bounded work (one table, two parsers, one enforcement hook in
the credential resolution path) and stays honest: it does NOT emulate
AWS account principals, cross-account semantics or public access. If
the owner approves, implement best-effort per this design.

| AWS S3 API operation | Status | Target |
| --- | --- | --- |

### P2-B — Encryption and immutable retention

Implement actual encryption/key lifecycle and enforce per-version retention and legal-hold semantics across REST/S3/local jobs, copy, version delete and eventual physical GC.

**To fully support:** PutBucketEncryption/GetBucketEncryption pairs become honest with server-side envelope encryption — a deployment-managed master key in config, per-object data keys, encrypted-at-rest chunk payloads, and the existing checksum layer verifying ciphertext integrity (note: this conflicts with content-addressed dedup and cross-account replication, which operate on plaintext bytes — a deployment would choose one or the other). Object Lock/retention/legal-hold need a per-version retention column enforced on EVERY delete path (including batch delete and version delete) with compliance mode immutable at the SQL level. Best-effort candidate: retention/legal-hold first (pure catalog work), SSE second (engine-level, conflicts with dedup).

| AWS S3 API operation | Status | Target |
| --- | --- | --- |

### P2-D — Lifecycle, expiration, transitions, replication and restore

Model rules and durable workers without promising AWS transitions that Telegram cannot provide. Physical expiration/deletion requires independent backup and writer fences. A two-person authorization is **not** required (owner decision); an optional signature is verified when supplied.

**To fully support:** PutBucketReplication/DeleteBucketReplication could expose the EXISTING storage-engine cross-account replication (the destination is a second TeleDrive Telegram credential set, not an AWS bucket) — a mapping layer from the S3 replication XML onto the replication runtime is real, bounded work. Expiration/transition rules remain GC-gated (see section 3.3). RestoreObject has no archive tier to restore from — it would require inventing one. Best-effort candidate: the replication configuration surface.

| AWS S3 API operation | Status | Target |
| --- | --- | --- |

### P2-E — Advanced data-plane protocol compatibility

Support copy-part source ranges, signing and ownership, checksum composition and crash/retry semantics; also address parameter/header gaps for already partial operations.

**Status:** no unsupported operations remain in this group — UploadPartCopy
(inclusive copy-source ranges) shipped and the remaining protocol gaps
(trailer checksum composition on completion, version-listing selectors)
— only presigned CopyObject remains, tracked as a by-code partial in section 3.2.

### P2-F — Website, notifications and access logging

Specify whether private-only hosting permits website mode; use transactional outbox for events, durable retries, scoped destinations and secret-safe log delivery.

**To fully support:** website hosting requires an explicit public-exposure decision (a public static-file route serving bucket objects — directly against the private-only model, so it needs an owner call first). Notifications are honest work: a transactional event outbox (the catalog already versions every mutation) plus scoped webhook destinations with durable retries and backpressure. Logging = delivering the existing audit-log stream into a bucket. Best-effort candidate: notifications first (no security conflict), website only behind a deliberate public-mode decision.

| AWS S3 API operation | Status | Target |
| --- | --- | --- |

### P3-G — Analytics, inventory, metrics and tier policies

Requires schedulers/report delivery and storage-tier accounting; out of P2 core. Telegram storage has no AWS Glacier/Intelligent-Tiering equivalence.

**To fully support:** pure code with no architectural conflict — report
schedulers (CSV exports delivered INTO a bucket on a cadence), inventory
listings (the catalog data already exists) and metrics rollups are
conventional features; only the tier-policy group would need real storage
classes to exist (they do not over Telegram). Best-effort candidate if
reporting workflows are wanted; lowest priority otherwise.

| AWS S3 API operation | Status | Target |
| --- | --- | --- |

### P3-H — AWS-managed products, directory buckets, annotations and provider services

Mostly depends on AWS account services (Express sessions, directory buckets, S3 Metadata, Object Lambda, acceleration, billing), not generic S3-compatible object storage.

**To fully support:** most of this group has no honest Telegram mapping
and should stay unsupported — directory buckets, Express sessions,
WriteGetObjectResponse (Lambda payload passthrough), billing (request
payment) and provider metadata tables describe AWS infrastructure that
does not exist here. SelectObjectContent could be approximated with a
server-side streaming filter (expensive: it must download and scan bytes,
and only supports SQL-lite predicates over the first N bytes) — recommend
keeping it out. GetObjectTorrent is obsolete. RenameObject maps to a
metadata-level copy+delete and could be supported if a client needs it.

| AWS S3 API operation | Status | Target |
| --- | --- | --- |
| [GetObjectTorrent](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTorrent.html) | ❌ Unsupported | P3-H |
| [WriteGetObjectResponse](https://docs.aws.amazon.com/AmazonS3/latest/API/API_WriteGetObjectResponse.html) | ❌ Unsupported | P3-H |

## 5. P2 Advanced S3 implementation plan

| Priority | Workstream | Implementation deliverable | Acceptance gate |
| --- | --- | --- | --- |
| P2-0 | Compatibility contract and fail-closed audit | Every known AWS selector, query parameter and unsupported header routed explicitly; central operation registry and machine-readable support manifest generated from tests. | Negative tests prove unsupported requests cannot fall through as successful list/get/put/delete; all documented statuses match behavior. |
| P2-1 | P2-E: multipart, checksums and SDK parity | UploadPartCopy or explicit permanent rejection; checksum negotiation, trailers, multipart composition, VersionId/copy attributes, SDK request-mode compatibility. | boto3 + AWS CLI + rclone matrix; corruption/mismatch rejection, retries, presigns, concurrent writers, cross-client REST/S3 readback. |
| P2-2 | P2-C: policies and ownership | Decide immutable private-only model versus scoped policy engine; implement safe Get/Put/Delete semantics only if authorization is real. | Cross-tenant permissions, deny-by-default, anonymous/public denial, authorization fuzz tests. |
| P2-3 | P2-B: encryption and retention | Design managed keys, SSE at-rest semantics, key rotation and version-aware Object Lock; preserve immutable historical reads. | Restart/backup/restore and recovery proofs, byte-level validation, enforced retention on *every* delete path. |
| P2-4 | P2-D: lifecycle and replication | Durable lifecycle state machine, dry-run expiration, target/failure handling, version-aware safety fences; replication only with genuinely independent destination. | SQL crash/replay/race tests, leaked/orphan protection, no Telegram physical delete without separately approved safety gates. |
| P2-5 | P2-F: notifications/logging/website | Event outbox and subscriber retries first; hosting only if consistent with private-only policy. | Exactly-once-visible event IDs or explicit dedupe policy, backpressure, no credential leakage, restart recovery. |
| After P2 | P3-G/H: reports and AWS-specific services | Independently evaluate ROI; avoid fake AWS-specific semantics (billing, S3 Express, Object Lambda, managed metadata). | Separate design/RFC and client contracts before implementing. |

### Engineering checklist / definition of done

- [x] Commit a machine-readable 116-operation manifest synchronized by CI with the reviewed specification matrix, and add a strict S3 request-parameter allowlist. Upstream AWS additions still require explicit periodic re-audits.
- [ ] For every supported operation, test normal, missing/auth-failed, malformed, over-limit, retry, multiworker race, signature-tampered and crash/restart cases; assert no partial SQL publication.
      **Status — five of the eight columns are now table-driven and complete:**

      | Column | Where | Coverage |
      |---|---|---|
      | normal | per-operation test files | every operation has at least one happy-path test |
      | missing / auth-failed | `tests/s3/test_s3_unsigned_matrix.py` | **all 114 supported operations**, asserted as 401/403 with no mutation and no Telegram traffic |
      | malformed | `tests/s3/test_s3_malformed_matrix.py` | all 14 XML-bodied operations; a 5xx is treated as a failure, not a pass |
      | over-limit | `tests/s3/test_s3_over_limit_matrix.py` | all 5 body-limited operations, limits imported from the enforcing module and sent as `limit + 1` |
      | signature-tampered | `tests/s3/test_s3_sigv4_defense.py` | per-class, not per-operation |
      | crash/restart | `tests/s3/test_s3_restart_matrix.py` | **11 supported operations whose state machine is multi-step**, plus physical GC: PutObject (ready-but-unpublished staging), CompleteMultipartUpload (live/expired completion lease), UploadPart, AbortMultipartUpload, DeleteObject, DeleteObjects, CopyObject, RenameObject, PutBucketPolicy, PutObjectLockConfiguration and RestoreObject; every case opens a NEW `Database`/catalog/store after the crash and asserts no half-publication, no lost chunk accounting and no resurrection |
      | retry, multiworker race | per-operation | only for the operations where the state machine makes it meaningful (publish CAS, multipart, GC) |

      Every matrix carries a meta-test that fails when a supported operation
      is added without an entry, so the coverage cannot rot. The
      *crash/restart* column is now complete for every operation that has a
      two-step durable window between Telegram I/O and SQL publication; the
      remaining operations commit their whole effect in one SQL transaction,
      so a process death cannot interrupt a half-state. What is genuinely
      still open is the *retry* column and the *multiworker race* column
      beyond the publish/multipart/GC paths.
- [x] For unsupported operations, add adversarial selector/HTTP method tests: **no accidental HTTP 200 or mutation**; unsupported-sensitive headers must fail before Telegram I/O.
- [ ] Verify all S3 mutation paths are reflected in REST/local-job heads, version records, tombstones, tags and copy aliases; invariants run against both SQLite and PostgreSQL.
      **Status:** all four write paths converge on `catalog.publish` (or
      `copy_object`, or `MultipartStore.complete`), and the equivalence is
      asserted for REST vs S3 vs local jobs; the *dual-database* half of this
      item is what stays open beyond the live-SQL suite.
- [x] Add boto3, AWS CLI and rclone version-pinned compatibility matrix plus optional client tests; distinguish simulated Telegram I/O from real test-channel Telegram E2E.
- [x] Define atomic migration/rollback and API backward compatibility for every metadata table or new header field; no irreversible rewrite of historic versions.
      **How:** `teledrive/storage/schema.py` is the only writer — append-only
      ordered steps, a recorded `schema_migrations` version, a real
      cross-process lock per backend, idempotent by construction. Historic
      object rows are never rewritten; new columns are nullable or have a
      server default. `docs/UPGRADING.md` carries the per-release migration
      notes.
- [ ] Respect GC blocking prerequisites: independent payload backup and restore rehearsal, owner/alias/retention graph, writer fencing and explicit independent approval **before** physical Telegram deletion.
      **Status:** these are OWNER actions, not engineering work. The code side
      is done — owner/alias/retention graph re-verified per object, writer
      fencing, a durable lease, and `deletion_permitted` stays `False` until
      the approvals exist.
- [x] Update this matrix, [README](../README.md), [Project Status](IMPLEMENTATION_STATUS.md) and [CI Guide](CI_WORKFLOWS.md) **only when implementation and evidence change**; keep unsupported rows marked unsupported until validated on the new SHA.
      **How:** `scripts/ops/sync_s3_inventory.py` is the only writer of this
      file's matrix rows and of the counters in the route-guard and meta
      tests; `--check` runs in CI 1, so drift fails the build instead of
      being discovered later.

## 6. Release and evidence boundaries

A successfully parsed or authenticated AWS request is **not** automatically a supported S3 specification. Successful synthetic tests prove only their scenario, not general AWS service parity, multi-region behavior, original-media recovery or an operator-authorized production cutover. P2 work should preserve the default **one-container** interface topology, bounded resource use, shared REST/S3/local-job catalog, and fail-closed safety guarantees documented in [Project Status](IMPLEMENTATION_STATUS.md).

**Upstream reference:** [Amazon S3 REST API operations](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations_Amazon_Simple_Storage_Service.html). **Repository evidence:** [S3 route](../web/s3.py), [S3 modules](../teledrive/s3/), [S3 tests](../tests/), [TODO](../TODO.md). The AWS operation inventory can grow; re-audit it before every advanced-compatibility milestone.
