# S3 Request Parameter Ledger

> **Scope:** parameter-level compatibility of TeleDrive's S3 gateway — every request **query parameter and header** the gateway parses, accepts, or rejects, per operation family. This complements the operation-level matrix in [s3-specs.md](s3-specs.md): an operation can be supported while individual options around it are rejected or unverified. **Last reviewed:** 2026-11-03 against the development tree.
>
> Each row names the **test file** that proves the enforced behavior. `tests/…` paths are relative to the repository root; browse them on [GitHub](https://github.com/babico/TeleDrive/tree/main/tests).

## How to read the states

| State | Meaning |
| --- | --- |
| SUPPORTED | Parsed and enforced, with focused regression coverage in the named test file. Not a claim of full AWS parity for every value the parameter can carry. |
| REJECTED | Parsed or matched by a fail-closed guard and answered with a modeled S3 error (`NotImplemented` 501, `InvalidArgument` 400, …) before any SQL or Telegram side effect. |
| UNVERIFIED | The gateway routes or tolerates the parameter, but no test pins its behavior. Treat these rows as the honest gap list — do not rely on them. |

A machine test keeps this ledger honest: `tests/meta/test_s3_parameter_ledger.py` (a) requires every SUPPORTED/REJECTED row to name an existing test file, and (b) re-derives the gateway's parsed query/header name sets from `teledrive/s3/route_guard.py`, `teledrive/s3/sigv4.py`, the protocol helpers and the `web/s3_gateway/` sources, so a parameter added to the code without a ledger row fails CI.

## Common (every operation)

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| `Authorization` (SigV4 header) | SUPPORTED | AWS Signature V4 header signing with scoped persisted S3 keys; SigV2 rejected. | tests/s3/test_s3_sigv4_defense.py |
| `x-amz-date` | SUPPORTED | Signed request timestamp inside the 15-minute SigV4 clock-skew window. The legacy `Date` header alone is not parsed; a header-signed request must carry a signed `x-amz-date`. | tests/s3/test_s3_sigv4_defense.py |
| `x-amz-content-sha256` | SUPPORTED | Signed payload hash verified before staging; `UNSIGNED-PAYLOAD` only with a signed Content-MD5 or SDK checksum. The one exemption is a CreateMultipartUpload initiation (`?uploads=`) that declares `Content-Length: 0` and is not chunked — it carries no bytes; every request that can carry bytes still needs a digest. | tests/s3/test_s3_sigv4_defense.py, tests/s3/test_s3_client_cyberduck.py |
| `content-length` | SUPPORTED | Read only to distinguish a zero-body multipart initiation from a payload-bearing request; a missing length plus `Transfer-Encoding` is never treated as empty. | tests/s3/test_s3_client_cyberduck.py |
| `Host` (virtual-host addressing) | SUPPORTED | Configured virtual-host suffix maps the bucket from the Host header; path-style remains the default. | tests/s3/test_s3_vhost.py |
| `x-amz-security-token` | UNVERIFIED | No STS issuer exists; the S3 Express session token uses `x-amz-s3session-token`, not this header. The code rejects the presigned-query form with `InvalidToken`, but no test pins that, and the header form is not parsed at all. | — |
| `x-amz-mfa` | REJECTED | 501 on every route; no MFA device exists. | tests/s3/test_s3_fail_closed.py |
| `x-amz-expected-bucket-owner` | REJECTED | 501 fail-closed; single-owner deployment has no cross-account bucket-owner check. | tests/s3/test_s3_fail_closed.py |
| `x-amz-request-payer` | REJECTED | 501 on every route; requester-pays does not exist. | tests/s3/test_s3_fail_closed.py |
| `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Signature`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders` (presigned query) | SUPPORTED | Query presigns with 1–604,800 s expiry, limited methods and checksum-bound PUT/multipart rules; `X-Amz-SignedHeaders` binds the signed header set. | tests/s3/test_s3_presigned.py |
| `X-Amz-Algorithm` / `X-Amz-SignedHeaders` on write routes | SUPPORTED | Used to identify presigned copies/uploads and to require signed source headers. | tests/s3/test_s3_presigned_complete.py |
| `x-id` (SDK operation hint) | SUPPORTED | Non-authoritative routing hint only; validated (single, ≤128 chars) and ignored. | tests/s3/test_s3_route_guard.py |

## Service root

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| ListBuckets `max-buckets` | SUPPORTED | 1–10,000 page size with keyset pagination. | tests/s3/test_s3_bucket_listing.py |
| ListBuckets `prefix` | SUPPORTED | Bucket-name prefix filter. | tests/s3/test_s3_bucket_listing.py |
| ListBuckets `bucket-region` | SUPPORTED | Only `us-east-1` accepted; another region is `InvalidRequest` 400. | tests/s3/test_s3_bucket_listing.py |
| ListBuckets `continuation-token` | SUPPORTED | HMAC-scoped cursor bound to the prefix and credential. | tests/s3/test_s3_bucket_listing.py |
| ListDirectoryBuckets `continuation-token` | SUPPORTED | 1–1024 chars; HMAC-scoped, expires after 15 minutes; stale/foreign tokens 400. | tests/s3/test_s3_directory_buckets.py |
| ListDirectoryBuckets `max-directory-buckets` | SUPPORTED | Decimal 1–1000 validation; real keyset pages. | tests/s3/test_s3_directory_buckets.py |

## Bucket listings

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| ListObjectsV2 `list-type` | SUPPORTED | Must be `2`; other values are 400. | tests/s3/test_s3_bucket_listing.py |
| ListObjectsV2 `prefix` | SUPPORTED | Key prefix filter. | tests/s3/test_s3_bucket_listing.py |
| ListObjectsV2 `delimiter` | SUPPORTED | Common-prefix grouping counted against max-keys like AWS. | tests/s3/test_s3_bucket_listing.py |
| ListObjectsV2 `continuation-token` | SUPPORTED | HMAC-scoped cursor; cannot be replayed against another prefix. | tests/s3/test_s3_bucket_listing.py |
| ListObjectsV2 `start-after` | UNVERIFIED | Parsed and applied as the keyset start position, but no dedicated test pins it. | — |
| ListObjectsV2 `max-keys` | SUPPORTED | 0 is a valid empty page; large values are clamped. | tests/s3/test_s3_bucket_listing.py |
| ListObjectsV2 `encoding-type` | SUPPORTED | `url` URL-encodes keys in the XML response; other values rejected. | tests/s3/test_s3_listing_v1.py |
| ListObjectsV2 `fetch-owner` | SUPPORTED | `true` adds the Owner element, `false` omits it, and any other value is 400. | tests/s3/test_s3_gap_closures.py |
| ListObjectsV1 `marker` | SUPPORTED | Keyset cursor; mixing with V2 cursors is 400. | tests/s3/test_s3_listing_v1.py |
| ListObjectVersions `versions` | SUPPORTED | Empty-flag selector for the version listing. | tests/s3/test_s3_version_listing.py |
| ListObjectVersions `key-marker` / `version-id-marker` | SUPPORTED | Paired cursors; a version-id marker requires a key marker and must resolve to a published version. | tests/s3/test_s3_version_listing.py |
| ListObjectVersions `prefix` / `delimiter` / `max-keys` / `encoding-type` | SUPPORTED | Same semantics as the object listings, over version entries. | tests/s3/test_s3_version_listing.py |
| ListMultipartUploads `uploads` | SUPPORTED | Empty-flag selector; owner-scoped sessions only. | tests/s3/test_s3_multipart.py |
| ListMultipartUploads `key-marker` / `upload-id-marker` / `max-uploads` | SUPPORTED | Same-key upload-id cursors with bounded pages. | tests/s3/test_s3_multipart.py |
| ListMultipartUploads `prefix` / `delimiter` / `encoding-type` | SUPPORTED | Grouping and URL encoding like the object listings. | tests/s3/test_s3_multipart.py |

## Bucket control plane

Unless noted, each selector is an empty-flag query (GET/PUT/DELETE per the route guard) and the state is SUPPORTED.

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| `versioning` | SUPPORTED | GET reports Enabled/Suspended; PUT accepts both. Suspended follows the AWS null-version slot contract. | tests/s3/test_s3_bucket_versioning.py |
| `versioning` `MFADelete` (XML field) | REJECTED | 501: no MFA device exists. | tests/s3/test_s3_bucket_versioning.py |
| `location` | SUPPORTED | Empty LocationConstraint (us-east-1 shape). | tests/s3/test_s3_bucket_location.py |
| `tagging` | SUPPORTED | 50-tag limit, UTF-16 validation, atomic replacement, checksum-verified bodies. | tests/s3/test_s3_tagging.py |
| `cors` | SUPPORTED | Restricted grammar, ≤100 rules, ≤64 KiB config; preflight honored. | tests/s3/test_s3_cors.py |
| `acl` | SUPPORTED | Real grant store; PUT replaces the ACL; private-only model. | tests/s3/test_s3_acl.py |
| `policy` | SUPPORTED | Real policy engine with Deny precedence and scoped principals. | tests/s3/test_s3_policy_engine.py |
| `policyStatus` | SUPPORTED | Read-only; always IsPublic=false. | tests/s3/test_s3_policy_status.py |
| `ownershipControls` | SUPPORTED | BucketOwnerEnforced/ObjectWriter/BucketOwnerPreferred with real effects. | tests/s3/test_s3_ownership_abac.py |
| `abac` | SUPPORTED | Principal/object tag condition store and enforcement. | tests/s3/test_s3_ownership_abac.py |
| `replication` | SUPPORTED | SQL-backed replication configuration over the replica engine. | tests/s3/test_s3_replication.py |
| `website` | SUPPORTED | Index/error documents; public read is a separate admin gate. | tests/s3/test_s3_website.py |
| `notification` / `notificationConfiguration` | SUPPORTED | Owner-approved destinations, event filtering, outbox rows. | tests/s3/test_s3_notifications.py |
| `logging` | SUPPORTED | Logging configuration round trip; a bucket without logging returns an empty `BucketLoggingStatus` (AWS shape), not a 404. | tests/s3/test_s3_notifications.py |
| `encryption` | SUPPORTED | Bucket default-encryption configuration CRUD: an empty SSE-C rule set always, or an AES256 default only when `storage.encryption: envelope`; `aws:kms` is 501. | tests/s3/test_s3_sse_c.py |
| `object-lock` | SUPPORTED | One-way enable with default mode/days. | tests/s3/test_s3_object_lock.py |
| `publicAccessBlock` | SUPPORTED | Four persisted flags, all-true default. | tests/s3/test_s3_public_access_block.py |
| `lifecycle` | SUPPORTED | AbortIncompleteMultipartUpload, Expiration (incl. ExpiredObjectDeleteMarker), Transition, NoncurrentVersionTransitions and NoncurrentVersionExpiration rules; archive classes only (others 501). | tests/s3/test_s3_lifecycle.py |
| `requestPayment` | SUPPORTED | BucketOwner accepted and reported; Requester is an honest 501. | tests/s3/test_s3_request_payment_accelerate.py |
| `accelerate` | SUPPORTED | Suspended accepted and reported; Enabled is an honest 501. | tests/s3/test_s3_request_payment_accelerate.py |
| `session` | SUPPORTED | S3 Express CreateSession: issues real short-lived zonal credentials for an existing directory bucket (control plane, long-lived signer). | tests/s3/test_s3_directory_buckets.py |
| `x-amz-create-session-mode` | SUPPORTED | CreateSession mode validation; `ReadOnly`/`ReadWrite` (default `ReadWrite`), malformed modes 400. The handler reads the header but does not currently require it to be in `SignedHeaders`. | tests/s3/test_s3_directory_buckets.py |
| `x-amz-s3session-token` | SUPPORTED | Required and signed on every zonal (object data-plane) directory-bucket request; matched exactly against the stored SHA-256 hash of the issued session token. Missing, unsigned, wrong or replayed-after-revocation tokens are 403 without ever echoing the token. | tests/s3/test_s3_directory_buckets.py |
| `intelligent-tiering` (+ `id`) | SUPPORTED | Tiering configuration CRUD and scheduler. | tests/s3/test_s3_tiering.py |
| `analytics` / `inventory` / `metrics` (+ `id`) | SUPPORTED | Storage-report configuration CRUD; CSV/JSON lines outputs. | tests/s3/test_s3_report_configs.py |
| `metadataConfiguration` / `metadataTable` / `metadataJournalTable` / `metadataInventoryTable` / `metadataAnnotationTable` | SUPPORTED | S3 Metadata table configuration CRUD (V1/V2 shapes). | tests/s3/test_s3_metadata_journal.py |
| `delete` (POST DeleteObjects) | SUPPORTED | Batch delete with per-entry markers or explicit VersionIds, Quiet mode, per-object ACL. | tests/s3/test_s3_batch_delete.py |

## Object data plane (GET/HEAD/PUT/DELETE)

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| `versionId` (GET/HEAD) | SUPPORTED | Reads one published historical version; delete markers answer 405 with `Allow: DELETE`. | tests/s3/test_s3_version_reads.py |
| `versionId` (DELETE) | SUPPORTED | Permanently revokes that version; head advances to the latest remaining version. | tests/s3/test_s3_version_reads.py |
| `response-content-type` / `response-content-disposition` / `response-cache-control` / `response-content-encoding` / `response-content-language` / `response-expires` | SUPPORTED | Signed presigned-URL response overrides for GetObject/HeadObject; ≤2 KiB, control characters rejected. | tests/s3/test_s3_review_fixes.py |
| `Range` | SUPPORTED | Byte ranges (inclusive AWS syntax); over-long ranges serve the whole object. | tests/s3/test_s3_gateway.py |
| `If-Match` / `If-None-Match` (reads) | SUPPORTED | ETag preconditions with 412/304 semantics. | tests/s3/test_s3_conditions.py |
| `If-Modified-Since` / `If-Unmodified-Since` (reads) | SUPPORTED | Date preconditions against the stable manifest timestamp. | tests/s3/test_s3_conditions.py |
| `If-Range` | SUPPORTED | Matching validator permits the 206; a stale validator serves the full body. | tests/s3/test_s3_conditions.py |
| `If-Match` / `If-None-Match` (writes: PUT/DELETE/MPU-complete) | SUPPORTED | Signed conditional writes with atomic CAS; date-based write conditions are 501. | tests/s3/test_s3_conditional_writes.py |
| `x-amz-checksum-mode` | SUPPORTED | `ENABLED` on GET/HEAD returns the full-object SHA-256; other values 400; wrong routes 501. | tests/s3/test_s3_additional_checksums.py |
| `Content-MD5` | SUPPORTED | Verified against the body on PUT and control-plane bodies; mismatch is `BadDigest`. | tests/s3/test_s3_additional_checksums.py |
| `x-amz-sdk-checksum-algorithm` | SUPPORTED | Binds the declared SDK algorithm to its checksum header value. | tests/s3/test_s3_additional_checksums.py |
| `x-amz-checksum-sha256` / `x-amz-checksum-sha1` / `x-amz-checksum-crc32` / `x-amz-checksum-crc32c` / `x-amz-checksum-crc64nvme` | SUPPORTED | Declared digests verified before any Telegram upload; mismatches never upload. | tests/s3/test_s3_additional_checksums.py |
| `x-amz-tagging` (PUT) | SUPPORTED | Signed inline tags (≤8 KiB, ≤10 tags) applied atomically at publish; requires PutObjectTagging scope. | tests/s3/test_s3_tagging.py |
| `x-amz-meta-*` (PUT/copy REPLACE) | SUPPORTED | Signed custom metadata persisted per version, ≤2 KiB serialized. | tests/s3/test_s3_metadata.py |
| `Content-Type` / `Cache-Control` / `Content-Disposition` / `Content-Encoding` / `Content-Language` / `Expires` (PUT) | SUPPORTED | Signed HTTP metadata persisted per version and replayed on reads. | tests/s3/test_s3_metadata.py |
| `x-amz-acl` | SUPPORTED | Only `private`, `bucket-owner-read` and `bucket-owner-full-control` accepted (signed); other canned ACLs 501, unknown values 400 `InvalidArgument`; on PUT `?acl` a canned value may replace the XML body. | tests/s3/test_s3_acl_parity.py |
| `x-amz-storage-class` | SUPPORTED | Only `STANDARD` accepted (signed); other tiers 501. | tests/s3/test_s3_fail_closed.py |
| `x-amz-server-side-encryption: AES256` (PUT) | SUPPORTED | Real SSE-S3 envelope when `storage.encryption: envelope`; otherwise a precise 501 naming the setting. | tests/s3/test_s3_sse_c.py |
| `x-amz-server-side-encryption: aws:kms` / `aws:kms:dsse` | REJECTED | 501: no AWS KMS backend exists. | tests/s3/test_s3_fail_closed.py |
| `x-amz-server-side-encryption-aws-kms-key-id` / `x-amz-server-side-encryption-context` / `x-amz-bucket-key-enabled` | REJECTED | 501 fail-closed on every route (KMS family). | tests/s3/test_s3_fail_closed.py |
| SSE-C: `x-amz-server-side-encryption-customer-algorithm`, `x-amz-server-side-encryption-customer-key`, `x-amz-server-side-encryption-customer-key-md5` | SUPPORTED | Full family required and signed; per-object AES-256-GCM; a missing or wrong key is `400 InvalidRequest` before any plaintext is emitted. | tests/s3/test_s3_sse_c.py |
| `x-amz-trailer` + `x-amz-decoded-content-length` (aws-chunked) | SUPPORTED | Accepted only on genuine streaming uploads; the decoder enforces the declared trailer and length. | tests/s3/test_s3_aws_chunked.py |
| `Content-Encoding: aws-chunked` | SUPPORTED | Decoded and verified when streaming mode is genuine; otherwise rejected. | tests/s3/test_s3_aws_chunked.py |
| `x-amz-grant-read` / `x-amz-grant-write` / `x-amz-grant-full-control` / `x-amz-grant-read-acp` / `x-amz-grant-write-acp` | SUPPORTED | On PUT `?acl` (signed): `id="…"` CanonicalUser grantees apply like XML grants; `emailAddress`/`uri` grantees and the ACP pair 501; malformed grammar 400; grant headers on other write routes 501. A GET `?acl` that carries grant headers currently ignores them instead of refusing. | tests/s3/test_s3_acl_parity.py |
| `x-amz-website-redirect-location` | REJECTED | 501: no website redirect. | tests/s3/test_s3_fail_closed.py |
| `x-amz-object-lock-mode` / `x-amz-object-lock-retain-until-date` / `x-amz-object-lock-legal-hold` (PUT) | REJECTED | 501: retention is set via the retention control, never acknowledged silently on upload. | tests/s3/test_s3_object_lock.py |
| `x-amz-bypass-governance-retention` | SUPPORTED | On PUT `?retention` only (signed, exactly `true`): shortens/clears an active GOVERNANCE window when the credential holds `s3:BypassGovernanceRetention`, else 403 `AccessDenied`; `false` is the explicit negative, other values 400; COMPLIANCE never shortens; every other route stays 501. | tests/s3/test_s3_governance_bypass.py |

## Object subresources

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| `tagging` (+ `versionId`) | SUPPORTED | Per-version tag sets; a version selector addresses one published version. | tests/s3/test_s3_version_tagging.py |
| `attributes` (+ `versionId`) | SUPPORTED | GetObjectAttributes over published historical versions. | tests/s3/test_s3_object_attributes.py |
| `x-amz-object-attributes` | SUPPORTED | Signed attribute list; only ETag/ObjectSize/Checksum/StorageClass/ObjectParts supported, others 501. | tests/s3/test_s3_object_attributes.py |
| `x-amz-max-parts` / `x-amz-part-number-marker` | SUPPORTED | Signed 1–1000 / 0–10000 part pagination for ObjectParts. | tests/s3/test_s3_object_attributes.py |
| `acl` (object) | SUPPORTED | Per-key object ACL grants; versioned ACL selectors unsupported. | tests/s3/test_s3_acl.py |
| `retention` (+ `versionId`) | SUPPORTED | GOVERNANCE/COMPLIANCE retention windows per version; locked versions refuse deletes. | tests/s3/test_s3_object_lock.py |
| `legal-hold` (+ `versionId`) | SUPPORTED | Per-version legal hold with delete fencing. | tests/s3/test_s3_object_lock.py |
| `restore` (+ `versionId`) | SUPPORTED | Queues a real cold retrieval for verified archives (202, `ongoing-request="true"` until whole-SHA256 verification opens the window) or opens the hot-copy window when no archive exists; STANDARD objects answer `InvalidObjectState`; Days/Tier validated. | tests/s3/test_s3_restore.py |
| `select` + `select-type` | SUPPORTED | `select-type=2` is required; bounded SQL subset over real bytes; unsupported expressions are rejected, never ignored. | tests/s3/test_s3_select.py |
| `rename` / `renameObject` | SUPPORTED | TeleDrive superset of the directory-bucket rename; destination must not exist (409). | tests/s3/test_s3_rename.py |
| `x-amz-rename-source` | SUPPORTED | Signed local `bucket/key` source; same-bucket only. | tests/s3/test_s3_rename.py |
| `x-amz-rename-source-if-*` | REJECTED | 501: conditional rename is unsupported. | tests/s3/test_s3_rename.py |
| `encryption` (object PUT) | SUPPORTED | UpdateObjectEncryption rotates an existing object to a new SSE-C key. | tests/s3/test_s3_sse_c.py |
| `annotation` (+ `annotationName`) | SUPPORTED | Per-object annotation CRUD with signed checksums. | tests/s3/test_s3_annotations.py |
| `annotation-prefix` / `max-annotation-results` / `continuation-token` (annotation listing) | SUPPORTED | Bounded, paginated annotation listing on the current object. | tests/s3/test_s3_annotations.py |

## CopyObject and UploadPartCopy

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| `x-amz-copy-source` | SUPPORTED | Must be signed; local bucket/key only; may carry a single `?versionId=` selector for a published source version. | tests/s3/test_s3_copy.py |
| `x-amz-copy-source-if-match` / `x-amz-copy-source-if-none-match` | SUPPORTED | Signed source preconditions with 412 on failure. | tests/s3/test_s3_copy.py |
| `x-amz-copy-source-if-modified-since` / `x-amz-copy-source-if-unmodified-since` | SUPPORTED | Date conditions with AWS precedence (ETag condition overrides a contradicting date). | tests/s3/test_s3_copy.py |
| `x-amz-copy-source-range` | SUPPORTED | Signed inclusive `bytes=first-last`; a ranged copy stages real bytes. | tests/s3/test_s3_copy.py |
| `x-amz-metadata-directive` | SUPPORTED | `COPY` (default) or `REPLACE`, signed; metadata requires REPLACE. | tests/s3/test_s3_copy.py |
| `x-amz-tagging-directive` | SUPPORTED | `COPY` (default) or `REPLACE`, signed; tag scopes enforced on both. | tests/s3/test_s3_copy.py |
| `x-amz-server-side-encryption` / `x-amz-storage-class` on CopyObject | REJECTED | 501: copy never acknowledges encryption or tiers. | tests/s3/test_s3_copy.py |
| `x-amz-copy-source-server-side-encryption-customer-algorithm`, `x-amz-copy-source-server-side-encryption-customer-key`, `x-amz-copy-source-server-side-encryption-customer-key-md5` | REJECTED | 501 except on UpdateObjectEncryption, which parses this AWS-spelled old-key family for SSE-C rotation; copy-source SSE-C keys fail closed elsewhere. | tests/s3/test_s3_sse_c.py |

## Multipart upload

| Parameter | State | Enforced behavior | Proven by |
| --- | --- | --- | --- |
| `uploads` (POST initiate) | SUPPORTED | Metadata-only initiate; empty body required; SSE-C key bound at initiate. | tests/s3/test_s3_multipart.py |
| `uploadId` (POST complete / DELETE abort / GET list) | SUPPORTED | Owner-scoped session with durable staged parts and completion leases. | tests/s3/test_s3_multipart.py |
| `partNumber` (PUT UploadPart) | SUPPORTED | 1–10,000; required together with `uploadId`. | tests/s3/test_s3_multipart.py |
| `partNumber` (GET Object) | SUPPORTED | Exactly one decimal 1–10,000; serves the logical MPU part from the immutable completion layout (sparse-safe offset math); 206 + `Content-Range` + `x-amz-mp-parts-count`; single-PUT part 1 is the whole object; zero-byte part is an empty 200; absent part → 416 `InvalidPartNumber`; Range+partNumber → 400 `InvalidRequest`; HEAD stays 501. | tests/s3/test_s3_part_number.py |
| `part-number-marker` / `max-parts` (ListParts) | SUPPORTED | Decimal 0–10000 / 1–1000 bounded pages. | tests/s3/test_s3_multipart.py |
| `x-amz-checksum-type` (complete) | SUPPORTED | `COMPOSITE`/`FULL_OBJECT` validation at completion; a non-SHA declaration requires an explicit type. | tests/s3/test_s3_multipart.py |

## Known non-goals

- The literal AWS wire string `versionId: null` is not used: TeleDrive version IDs are internal UUIDs, and the null-version slot is enforced structurally (see [s3-specs.md](s3-specs.md) and `tests/s3/test_s3_versioning_submodes.py`).
- SigV2, STS session tokens, and AWS KMS headers are out of scope by design; they are either rejected or (for the session token) explicitly listed UNVERIFIED above.
