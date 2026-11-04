# S3 operation evidence matrix

The [compatibility matrix](s3-specs.md) says **what** each of the 114
supported operations does. This page says **what per-operation proof
exists**: for every supported operation in
[`teledrive/s3/operation_manifest.json`](https://github.com/babico/TeleDrive/blob/main/teledrive/s3/operation_manifest.json),
which of the seven evidence classes below are proven by a test that
names and exercises *that operation* — not only a global sweep.

This is the per-operation half of the roadmap item in
[§3 Protocol evidence](../project/roadmap.md): the table-driven sweeps
already guarantee a floor for everyone; the rows below record the
per-operation depth beyond that floor.

## How to read a cell

| Column | Means | A cell is filled when |
|---|---|---|
| normal | the documented happy path returns the documented shape | a dedicated test exercises this operation's success contract |
| auth-failure | a *validly signed* credential without the operation's own permission (revoked, expired or scoped elsewhere) is refused | a dedicated test proves this operation's authorization denial — the unsigned sweep is the floor, not the cell |
| malformed | syntactically or structurally invalid input is refused 4xx without mutation | a dedicated test sends malformed input to this operation |
| over-limit | an input past the enforced bound (body size, count, value ceiling) is refused | a dedicated test sends `limit + 1` to this operation |
| retry | the same logical request replayed is idempotent or a clean conflict | a dedicated test replays this operation and asserts no second row, no resurrection |
| crash-restart | state survives a process death; a NEW connection/store observes no half-state | a dedicated test reopens the database and asserts this operation's state |
| race | two concurrent writers leave exactly one winner, never a torn state | a dedicated test forces the interleaving for this operation |

* A cell names the test file that proves it (one file, the primary
  proof).
* `—` means the column **cannot apply** to that operation: no request
  body exists to malform or bound (bodyless GET/HEAD/DELETE), or the
  operation has no side effect to replay or crash between (pure reads).
* An **empty cell is the finding**: no dedicated per-operation test
  exists beyond the global sweeps. It does *not* mean the operation is
  untested — see the floor below.

## The global floor (not repeated in cells)

These table-driven sweeps are keyed by manifest operation name and run
per operation; they are the floor every row stands on, and the cells
below deliberately record only evidence *beyond* them:

| Sweep | File | What it proves for every named operation |
|---|---|---|
| unsigned | `tests/s3/test_s3_unsigned_matrix.py` | all 114 supported operations refuse a request with no Authorization header (401/403, no mutation, no Telegram traffic) |
| malformed | `tests/s3/test_s3_malformed_matrix.py` | the 14 XML-bodied operations listed in its table refuse malformed bodies 4xx |
| over-limit | `tests/s3/test_s3_over_limit_matrix.py` | the 5 body-limited operations listed in its table refuse `limit + 1` bodies |
| crash-restart | `tests/s3/test_s3_restart_matrix.py` | the 11 multi-step state machines listed in its table survive a simulated restart |
| retry / race | `tests/s3/test_s3_retry_race_matrix.py` | the 7 retry and 3 race cases listed in its tables hold under replay and concurrency |
| signature-tampered | `tests/s3/test_s3_sigv4_defense.py` | per-class (not per-operation) signature defense |

The evidence files added for this matrix
(`tests/s3/test_s3_evidence_*.py`) fill the largest per-operation gaps:
storage reports, metadata configuration, notifications/logging, tagging
and website hosting.

## Service and bucket lifecycle

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| CreateBucket | tests/s3/test_s3_gateway.py | | — | — | | | tests/s3/test_s3_bucket_listing.py |
| HeadBucket | tests/s3/test_s3_route_guard.py | | — | — | — | — | |
| DeleteBucket | tests/s3/test_s3_gateway.py | | — | — | | | |
| ListBuckets | tests/s3/test_s3_bucket_listing.py | tests/s3/test_s3_permissions.py | tests/s3/test_s3_bucket_listing.py | — | — | — | tests/s3/test_s3_bucket_listing.py |
| GetBucketLocation | tests/s3/test_s3_bucket_location.py | tests/s3/test_s3_bucket_location.py | — | — | — | — | |
| ListDirectoryBuckets | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | — | — | — | |
| CreateSession | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | — | — | tests/s3/test_s3_directory_buckets.py | |

## Object listing

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| ListObjects | tests/s3/test_s3_listing_v1.py | | tests/s3/test_s3_listing_v1.py | — | — | — | |
| ListObjectsV2 | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | tests/s3/test_s3_gateway.py | — | — | — | |
| ListObjectVersions | tests/s3/test_s3_version_listing.py | tests/s3/test_s3_version_listing.py | tests/s3/test_s3_version_listing.py | — | — | — | |

## Object data plane

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| PutObject | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | tests/s3/test_s3_metadata.py | tests/s3/test_s3_quota_gateway.py | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_retry_race_matrix.py |
| GetObject | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | — | — | — | — | |
| HeadObject | tests/s3/test_s3_gateway.py | | — | — | — | — | |
| DeleteObject | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | — | — | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_retry_race_matrix.py |
| DeleteObjects | tests/s3/test_s3_batch_delete.py | tests/s3/test_s3_batch_delete.py | tests/s3/test_s3_batch_delete.py | | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | |
| CopyObject | tests/s3/test_s3_copy.py | tests/s3/test_s3_copy.py | | — | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | |
| GetObjectAttributes | tests/s3/test_s3_object_attributes.py | tests/s3/test_s3_object_attributes.py | tests/s3/test_s3_object_attributes.py | — | — | — | |
| RenameObject | tests/s3/test_s3_rename.py | tests/s3/test_s3_rename.py | tests/s3/test_s3_rename.py | — | | tests/s3/test_s3_restart_matrix.py | |
| SelectObjectContent | tests/s3/test_s3_select.py | tests/s3/test_s3_select.py | tests/s3/test_s3_select.py | tests/s3/test_s3_select.py | — | — | |
| UpdateObjectEncryption | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_sse_c.py | — | | | |

## Multipart

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| CreateMultipartUpload | tests/s3/test_s3_multipart.py | | | — | | | |
| UploadPart | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | | | tests/s3/test_s3_restart_matrix.py | |
| UploadPartCopy | tests/s3/test_s3_gateway.py | | | — | | | |
| ListParts | tests/s3/test_s3_multipart.py | | | — | — | — | |
| ListMultipartUploads | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | — | — | — | |
| CompleteMultipartUpload | tests/s3/test_s3_multipart.py | | tests/s3/test_s3_multipart.py | | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_retry_race_matrix.py |
| AbortMultipartUpload | tests/s3/test_s3_multipart.py | | — | — | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | |

## Bucket tagging

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | — | — | |
| PutBucketTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py |
| DeleteBucketTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | tests/s3/test_s3_evidence_tagging.py | | |

## Object tagging

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetObjectTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | — | — | |
| PutObjectTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py |
| DeleteObjectTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | tests/s3/test_s3_evidence_tagging.py | | |

## CORS

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketCors | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | — | — | — | — | |
| PutBucketCors | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | | | |
| DeleteBucketCors | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | — | — | | | |

## Versioning

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketVersioning | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_bucket_versioning.py | — | — | — | — | |
| PutBucketVersioning | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_bucket_versioning.py | | tests/s3/test_s3_bucket_versioning.py | | |

## Website hosting

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketWebsite | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | — | — | — | — | |
| PutBucketWebsite | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | tests/s3/test_s3_evidence_website.py | tests/s3/test_s3_evidence_website.py | tests/s3/test_s3_evidence_website.py |
| DeleteBucketWebsite | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | — | — | tests/s3/test_s3_evidence_website.py | | |

## Notifications and logging

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketNotification | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | — | — | — | — | |
| GetBucketNotificationConfiguration | tests/s3/test_s3_notifications.py | tests/s3/test_s3_evidence_notifications.py | — | — | — | — | |
| PutBucketNotification | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py |
| PutBucketNotificationConfiguration | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py |
| GetBucketLogging | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | — | — | — | — | |
| PutBucketLogging | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py |

## Replication

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketReplication | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | — | — | — | — | |
| PutBucketReplication | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | | | | |
| DeleteBucketReplication | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | — | — | | | |

## Storage reports — analytics

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketAnalyticsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | — | — | — | — | |
| PutBucketAnalyticsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py |
| DeleteBucketAnalyticsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | tests/s3/test_s3_report_configs.py | | |
| ListBucketAnalyticsConfigurations | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | — | — | |

## Storage reports — inventory

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketInventoryConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | — | — | — | — | |
| PutBucketInventoryConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py |
| DeleteBucketInventoryConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | tests/s3/test_s3_report_configs.py | | |
| ListBucketInventoryConfigurations | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | — | — | |

## Storage reports — metrics

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketMetricsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | — | — | — | — | |
| PutBucketMetricsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py |
| DeleteBucketMetricsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | tests/s3/test_s3_report_configs.py | | |
| ListBucketMetricsConfigurations | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | — | — | |

## Intelligent tiering

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketIntelligentTieringConfiguration | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | — | — | — | — | |
| PutBucketIntelligentTieringConfiguration | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | | | |
| DeleteBucketIntelligentTieringConfiguration | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | — | — | | | |
| ListBucketIntelligentTieringConfigurations | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | — | — | — | |

## Metadata configuration

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| CreateBucketMetadataConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | | |
| CreateBucketMetadataTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | | | tests/s3/test_s3_evidence_metadata_config.py | | |
| GetBucketMetadataConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | — | — | — | — | |
| GetBucketMetadataTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | — | — | — | — | |
| DeleteBucketMetadataConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | | — | tests/s3/test_s3_evidence_metadata_config.py | | |
| DeleteBucketMetadataTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_metadata_journal.py | — | | | |
| UpdateBucketMetadataJournalTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | | | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_metadata_config.py |
| UpdateBucketMetadataInventoryTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | | | | | |
| UpdateBucketMetadataAnnotationTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | | | | | |

## Object annotations

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetObjectAnnotation | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | — | — | — | — | |
| PutObjectAnnotation | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | | |
| DeleteObjectAnnotation | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | — | — | | | |
| ListObjectAnnotations | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | — | — | — | |

## ABAC

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketAbac | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | — | — | — | — | |
| PutBucketAbac | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | | | |

## ACL

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | — | — | — | — | |
| PutBucketAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | | | | |
| GetObjectAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | — | — | — | — | |
| PutObjectAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | | | | |

## Ownership controls

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketOwnershipControls | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | — | — | — | — | |
| PutBucketOwnershipControls | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | | | | |
| DeleteBucketOwnershipControls | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | — | — | | | |

## Public access block

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetPublicAccessBlock | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | — | — | — | — | |
| PutPublicAccessBlock | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | | | | |
| DeletePublicAccessBlock | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | — | — | | | |

## Bucket policy

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketPolicy | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | — | — | — | — | |
| PutBucketPolicy | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_retry_race_matrix.py | | |
| DeleteBucketPolicy | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | — | — | | | |
| GetBucketPolicyStatus | tests/s3/test_s3_policy_status.py | tests/s3/test_s3_policy_status.py | — | — | — | — | |

## Bucket encryption

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketEncryption | tests/s3/test_s3_sse_c.py | | — | — | — | — | |
| PutBucketEncryption | tests/s3/test_s3_sse_c.py | | tests/s3/test_s3_sse_c.py | | | | |
| DeleteBucketEncryption | tests/s3/test_s3_sse_c.py | | — | — | | | |

## Object lock and retention

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetObjectLockConfiguration | tests/s3/test_s3_object_lock.py | | — | — | — | — | |
| PutObjectLockConfiguration | tests/s3/test_s3_object_lock.py | | tests/s3/test_s3_object_lock.py | | | tests/s3/test_s3_restart_matrix.py | |
| GetObjectRetention | tests/s3/test_s3_object_lock.py | | — | — | — | — | |
| PutObjectRetention | tests/s3/test_s3_object_lock.py | | | | | | |
| GetObjectLegalHold | tests/s3/test_s3_object_lock.py | | — | — | — | — | |
| PutObjectLegalHold | tests/s3/test_s3_object_lock.py | | | | | | |

## Lifecycle

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketLifecycle | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | — | — | — | — | |
| PutBucketLifecycle | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | | | |
| GetBucketLifecycleConfiguration | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | — | — | — | — | |
| PutBucketLifecycleConfiguration | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | | | |
| DeleteBucketLifecycle | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | — | — | | | |

## Restore

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| RestoreObject | tests/s3/test_s3_tiering.py | tests/s3/test_s3_restore.py | tests/s3/test_s3_restore.py | — | | tests/s3/test_s3_restart_matrix.py | |

## Request payment and accelerate

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketRequestPayment | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | — | — | — | — | |
| PutBucketRequestPayment | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | | | |
| GetBucketAccelerateConfiguration | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | — | — | — | — | |
| PutBucketAccelerateConfiguration | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | | | |

## Summary

**114 supported operations, 798 cells.** Counted before the
`tests/s3/test_s3_evidence_*.py` files landed (the honest baseline), and
after (the current state):

| Column | filled (before) | filled (now) | n/a | open |
|---|---|---|---|---|
| normal | 113 | 114 | 0 | 0 |
| auth-failure | 74 | 95 | 0 | 19 |
| malformed | 51 | 51 | 51 | 12 |
| over-limit | 18 | 21 | 76 | 17 |
| retry | 12 | 28 | 50 | 36 |
| crash-restart | 11 | 21 | 49 | 44 |
| race | 5 | 15 | 0 | 99 |

A cell is *open* when it is applicable but empty; `n/a` cells are
structurally impossible (bodyless requests for malformed/over-limit,
side-effect-free reads for retry/crash-restart). Coverage of applicable
cells after the evidence files: normal 114/114, auth-failure 95/114,
malformed 51/63, over-limit 21/38, retry 28/64, crash-restart 21/65,
race 15/114.

The ten largest remaining gaps:

1. **race, everything but the publish state machines — 99 open cells.**
   The retry/race matrix covers the write state machines and the
   evidence files cover the report/tagging/website/notification/metadata
   PUT races; read-side behavior under concurrent mutation is proven
   only for `ListBuckets`, and the delete paths of every config family
   have no concurrent delete-vs-put test.
2. **crash-restart, single-transaction config writes — 44 open cells.**
   CORS, versioning, replication, intelligent tiering, ACL, ownership,
   PAB, policy get/delete, encryption, lifecycle, restore and the
   report-delete rows: each commits its whole effect in one SQL
   transaction, so the restart matrix deliberately excludes them, and no
   dedicated per-operation restart test exists yet.
3. **retry, the remaining write families — 36 open cells.** The
   multipart creates/parts/copies, and the config families not covered
   by the evidence files (CORS, versioning, replication, tiering, ACL,
   ownership, PAB, policy get/delete, encryption, lifecycle, restore,
   accelerate/request payment, annotation delete).
4. **auth-failure, the lock family — 6 open cells.**
   `PutObjectLockConfiguration`, `PutObjectRetention`,
   `PutObjectLegalHold` and the lock reads have no signed-but-
   unauthorized denial test; the unsigned sweep is their only floor.
5. **auth-failure, service and multipart basics — 13 open cells.**
   `CreateBucket`, `HeadBucket`, `DeleteBucket`, `HeadObject`,
   `CreateMultipartUpload`, `UploadPartCopy`, `ListParts`,
   `CompleteMultipartUpload`, `AbortMultipartUpload`,
   `CreateBucketMetadataTableConfiguration`-adjacent V1 rows and the
   bucket-encryption trio have no scoped-credential denial naming them.
6. **over-limit, the sweep-only bodies — 17 open cells.**
   `PutBucketReplication` is covered only by the global sweep;
   `PutBucketVersioning`, `PutBucketAcl`, `PutObjectAcl`,
   `PutBucketEncryption`, the V1 metadata create and the object-lock
   bodies have no per-operation bound test.
7. **malformed, the V1 metadata and copy surfaces — 12 open cells.**
   `CreateBucketMetadataTableConfiguration`,
   `DeleteBucketMetadataConfiguration`, `CopyObject`,
   `CreateMultipartUpload`, `UploadPartCopy` and the lock retention and
   legal-hold bodies rely on the global malformed sweep alone.
8. **object lock, the whole auth-failure column** — see gap 4; the
   family's filled-cell count (8 of 39 applicable) is the lowest of any
   family because its writes also lack retry/race/restart depth.
9. **read-side listing races** — `ListObjects`, `ListObjectsV2`,
   `ListObjectVersions`, `ListParts`, `ListMultipartUploads` and the
   report/tag list operations have no test pinning pagination
   consistency while a writer mutates the same prefix (only
   `ListBuckets` cursor stability under concurrent create is proven).
10. **report and tagging delete restart depth** — the delete rows of the
    report and tagging families prove replay idempotency but not
    delete-then-restart durability; the PUT paths do.

### How this page is enforced

`tests/meta/test_s3_evidence_matrix.py` fails the build when a
supported operation in the manifest has no row here, when a non-empty
cell names a test file that does not exist (or contains no tests), or
when a table row loses a column — so a new operation cannot be added
without its evidence row.
