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
| CreateBucket | tests/s3/test_s3_gateway.py | tests/s3/test_s3_evidence_authfail.py | — | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_bucket_listing.py |
| HeadBucket | tests/s3/test_s3_route_guard.py | tests/s3/test_s3_evidence_authfail.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| DeleteBucket | tests/s3/test_s3_gateway.py | tests/s3/test_s3_evidence_authfail.py | — | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_control.py |
| ListBuckets | tests/s3/test_s3_bucket_listing.py | tests/s3/test_s3_permissions.py | tests/s3/test_s3_bucket_listing.py | — | — | — | tests/s3/test_s3_bucket_listing.py |
| GetBucketLocation | tests/s3/test_s3_bucket_location.py | tests/s3/test_s3_bucket_location.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| ListDirectoryBuckets | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | — | — | — | tests/s3/test_s3_evidence_race_listings.py |
| CreateSession | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_directory_buckets.py | — | — | tests/s3/test_s3_directory_buckets.py | tests/s3/test_s3_evidence_race_control.py |

## Object listing

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| ListObjects | tests/s3/test_s3_listing_v1.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_listing_v1.py | — | — | — | tests/s3/test_s3_evidence_race_listings.py |
| ListObjectsV2 | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | tests/s3/test_s3_gateway.py | — | — | — | tests/s3/test_s3_evidence_race_listings.py |
| ListObjectVersions | tests/s3/test_s3_version_listing.py | tests/s3/test_s3_version_listing.py | tests/s3/test_s3_version_listing.py | — | — | — | tests/s3/test_s3_evidence_race_listings.py |

## Object data plane

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| PutObject | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | tests/s3/test_s3_metadata.py | tests/s3/test_s3_quota_gateway.py | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_retry_race_matrix.py |
| GetObject | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | — | — | — | — | tests/s3/test_s3_evidence_race_objects.py |
| HeadObject | tests/s3/test_s3_gateway.py | tests/s3/test_s3_evidence_authfail.py | — | — | — | — | tests/s3/test_s3_evidence_race_objects.py |
| DeleteObject | tests/s3/test_s3_gateway.py | tests/s3/test_s3_permissions.py | — | — | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_retry_race_matrix.py |
| DeleteObjects | tests/s3/test_s3_batch_delete.py | tests/s3/test_s3_batch_delete.py | tests/s3/test_s3_batch_delete.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_evidence_race_objects.py |
| CopyObject | tests/s3/test_s3_copy.py | tests/s3/test_s3_copy.py | tests/s3/test_s3_evidence_limits.py | — | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_evidence_race_objects.py |
| GetObjectAttributes | tests/s3/test_s3_object_attributes.py | tests/s3/test_s3_object_attributes.py | tests/s3/test_s3_object_attributes.py | — | — | — | tests/s3/test_s3_evidence_race_objects.py |
| RenameObject | tests/s3/test_s3_rename.py | tests/s3/test_s3_rename.py | tests/s3/test_s3_rename.py | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_evidence_race_objects.py |
| SelectObjectContent | tests/s3/test_s3_select.py | tests/s3/test_s3_select.py | tests/s3/test_s3_select.py | tests/s3/test_s3_select.py | — | — | tests/s3/test_s3_evidence_race_objects.py |
| UpdateObjectEncryption | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_sse_c.py | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_objects.py |

## Multipart

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| CreateMultipartUpload | tests/s3/test_s3_multipart.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_evidence_limits.py | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_objects.py |
| UploadPart | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_evidence_race_objects.py |
| UploadPartCopy | tests/s3/test_s3_gateway.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_evidence_limits.py | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_objects.py |
| ListParts | tests/s3/test_s3_multipart.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_evidence_limits.py | — | — | — | tests/s3/test_s3_evidence_race_listings.py |
| ListMultipartUploads | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | tests/s3/test_s3_multipart.py | — | — | — | tests/s3/test_s3_evidence_race_listings.py |
| CompleteMultipartUpload | tests/s3/test_s3_multipart.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_multipart.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_retry_race_matrix.py |
| AbortMultipartUpload | tests/s3/test_s3_multipart.py | tests/s3/test_s3_evidence_authfail.py | — | — | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_evidence_race_objects.py |

## Bucket tagging

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py |
| DeleteBucketTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Object tagging

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetObjectTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutObjectTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_tagging.py |
| DeleteObjectTagging | tests/s3/test_s3_tagging.py | tests/s3/test_s3_tagging.py | — | — | tests/s3/test_s3_evidence_tagging.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_config.py |

## CORS

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketCors | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketCors | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| DeleteBucketCors | tests/s3/test_s3_cors.py | tests/s3/test_s3_cors.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Versioning

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketVersioning | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_bucket_versioning.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketVersioning | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_bucket_versioning.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Website hosting

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketWebsite | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketWebsite | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | tests/s3/test_s3_evidence_website.py | tests/s3/test_s3_evidence_website.py | tests/s3/test_s3_evidence_website.py |
| DeleteBucketWebsite | tests/s3/test_s3_website.py | tests/s3/test_s3_website.py | — | — | tests/s3/test_s3_evidence_website.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Notifications and logging

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketNotification | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| GetBucketNotificationConfiguration | tests/s3/test_s3_notifications.py | tests/s3/test_s3_evidence_notifications.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| PutBucketNotification | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py |
| PutBucketNotificationConfiguration | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py |
| GetBucketLogging | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| PutBucketLogging | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py | tests/s3/test_s3_evidence_notifications.py |

## Replication

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketReplication | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketReplication | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| DeleteBucketReplication | tests/s3/test_s3_replication.py | tests/s3/test_s3_replication.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Storage reports — analytics

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketAnalyticsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketAnalyticsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py |
| DeleteBucketAnalyticsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| ListBucketAnalyticsConfigurations | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | — | — | tests/s3/test_s3_evidence_race_config.py |

## Storage reports — inventory

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketInventoryConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketInventoryConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py |
| DeleteBucketInventoryConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| ListBucketInventoryConfigurations | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | — | — | tests/s3/test_s3_evidence_race_config.py |

## Storage reports — metrics

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketMetricsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketMetricsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_evidence_reports.py |
| DeleteBucketMetricsConfiguration | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| ListBucketMetricsConfigurations | tests/s3/test_s3_report_configs.py | tests/s3/test_s3_evidence_reports.py | tests/s3/test_s3_report_configs.py | — | — | — | tests/s3/test_s3_evidence_race_config.py |

## Intelligent tiering

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketIntelligentTieringConfiguration | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketIntelligentTieringConfiguration | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| DeleteBucketIntelligentTieringConfiguration | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| ListBucketIntelligentTieringConfigurations | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | tests/s3/test_s3_tiering.py | — | — | — | tests/s3/test_s3_evidence_race_config.py |

## Metadata configuration

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| CreateBucketMetadataConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |
| CreateBucketMetadataTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |
| GetBucketMetadataConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| GetBucketMetadataTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| DeleteBucketMetadataConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_limits.py | — | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |
| DeleteBucketMetadataTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_metadata_journal.py | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |
| UpdateBucketMetadataJournalTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_metadata_config.py |
| UpdateBucketMetadataInventoryTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |
| UpdateBucketMetadataAnnotationTableConfiguration | tests/s3/test_s3_metadata_journal.py | tests/s3/test_s3_evidence_metadata_config.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |

## Object annotations

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetObjectAnnotation | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutObjectAnnotation | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_config.py |
| DeleteObjectAnnotation | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | — | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_config.py |
| ListObjectAnnotations | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | tests/s3/test_s3_annotations.py | — | — | — | tests/s3/test_s3_evidence_race_config.py |

## ABAC

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketAbac | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketAbac | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## ACL

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| GetObjectAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutObjectAcl | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | tests/s3/test_s3_acl.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_config.py |

## Ownership controls

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketOwnershipControls | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketOwnershipControls | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| DeleteBucketOwnershipControls | tests/s3/test_s3_ownership_abac.py | tests/s3/test_s3_ownership_abac.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Public access block

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetPublicAccessBlock | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutPublicAccessBlock | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| DeletePublicAccessBlock | tests/s3/test_s3_public_access_block.py | tests/s3/test_s3_public_access_block.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Bucket policy

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketPolicy | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketPolicy | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_retry_race_matrix.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |
| DeleteBucketPolicy | tests/s3/test_s3_policy_engine.py | tests/s3/test_s3_policy_engine.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| GetBucketPolicyStatus | tests/s3/test_s3_policy_status.py | tests/s3/test_s3_policy_status.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |

## Bucket encryption

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketEncryption | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_evidence_authfail.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketEncryption | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| DeleteBucketEncryption | tests/s3/test_s3_sse_c.py | tests/s3/test_s3_evidence_authfail.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Object lock and retention

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetObjectLockConfiguration | tests/s3/test_s3_object_lock.py | tests/s3/test_s3_evidence_authfail.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| PutObjectLockConfiguration | tests/s3/test_s3_object_lock.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_object_lock.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_evidence_race_control.py |
| GetObjectRetention | tests/s3/test_s3_object_lock.py | tests/s3/test_s3_evidence_authfail.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| PutObjectRetention | tests/s3/test_s3_object_lock.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_control.py |
| GetObjectLegalHold | tests/s3/test_s3_object_lock.py | tests/s3/test_s3_evidence_authfail.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| PutObjectLegalHold | tests/s3/test_s3_object_lock.py | tests/s3/test_s3_evidence_authfail.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_limits.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_objects.py | tests/s3/test_s3_evidence_race_control.py |

## Lifecycle

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketLifecycle | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketLifecycle | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| GetBucketLifecycleConfiguration | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | — | — | — | — | tests/s3/test_s3_evidence_race_config.py |
| PutBucketLifecycleConfiguration | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |
| DeleteBucketLifecycle | tests/s3/test_s3_lifecycle.py | tests/s3/test_s3_lifecycle.py | — | — | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_config.py |

## Restore

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| RestoreObject | tests/s3/test_s3_tiering.py | tests/s3/test_s3_restore.py | tests/s3/test_s3_restore.py | — | tests/s3/test_s3_evidence_retry_objects.py | tests/s3/test_s3_restart_matrix.py | tests/s3/test_s3_evidence_race_objects.py |

## Request payment and accelerate

| Operation | normal | auth-failure | malformed | over-limit | retry | crash-restart | race |
|---|---|---|---|---|---|---|---|
| GetBucketRequestPayment | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| PutBucketRequestPayment | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |
| GetBucketAccelerateConfiguration | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | — | — | — | — | tests/s3/test_s3_evidence_race_control.py |
| PutBucketAccelerateConfiguration | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_request_payment_accelerate.py | tests/s3/test_s3_evidence_retry_config.py | tests/s3/test_s3_evidence_restart_config.py | tests/s3/test_s3_evidence_race_control.py |

## Summary

**114 supported operations, 798 cells.** Counted before the
`tests/s3/test_s3_evidence_*.py` files landed (the honest baseline), and
after (the current state):

| Column | filled (before) | filled (now) | n/a | open | coverage of applicable |
|---|---|---|---|---|---|
| normal | 113 | 114 | 0 | 0 | 100% |
| auth-failure | 74 | 114 | 0 | 0 | 100% |
| malformed | 51 | 63 | 51 | 0 | 100% |
| over-limit | 18 | 38 | 76 | 0 | 100% |
| retry | 12 | 64 | 50 | 0 | 100% |
| crash-restart | 11 | 65 | 49 | 0 | 100% |
| race | 5 | 114 | 0 | 0 | 100% |

A cell is *open* when it is applicable but empty; `n/a` cells are
structurally impossible (bodyless requests for malformed/over-limit,
side-effect-free reads for retry/crash-restart). All seven columns are
now complete for every applicable cell.

The remaining gaps:

1. **None in the matrix.** The final race audit filled the data plane
   (GetObject/HeadObject/GetObjectAttributes/Select, CopyObject,
   RenameObject, DeleteObjects, `UpdateObjectEncryption`, the multipart
   create/part/part-copy/abort paths and `RestoreObject`) and the
   lock/service control plane (bucket head/delete/location,
   `CreateSession`, the object-lock family, request-payment/accelerate,
   the metadata-config family, the notification/logging reads and the
   policy surfaces). Each row pins a barrier-synchronized read-vs-write
   or write-vs-write contract: one complete version / one complete row,
   or exactly one winner and a designed conflict. The rename race also
   hardened `BucketCatalog.rename_object`: a loser that loses the
   destination head insert now surfaces the designed 409
   `OperationAborted` instead of a raw `IntegrityError` on backends with
   row-level locking (SQLite serializes writers, so its single-writer
   lock masks that window; the branch is defensive there). The listing
   surfaces and every config family's put/delete paths were already
   proven (including the bug an earlier audit found: `ListObjectVersions`
   returned 400 when the marker version was deleted between pages —
   fixed, and the fix is pinned).
2. **A reported, not-yet-reproduced dialect risk outside the matrix:**
   `BucketEncryptionStore.replace` was a SELECT-then-INSERT/UPDATE upsert
   that could surface an `IntegrityError` as a 500 on PostgreSQL/MySQL
   when two concurrent *first* writes raced. It now uses the
   UPDATE-first shape (the shared pattern), proven convergent on SQLite;
   the PostgreSQL/MySQL variant should join the external-backend matrix.

### How this page is enforced

`tests/meta/test_s3_evidence_matrix.py` fails the build when a
supported operation in the manifest has no row here, when a non-empty
cell names a test file that does not exist (or contains no tests), or
when a table row loses a column — so a new operation cannot be added
without its evidence row.
