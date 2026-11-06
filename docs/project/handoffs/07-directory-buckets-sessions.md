# Handoff 07 — Real directory bucket and CreateSession behavior

**State:** Delivered in v1.0.10. **Prerequisite:** Handoff 06 and baseline S3 operation route tests green.

**Existing:** `teledrive/s3/directory_buckets.py` always lists zero directory buckets and rejects `CreateSession`; `web/s3_gateway/dispatch.py` discriminates `s3express` signing. This is an honest refusal but not a working Express-like service.

## Design that actually works

- Add `bucket_type = general | directory` with migration, typed create/list/delete, immutable directory bucket name (`base--zone-id--x-s3`), and logical `zone_id` mapping. Do **not** pretend Telegram is an AWS Availability Zone or claim One Zone throughput/durability. If a zone ID is configured, label it a *logical compatibility zone*.
- Implement separate directory namespace/route semantics, delimiter `/`, directory listing and object rules; explicitly reject general-purpose-only operations. Preserve one process and existing SQL/Telegram manifests.
- `CreateSession` must issue cryptographically random short-lived `AccessKeyId`, `SecretAccessKey`, `SessionToken` and `Expiration` bound to one directory bucket, mode (`ReadOnly`/`ReadWrite`), signer identity and configurable logical zone. Default 5-minute lifetime; hash token at rest, store or derive encrypted secret with server master key. Revoke on bucket deletion/owner credential revocation.
- Implement real SigV4 `s3express` session-credential lookup and exact `x-amzn-s3session-token` validation for Zonal/object requests; control-plane bucket operations continue using long-lived credentials. Test credential expiry and revocation (including parallel workers / SQL shared state), bucket crossover, signature mismatch, read-only write refusal, replay, clock skew and token redaction.
- `ListDirectoryBuckets` must enumerate actual directory-bucket SQL rows, support pagination and opaque scoped continuation tokens, and never leak general buckets. `CreateBucket` and `DeleteBucket` must route the type-specific request rather than accepting a directory name in the wrong class.
- Test with a current botocore S3 Express-compatible SDK against real HTTP and with SigV4 recorded requests; do not claim complete SDK auto-refresh until it works end to end.

## Acceptance

1. Create two directory buckets and one general bucket; list only the two directory buckets; paginate; remove one and validate empty/paged responses.
2. `CreateSession` returns usable temporary credentials; PUT/GET/LIST work against the correct directory bucket, read-only mode cannot PUT, expiry and revoke are immediate and distributed.
3. Wrong endpoint, wrong signing service/zone, wrong token, missing signed session token, stale continuation token and invalid zone/name must fail closed.
4. Restart and 3-worker PostgreSQL E2E; duplicate session issuance and deletion races; rollback migration tests; no API-surface regression.
5. Document realistic performance caveat: **functional directory-bucket protocol**, not real AWS S3 Express physical infrastructure.

**AWS source:** https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-security-best-practices.html and https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-overview.html.
