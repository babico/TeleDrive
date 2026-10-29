# Upgrading to TeleDrive 1.0.8

This guide is for an operator moving from v1.0.7 (or a later development
build) to 1.0.8. It covers the breaking deployment and S3 behaviour changes.
It does not repeat the full installation guide.

Back up `config/`, the SQL database and the S3 master key before starting.
The database now stores the live service settings and object-lock/tiering
state; a database-only backup is still not a backup of Telegram media.

> **v1.0.7 predates the current config schema.** Its example config used
> `telegram:` and `upload:` sections, and parts of the runtime still accepted
> Bot transport. 1.0.8 is USER MTProto only and uses `web:`, `storage:`,
> `jobs:`, `state:` and `paths:`. Start from the shipped
> [`config.example.yaml`](../config.example.yaml) and copy your Telegram
> account/session settings into it. Do not try to reuse the old file
> unchanged.

## 1. Ports and TLS moved to environment variables

Listener ports, bind address and TLS paths are deployment plumbing now.
They are not read from `config.yaml`. The same port variable drives the
host mapping, the in-container listener and the healthcheck, so a change
cannot leave one of them stale; the bind address only selects the host side
of the Docker mapping (the service binds `0.0.0.0` inside the container).

If your `config.yaml` still has the older listener keys, remove them:

```yaml
# BEFORE — no longer read
web:
  bind_address: "0.0.0.0"
  port: 8080
  s3_port: 9000
  ssl_certfile: "/config/tls/server.crt"
  ssl_keyfile: "/config/tls/server.key"
```

Move them to `.env` (or the Compose `environment:` block):

```env
# AFTER — .env
TELEDRIVE_WEB_PORT=8080
TELEDRIVE_S3_PORT=9000
TELEDRIVE_BIND_ADDRESS=0.0.0.0

# WebUI/REST listener
TELEDRIVE_SSL_CERTFILE=/config/ssl/server.crt
TELEDRIVE_SSL_KEYFILE=/config/ssl/server.key

# S3 listener (independent pair)
TELEDRIVE_S3_SSL_CERTFILE=/config/ssl/server.crt
TELEDRIVE_S3_SSL_KEYFILE=/config/ssl/server.key

# Only when TLS terminates in front of the app:
# TELEDRIVE_TRUSTED_PROXY=1
```

Notes:

- A combined `.pem` containing the chain and private key needs only the
  `_CERTFILE` variable.
- Either listener, both or neither may serve TLS. All six combinations work.
- Certificates live under the `./config` mount, for example
  `/config/ssl/server.crt`, so no extra volume is needed.
- `deploy/tls/generate.sh` writes the material and prints the matching
  environment lines.
- The unauthenticated `/server.cer` (DER) and `/server.crt` (PEM chain)
  endpoints publish the certificate for client trust bootstrap. See
  [Reverse Proxy](REVERSE_PROXY.md#client-configuration-examples) for the
  Windows trust-store steps.

## 2. Service settings now live in SQL

On the first boot after upgrading, the service creates a single encrypted
`service_settings` row and seeds it from `config/config.yaml`. From then on
the SQL row is authoritative.

What this means in practice:

- A save from the Settings page writes both the SQL row and the mounted
  file. The file stays the bootstrap and disaster-recovery copy.
- A container rebuild that starts from an older mounted `config.yaml` will
  not roll the settings back. The SQL row wins.
- If the SQL row is missing, the service seeds it from the file. If the row
  exists but cannot be decrypted, the service falls back to the file and
  re-seeds on the next save. Startup does not fail because of a
  master-key change.
- The row is encrypted with the S3 master key because the document contains
  the WebUI password and Telegram `api_hash` values.

**A master-key change has two different consequences.** Service settings
fall back to `config.yaml` and recover on the next save. Stored S3
credential secrets do not: they were encrypted with the old key and cannot
be decrypted. Re-issue those credentials, or restore the old master key.
Keep the master key with the database backup.

Multiple workers sharing one database now read the same settings document,
so a UI save no longer needs a restart to reach the other worker.

## 3. Ownership default changed: object ACLs may stop applying

The default ownership model is `BucketOwnerEnforced`. In that mode:

- object-ACL grants are ignored for access decisions;
- bucket ACLs still constrain bucket-level access;
- the owner and the bucket policy still apply.

Before the policy/ownership work, object-ACL grants were applied. A
deployment that relied on them must opt the bucket into `ObjectWriter`:

```python
import boto3

s3 = boto3.client("s3", endpoint_url="https://s3.example.com", ...)
s3.put_bucket_ownership_controls(
    Bucket="my-bucket",
    OwnershipControls={
        "Rules": [{"ObjectOwnership": "ObjectWriter"}]
    },
)
```

`BucketOwnerPreferred` is the other option: it behaves like `ObjectWriter`
and also adds an automatic owner `FULL_CONTROL` grant when an object is
uploaded with `x-amz-acl: bucket-owner-full-control`.

A bucket policy can still short-circuit the ACL layer with an explicit
Allow, and an explicit Deny always wins. Review stored policies before
changing ownership, so a policy does not silently keep an ACL restriction
in place.

## 4. Existing S3 credentials do not gain the new permission scopes

The S3 permission catalog grew from 18 to 88 scopes. Newly created
credentials receive the full default set, but existing credentials keep
the permission list stored when they were issued. Nothing is auto-granted.

A credential that must call a new operation needs that exact scope added
on **WebUI → S3 → Credentials** (Edit) or with
`PUT /api/v1/admin/s3-credentials/{identifier}`. Read-only compatibility
probes also have their own scopes; a credential used only for normal object
reads and writes does not need them. The console groups the catalog by
resource family, filters it, and marks scopes that can destroy data or
change governance, but it never grants anything implicitly.

New scopes in 1.0.8 (70 of the 88; the other 18 existed in 1.0.7):

```text
# ACLs and ownership
s3:GetBucketAcl
s3:GetObjectAcl
s3:PutBucketAcl
s3:PutObjectAcl
s3:GetOwnershipControls
s3:PutBucketOwnershipControls
s3:DeleteBucketOwnershipControls
s3:GetBucketPolicyStatus

# Bucket policy and ABAC
s3:GetBucketPolicy
s3:PutBucketPolicy
s3:DeleteBucketPolicy
s3:GetBucketAbac
s3:PutBucketAbac

# Public access block
s3:GetBucketPublicAccessBlock
s3:PutBucketPublicAccessBlock

# Versioning and lifecycle
s3:GetBucketVersioning
s3:PutBucketVersioning
s3:GetLifecycleConfiguration
s3:PutLifecycleConfiguration

# Object lock
s3:GetBucketObjectLockConfiguration
s3:PutBucketObjectLockConfiguration
s3:GetObjectRetention
s3:PutObjectRetention
s3:GetObjectLegalHold
s3:PutObjectLegalHold

# Website, notifications and logging
s3:GetBucketWebsite
s3:PutBucketWebsite
s3:DeleteBucketWebsite
s3:GetBucketNotification
s3:PutBucketNotification
s3:GetBucketLogging
s3:PutBucketLogging

# Encryption (SSE-C only; no SSE-S3/KMS scope exists)
s3:GetBucketEncryption
s3:PutBucketEncryption
s3:DeleteBucketEncryption
s3:GetEncryptionConfiguration
s3:PutObjectEncryption

# Replication
s3:GetBucketReplication
s3:PutBucketReplication
s3:DeleteBucketReplication

# Request payment and accelerate compatibility
s3:GetBucketRequestPayment
s3:PutBucketRequestPayment
s3:GetAccelerateConfiguration
s3:PutBucketAccelerateConfiguration

# Analytics, inventory and metrics
s3:GetBucketAnalyticsConfiguration
s3:PutBucketAnalyticsConfiguration
s3:DeleteBucketAnalyticsConfiguration
s3:GetBucketInventoryConfiguration
s3:PutBucketInventoryConfiguration
s3:DeleteBucketInventoryConfiguration
s3:GetBucketMetricsConfiguration
s3:PutBucketMetricsConfiguration
s3:DeleteBucketMetricsConfiguration

# Intelligent-Tiering
s3:GetBucketIntelligentTieringConfiguration
s3:PutBucketIntelligentTieringConfiguration
s3:DeleteBucketIntelligentTieringConfiguration
s3:ListBucketIntelligentTieringConfigurations

# Bucket metadata configuration
s3:CreateBucketMetadataTableConfiguration
s3:GetBucketMetadataTableConfiguration
s3:DeleteBucketMetadataTableConfiguration
s3:UpdateBucketMetadataJournalTableConfiguration
s3:UpdateBucketMetadataInventoryTableConfiguration
s3:UpdateBucketMetadataAnnotationTableConfiguration

# Annotations
s3:GetObjectAnnotation
s3:PutObjectAnnotation
s3:DeleteObjectAnnotation
s3:ListObjectAnnotations

# Data-plane additions
s3:RenameObject
s3:SelectObjectContent
s3:RestoreObject
```

## 5. Object lock and tiering change behaviour

### Object lock is one-way

Enabling Object Lock on a bucket is permanent. AWS semantics apply: the
bucket cannot return to an unlocked state, and the default retention can
only be extended, never shortened.

Before enabling it:

- Decide the retention mode and days for every new version. The default is
  applied at publish time, not retroactively to existing versions.
- `COMPLIANCE` retention is extend-only and cannot be cleared while active.
- Retained and held versions refuse explicit and batch version deletes.
  The GC collector and lifecycle expiration will not touch them.
- The `x-amz-bypass-governance-retention` header is rejected `501`; there is
  no governance-elevation model.
- Test on a disposable bucket first. There is no disable switch to undo a
  mistaken default.

### Intelligent-Tiering is an access gate, not Glacier

Enabling a tiering configuration starts real access counting and lets the
scheduler move `storage_class` from idle time. An archived object then
answers `403 InvalidObjectState` to GET, HEAD and ranged reads until
`RestoreObject` opens a bounded restore window.

- No Telegram chunk is moved, compressed or deleted. There is no cold
  backend, no Glacier durability and no retrieval pricing.
- A client that does not handle `InvalidObjectState` will treat an archived
  object as broken. Restore it first, or keep tiering disabled.
- Deleting the tiering configuration stops future transitions. Objects
  already transitioned keep their class; that configuration will no longer
  re-evaluate them, so the gate can remain until a new configuration
  matches the bucket.
- Reads now perform an access-counter update. This is intentional and is
  required for the scheduler to be honest.

## 6. Test tooling moved out of the runtime requirements

Test dependencies are now in `requirements-dev.txt`, not
`requirements.txt`. The runtime image no longer installs pytest, xdist,
boto3, bandit or pip-audit.

For local work:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt

# Fast run: one test FILE per worker, which is what the tmp databases expect
python -m pytest -q -n auto

# Serial run, for isolating a failure
python -m pytest -q
```

The suite is parallel-safe after the deterministic-parametrise fixes. If a
machine has no xdist, the serial command still works.

## 7. Post-upgrade checks

1. `docker compose ps` reports the container healthy. The healthcheck uses
   the same port and TLS variables as the listeners.
2. Log in and confirm the settings you expect are shown. A UI save should
   survive a container rebuild.
3. `boto3` PUT/GET a small object, then a ranged GET with checksum mode
   enabled.
4. Open **S3 → Credentials** and confirm any credential used for policy,
   ownership, object-lock, website, notification, replication, SSE-C,
   metadata-configuration, reporting or tiering has the required scopes.
   The console groups them by family; a scope that existed before this
   release is not re-granted automatically.
5. Confirm physical GC is still off unless you deliberately enabled it and
   completed the owner gates. Upgrading does not turn it on.
