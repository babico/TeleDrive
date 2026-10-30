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

## 7. Security-surface changes that break existing behaviour

Six decisions tightened what an authenticated caller may do. Each one is
deliberate: the previous behaviour was reproducible as a takeover, a data
exposure or a silent data loss, and every one of them has a regression test.

### 7.1 HTTP Basic and the config password are gone

There is no authenticated identity other than the login-form session (cookie
or `td_sess_` bearer) and an API key. `web.user`, `web.password`,
`web.password_file` and `web.allow_insecure` are not settings any more; they
are stripped from an existing config file or SQL document when it is read.

First boot creates `admin` / `admin` in code, unconditionally and only when
no `admin` row exists — an existing row is never overwritten, and the account
cannot be renamed. **Change that password immediately on any instance that is
reachable from outside the host.**

If your only credential was the config password, you are locked out until you
run `scripts/ops/reset_local_password.py`, or delete the `admin` row and
restart.

### 7.2 S3 credentials are an interactive-session surface

`POST`/`PUT`/`DELETE` on `/api/v1/admin/s3-credentials` and the `…/secret`
reveal now answer **403** to an API key. A credential is itself a secret, so
letting a key mint, edit or read one bypassed the delegation ceiling: a key
scoped to only that route could create a credential holding every permission
and receive its secret. A human session is interactive, CSRF-fenced and
revocable, which is why it is the only principal allowed here.

Also:
- Creating a credential **without** a `permissions` list now grants a
  READ-ONLY set (list, location, get, attributes). It used to grant every
  known permission.
- `PUT` enforces the same expiry bounds as `POST` and refuses to edit an
  expired credential (editing one back to life was real access, because
  expiry is checked at signature time).
- The identifier may be the id **or** the access key, on every operation.

### 7.3 Presigned URLs and config writes are interactive-session only

A presigned URL is durable anonymous authority: it keeps working for up to
seven days after your session or API key is revoked. Delegating that from an
API key would let a key plant access that outlives its own revocation. Same
reasoning for `PUT /api/v1/config`, which can change allowed hosts,
filesystem roots and the job watcher.

### 7.4 Share links pin the object version they were issued for

`share_links` gained `object_id` (schema step 24). A new link serves exactly
the version that existed when it was created: overwriting the key no longer
changes what the URL returns, and an unlink followed by a re-upload does not
revive it. A link that can no longer resolve its pinned version answers the
same uniform 404 as an expired one.

A failed request — a 404, a link-preview fetch, a broken transfer — no longer
consumes a download slot. Only a request that actually streams counts.

Links created before this release have `object_id = NULL` and stay key-bound;
re-issue them if you need the pinning guarantee.

### 7.5 The audit trail is admin-only, and it is now durable

`GET /api/logs` and the live log websocket are admin-only: the buffer carries
object keys, request paths and failure detail, which is how a share token
became readable by a read-only account.

Security events are also recorded in a `security_audit_events` table (schema
step 25) and exposed at `GET /api/v1/admin/audit`. That covers credential
issue/edit/revoke/reveal, API-key issue/rotate, config writes, user
create/update/delete, physical GC start/finish, presign and share creation —
with the actor, target and a scrubbed detail blob. The table is append-only
and the module refuses to store anything shaped like a credential.

### 7.6 Envelope encryption (SSE-S3) is available, and opt-in

`storage.encryption: envelope` makes encrypted-at-rest a **server** property:
one fresh AES-256-GCM data key per object, wrapped by a KEK derived from the
S3 master key you already need, with only the wrapped form persisted. Clients
send plaintext and never manage keys, which is the S3 SSE-S3 shape.

Enable it, then either set a bucket default or ask per request:

```
# config.yaml
storage:
  encryption: envelope
```

```
aws s3api put-bucket-encryption --bucket backups \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

What it costs, stated by the software rather than left to discover:

* **no deduplication** for encrypted objects (identical plaintext must not
  share ciphertext, and a dedup hit would leak equality),
* **no replication** for encrypted objects,
* **no content indexing** for encrypted objects (the index is plaintext).

`envelope.capabilities()` reports exactly those three, and the UI shows them.
Turning it on is not retroactive: existing objects keep their current form.

`aws:kms` stays `501` in both modes — there is no AWS KMS here — and asking
for `AES256` while the setting is `none` is also `501` naming the setting,
because silently storing plaintext after an encryption request is the worst
possible answer. SSE-C is unchanged and always available.

### 7.7 A two-person deletion approval is no longer required

The physical-GC gate list was: independent backup, restore drill, writer
barrier and a two-person deletion approval. **The last one is removed by
owner decision.** The other three still gate `deletion_permitted`, which
remains `False`, and `scripts/ops/verify_production_bundle.py` still verifies
the technical evidence and any signature that is supplied — an optional
attestation must not become an unverified one.

### 7.8 S3 operations that now refuse instead of pretending

- `PUT ?retention` / `?legal-hold` with a streaming payload must carry a
  verifiable `x-amz-checksum-sha256`; otherwise the body is unbound to the
  signature and the change is refused.
- A `Range` header longer than 20 digits is `416`, not `500`.
- A REST read of an archived object is `403 InvalidObjectState`, and of an
  SSE-C object is `400` naming SSE-C — including on the public website and
  the WebUI download button, which previously returned `200` with zero bytes.
- An unlink of an object under legal hold or retention is `403`.

## 8. Post-upgrade checks

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
