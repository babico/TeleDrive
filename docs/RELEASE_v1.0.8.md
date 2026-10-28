# TeleDrive 1.0.8

TeleDrive 1.0.8 expands the S3-compatible surface substantially. It turns
most of the previously "read-compatible but write-rejected" S3 surface into
real SQL-backed state:
bucket policies, ACLs, ownership, Public Access Block, object lock,
notifications, replication, website hosting, CORS, tagging, lifecycle
expiration, reports and intelligent-tiering. It also moves ports and TLS to
the environment, persists service settings in SQL, and closes the critical
findings from the codebase audit.

The release candidate is prepared from this tree. The published binaries
remain v1.0.7 until the mandatory checks pass on the exact release SHA; do
not treat this file as a tag.

## Upgrade

Read [Upgrading to 1.0.8](UPGRADING.md) before replacing a running
deployment. Four changes can break an existing setup:

- ports, bind address and TLS paths are read **only** from environment
  variables now, never from `config.yaml`;
- service settings live in SQL after the first boot, with `config.yaml` as
  the bootstrap and recovery copy;
- the default object-ownership model is `BucketOwnerEnforced`, which
  **ignores object-ACL grants** — a deployment that relied on them must
  switch the bucket to `ObjectWriter`;
- the S3 permission catalog grew from 18 to 78 scopes, and existing
  credentials are **not** auto-granted the new ones.

Object lock is a one-way bucket setting, and intelligent-tiering makes an
archived object answer `403 InvalidObjectState`. Both stay off unless
configured, but object lock cannot be undone and an archived object keeps
its read gate until a restore window or a new tiering pass changes it.

## S3 coverage, stated honestly

The authoritative inventory is [S3_SPECS.md](S3_SPECS.md). Its totals line
and the machine-readable manifest agree on **116 operations**:

| Status | Count | Meaning |
| --- | ---: | --- |
| Supported | **110** | Implemented for the documented TeleDrive contract and backed by focused regression tests. Not a claim of complete AWS parity. |
| Partial — by design | **2** | `GetBucketRequestPayment` and `GetBucketAccelerateConfiguration`. Both report the single state that exists here (BucketOwner / Suspended) and their write side rejects the state that would need requester-pays billing or an edge network. |
| Unsupported | **4** | Permanently impossible; listed below. Nothing is pending. |

There are **zero partial operations "by code"**: every remaining partial is
a deliberate architectural decision, fail-closed on purpose.

The four permanently impossible operations are not refused out of caution;
they have no honest backing here:

| Operation | Why it cannot be supported |
| --- | --- |
| `GetObjectTorrent` | Needs a BitTorrent swarm and a seeder. Producing a `.torrent` file we cannot seed would mislead the caller. |
| `CreateSession` | Issues an S3 Express One Zone session token. TeleDrive has no directory buckets. |
| `ListDirectoryBuckets` | Directory buckets are an AWS storage class with zone-local infrastructure that does not exist over Telegram. |
| `WriteGetObjectResponse` | S3 Object Lambda. There is no Lambda execution environment to run the transformation. |

No operation is left as ordinary pending work: the nine bucket-metadata
configuration operations (backed by a real mutation journal), `PutBucketEncryption`,
`DeleteBucketEncryption` and `UpdateObjectEncryption` (SSE-C) all shipped in this
release. SSE is supported **only** as SSE-C, where the client supplies the
AES-256 key on every request and we never persist or log it; a bucket-level
default `AES256` (SSE-S3) or `aws:kms` rule is rejected 501, because TeleDrive
holds no server-side key for data the client did not encrypt.
