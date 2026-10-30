# TeleDrive 1.0.8

TeleDrive 1.0.8 expands the S3-compatible surface substantially. It turns
most of the previously "read-compatible but write-rejected" S3 surface into
real SQL-backed state:
bucket policies, ACLs, ownership, Public Access Block, object lock,
notifications, replication, website hosting, CORS, tagging, lifecycle
expiration, reports and intelligent-tiering. SSE-C joins the encryption
surface, the metadata journal backs the nine bucket-metadata configuration
operations, and the S3 governance and credentials pages make the resulting
state operable without an S3 client. It also moves ports and TLS to the
environment, persists service settings in SQL, and closes the critical
findings from the codebase audit.

**v1.0.8 is tagged at the commit that carries this file.** The tag exists
only after all six mandatory workflows are green on that exact SHA; the
checks are per-SHA, not per-branch, so a green commit elsewhere is not
evidence for this one. Later `main` commits are not part of the release.

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
- the S3 permission catalog grew from 18 to 88 scopes, and existing
  credentials are **not** auto-granted the new ones. The credential
  console groups and filters them and labels the destructive and
  governance-changing ones.

S3 credentials are issued on `/s3/credentials` now, not on API
Management, and the S3 nav group reads Credentials · Buckets ·
Governance on every page. That console groups all 88 scopes into 20
resource families, offers five presets whose consequence is stated, marks
scopes that can destroy data or change governance, and supports create,
edit, rotate, revoke and reveal. Rotation is issue-new-then-revoke-old in
one confirmed step, because an access key and its secret are immutable by
design. A secret is shown once, is held only in the browser tab that
received it, and is never written to local or session storage or placed in
a URL.

Object lock is a one-way bucket setting, and intelligent-tiering makes an
archived object answer `403 InvalidObjectState`. Both stay off unless
configured, but object lock cannot be undone and an archived object keeps
its read gate until a restore window or a new tiering pass changes it.

## S3 coverage, stated honestly

The authoritative inventory is [S3_SPECS.md](S3_SPECS.md). Its totals line
and the machine-readable manifest agree on **116 operations**:

| Status | Count | Meaning |
| --- | ---: | --- |
| Supported | **114** | Implemented for the documented TeleDrive contract and backed by focused regression tests. Not a claim of complete AWS parity. |
| Partial | **0** | None — by code or by design. |
| Unsupported | **2** | Permanently impossible; listed below. Nothing is pending. |

There are **zero partial operations of any kind**. The last two were not
design decisions at all: `GetBucketAccelerateConfiguration` emitted
`<TransferAcceleratedStatus>`, the internal enum name, while botocore's
`AccelerateConfiguration` shape has exactly one member, `Status` — so boto3
parsed our document into an empty dict and the SDK never saw the state.
`GetBucketRequestPayment` was already correct and is now proven with a real
boto3 client rather than assumed.

Two operations previously listed here as impossible were re-examined and are
honest at a lower bar than full AWS parity:

| Operation | What it now does |
| --- | --- |
| `ListDirectoryBuckets` | A deployment with zero directory buckets has a real AWS answer: `200` with an empty `ListDirectoryBucketsResult` — no `Buckets`, no `ContinuationToken`. `continuation-token` and `max-directory-buckets` are validated; unknown parameters are 400. |
| `CreateSession` | Refuses truthfully instead of a blanket 501: a malformed name is `400 InvalidBucketName`, an existing general-purpose bucket is `400 InvalidRequest` naming the required directory-bucket class, and any other well-formed name is the AWS-declared `404 NoSuchBucket`. No session can ever be issued, because there are no S3 Express directory buckets. |

Both accept the real `s3express` SigV4 service scope that botocore uses to
sign those two calls; verification previously hard-coded `/s3/`, so genuine
SDK calls failed with `AccessDenied`.

The two permanently impossible operations are not refused out of caution;
they have no honest backing here:

| Operation | Why it cannot be supported |
| --- | --- |
| `GetObjectTorrent` | Needs a BitTorrent swarm and a seeder. Producing a `.torrent` file we cannot seed would mislead the caller. |
| `WriteGetObjectResponse` | S3 Object Lambda. There is no Lambda execution environment to run the transformation. The rejection names that absence rather than saying "NotImplemented". |

No operation is left as ordinary pending work: the nine bucket-metadata
configuration operations (backed by a real mutation journal), `PutBucketEncryption`,
`DeleteBucketEncryption` and `UpdateObjectEncryption` (SSE-C) all shipped in this
release. SSE is supported **only** as SSE-C, where the client supplies the
AES-256 key on every request and we never persist or log it; a bucket-level
default `AES256` (SSE-S3) or `aws:kms` rule is rejected 501, because TeleDrive
holds no server-side key for data the client did not encrypt.

## Security review before the tag

The tag was deliberately held while an exhaustive per-endpoint review ran.
Seven waves covered 25 endpoints — the whole authority surface, not the whole
route list — and found **64 real defects**, all fixed before release. The
full ledger, including the one finding that was disproved with evidence, is
[API_REVIEW.md](API_REVIEW.md).

The ones that would have shipped as vulnerabilities:

| Class | What it was |
| --- | --- |
| Takeover | A config save could redirect `state.database_url`; the bootstrap then created `admin`/`admin` in the new database. |
| Takeover | `GET /api/v1/config` returned the live Telethon `session_string` to a read-only viewer. |
| Takeover | Deleting a user left their session behind; SQLite reuses integer ids, so a later account inherited it (proved: a deleted viewer authenticating as a new admin). |
| Takeover | An API key scoped to one route could mint an S3 credential holding all 90 permissions and receive its secret. |
| Authorization | `admin:*` expanded to nine REST names, so the "full access" preset was rejected on every admin route. |
| Authorization | A `Deny` on `s3:prefix` answered 403 for `?prefix=a` and 200 for a bare listing, which enumerated the bucket. |
| Denial of service | A bucket-policy glob compiled `*` to `.*`: over five seconds of CPU per request, single-threaded, from a policy-writing credential. Now 0.4 ms. |
| Data loss | Physical GC's default scope deleted Telegram media and then rolled its own record back, leaving SQL saying `ready`. |
| Data loss | GC deleted only primary messages and dropped the replica rows: a full second copy of a "deleted" object stayed on another account forever. |
| Immutability | A suspended bucket removed a COMPLIANCE-retained head with no lock check; multipart completion and copy skipped the default retention entirely. |
| Exposure | Every public share token was readable by a viewer and written to the log stream; the link also re-targeted replaced bytes. |
| Exposure | Bucket delete left thirteen governance tables behind, so re-creating a name revived the old policy (including a Deny) and its public share links. |

Operator-visible consequences and migrations are in
[UPGRADING.md](UPGRADING.md) §7.
