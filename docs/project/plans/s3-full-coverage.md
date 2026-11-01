# TeleDrive — Full S3 Operation Coverage Plan

> **THIS PLAN IS COMPLETE — kept as a design record, not open work.**
>
> **Final state: 114 supported / 0 partial / 2 unsupported — 116 operations.**
> The 110/2/4 line below is the state at the time the plan was written (it was
> correct then). Two things changed afterwards:
>
> 1. The two remaining "partial"s were not a design decision but a **bug**:
>    `GetBucketAccelerateConfiguration` was writing `<TransferAcceleratedStatus>`
>    (an internal enum name), while botocore's schema has the single member
>    `Status` — so boto3 parsed the document as an empty dict.
>    `GetBucketRequestPayment` was already correct and is now proven with a real
>    boto3 client.
> 2. Two operations deemed "impossible" were possible at an honest lower level:
>    `ListDirectoryBuckets` (the real AWS answer when there is no directory
>    bucket: empty 200) and `CreateSession` (honest refusal by name class:
>    400/404).
>
> `GetObjectTorrent` (no seeder) and `WriteGetObjectResponse` (no Lambda
> runtime) remain permanently unsupported. The authoritative inventory is
> [S3_SPECS](../../reference/s3-specs.md) and `teledrive/s3/operation_manifest.json`.

**State (when the plan was written):** 110 supported / 2 partial (0 by code) / 4 unsupported — 116 operations.
**Target:** 112 supported / 0 partial / 4 unsupported (96.5%) — in practice the
honest final state reached was **110 supported / 2 partial / 4 unsupported**;
`GetBucketRequestPayment` and `GetBucketAccelerateConfiguration` remain partial
by design (no billing/edge), so the target of 112 is only meaningful if those
two read probes are also counted as "supported".
**Rule:** behind every operation there will be REAL state or REAL work.
"Accept and swallow" is forbidden; what cannot be done is refused honestly.

This document defines a concrete, honest implementation path for each of the 56
remaining operations. Ordering follows the (value / effort) ratio; each phase is
independently shippable and carries its own CI verification.

---

## State (2026-10-28)

| Phase | Scope | Op | State |
|---|---|---|---|
| Start | — | — | 60 supported / 8 partial / 48 unsupported |
| **L** | Policy engine, ownership, ABAC, PAB delete | 8 | ✅ `4831a67` |
| **N1–N3** | Analytics/inventory/metrics config + real report generation | 12 | ✅ `4831a67` |
| **O** | RenameObject, SelectObjectContent, RestoreObject, annotations, RequestPayment/Accelerate writes | 9 | ✅ `4831a67` + `2e461d1` (real AWS wire shapes) |
| **Subtotal** | | **29** | **89 supported / 7 partial / 20 unsupported** |
| **N5 + O1** | Access counter, intelligent tiering, RestoreObject's real archive path | 6 | ✅ `f341691`, `<Tiering>` fix `45d40ff` |
| **O3** | Bucket metadata journal (real mutation journal) | 9 | ✅ `fea11d9`, actor semantics `b850ad1` |
| **M1** | SSE-C (client-supplied key, AES-256-GCM/chunk) | 8 | ✅ `565796b` |
| **Result** | | **23** | **110 supported / 2 partial / 4 unsupported** |
| **D — impossible** | Torrent, CreateSession, ListDirectoryBuckets, WriteGetObjectResponse | 4 | ⛔ permanently unsupported |

> **The two remaining partials:** `GetBucketRequestPayment` and
> `GetBucketAccelerateConfiguration`. Both return their single real state
> (BucketOwner / Suspended); because the opposite state requires requester-pays
> billing or an edge network, the write side answers 501. Counting them as
> "supported" would make a billing/edge infrastructure that does not exist look
> as if it did.

> **Why we do not say we "support" these 4:** `GetObjectTorrent` requires a
> BitTorrent swarm/seeder (generating a .torrent without being able to seed it
> misleads the user), `CreateSession`/`ListDirectoryBuckets` depend on S3 Express
> One Zone directory buckets (there is no such storage),
> `WriteGetObjectResponse` is S3 Object Lambda (there is no Lambda execution
> environment). If any of the four were faked without real backing, the
> "supported" label would be a lie. TeleDrive's usage profile (self-host
> backup) never generates these calls.

## 0. Classification

| Class | Meaning | Count |
|---|---|---|
| **A — Real backing exists** | Real semantics can be built on the existing SQL/engine | 44 |
| **B — Only existing state** | One real value is accepted, the other is honestly 501 | 4 |
| **C — Only unblocked by SSE** | Partials close once encryption arrives | 4 |
| **D — Impossible** | No infrastructure; faking it would be a lie | 4 |

---

## 1. PHASE L — Policy engine (highest value)

**Closes:** `PutBucketPolicy`, `DeleteBucketPolicy`, `GetBucketPolicy` (partial),
`GetBucketAbac`, `PutBucketAbac`, `PutBucketOwnershipControls`,
`DeleteBucketOwnershipControls`, `DeletePublicAccessBlock` → **8 operations**

### L1 — `teledrive/s3/policy.py` (new)

A real IAM-style JSON policy engine. Today we refuse with "no policy engine";
in fact we already have everything needed: credentials (principal), ACL grants
(resource), and a single permission gate (`_acl_allows`).

Supported document:

```json
{"Version": "2012-10-17",
 "Statement": [
   {"Sid": "deny-delete", "Effect": "Deny",
    "Principal": {"CanonicalUser": ["TDB67BD1ABE1D21E7768F0A23"]},
    "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
    "Resource": ["arn:aws:s3:::photos/*"],
    "Condition": {"StringLike": {"s3:prefix": ["private/*"]}}}
 ]}
```

**Strict rules (fail-closed):**
- `Principal`: only a `CanonicalUser` list; every ID must be an active access key.
  `"*"`, `AWS`, `Service`, `Federated` → **501** (the private-only line).
- `Action`: `s3:*` glob (`*` and `?`); unknown action name → 400.
- `Resource`: `arn:aws:s3:::bucket` and `bucket/key` glob; any other partition → 400.
- `Effect`: `Allow` | `Deny`. **Deny always wins.**
- `Condition`: only operators we can actually evaluate:
  `StringEquals`, `StringLike`, `StringNotEquals`, `IpAddress`, `NotIpAddress`,
  `Bool`, `NumericLessThan/Equals/GreaterThan`. Keys:
  `s3:prefix`, `s3:max-keys`, `s3:delimiter`, `aws:SourceIp`,
  `s3:ExistingObjectTag/<key>`, `aws:PrincipalTag/<key>`, `s3:x-amz-acl`.
  Unknown operator/key → **400** (silently ignoring them widens authority).
- Document size ≤ 20 KiB (same as AWS), statement ≤ 50, bounded depth.

### L2 — Single decision point

`web/s3.py::_authorize_resource(catalog, access_key, action, bucket, key)`:

```
1. credential scope check (SigV4 — already exists)
2. bucket policy: explicit Deny?      → reject
3. bucket policy: explicit Allow?     → skip the ACL layer (AWS semantics)
4. no evidence: ACL intersection gate (Phase D) → current behaviour
```

This replaces the existing `_acl_allows`; ACL and policy merge into the same
function. One decision point = one place to test.

### L3 — Evaluation cost

The policy is not parsed on every request: a compiled AST per bucket + LRU cache,
invalidated by `updated_at`. The 20 KiB limit + 50 statements keeps the upper
bound fixed.

### L4 — ABAC

`GetBucketAbac`/`PutBucketAbac` sit on top of this engine: ABAC is simply
requiring `aws:PrincipalTag/*` and `s3:ExistingObjectTag/*` conditions at the
bucket level. Credential tags are added to the `api_credentials` and
`s3_credentials` tables as a `tags` JSON column.

### L5 — Ownership controls (now real)

| Value | Real semantics |
|---|---|
| `BucketOwnerEnforced` (default) | Object ACLs are **ignored** in access decisions; only owner + policy |
| `ObjectWriter` | Object ACL grants **are applied** (today's Phase D behaviour) |
| `BucketOwnerPreferred` | ObjectWriter + automatic owner grant on objects uploaded with the `bucket-owner-full-control` canned ACL |

`Delete` → reverts to `BucketOwnerEnforced`. No longer a constant but a real
setting that changes behaviour.

### L6 — DeletePublicAccessBlock

Deletes the PAB row → reverts to the all-true default (most restrictive). The
risk of loss is zero. The only caveat: if `BlockPublicAcls` is off and the policy
has no public principal (which it cannot, 501), the result is still safe.

**Effort:** L (1 week). **Tests:** new `tests/s3/test_s3_policy_engine.py` +
`tests/s3/test_s3_abac.py`, ~40 scenarios (deny-overrides, glob, condition,
principal validation, cache invalidation, together with ACL).

---

## 2. PHASE M — Encryption (SSE)

**Closes:** `PutBucketEncryption`, `DeleteBucketEncryption`, `GetBucketEncryption`
(partial), `UpdateObjectEncryption`, `PutObject`, `GetObject`, `HeadObject`,
`CreateMultipartUpload` (partials) → **8 operations**

### M1 — SSE-C (real, priority)

The client supplies the key on every request; we do not store it. Chunks are
encrypted with AES-256-GCM, nonce random per chunk, AAD = object_id + ordinal.

- Headers: `x-amz-server-side-encryption-customer-{algorithm,key,key-md5}`
- Wrong key → `InvalidRequest` (with GCM tag verification, no oracle)
- **Dedup closes naturally** (same plaintext, different ciphertext) — the same as
  on AWS. Content search closes for those objects (documented).
- `UpdateObjectEncryption` = decrypt with the old key, encrypt with the new one
  (real rotation, single transaction + chunk re-upload).

### M2 — SSE-S3 (real, optional mode)

`storage.encryption = none | envelope`. With envelope on:
- Master key (`/config/s3.key`) → per-object data key wrap (AES-KW)
- Chunks encrypted with the data key, checksum over the ciphertext
- **Dedup / replication / content-search turn themselves off** and report that
  via `/api/v1/admin/storage/health`. This is not a regression but a deliberate
  trade-off: the owner chooses which two they want.
- `GetBucketEncryption` returns the real config.

### M3 — SSE-KMS

There is no KMS. `x-amz-server-side-encryption: aws:kms` → **501** (honest).
`AES256` → SSE-S3. `aws:kms` + key-id → 501 "no KMS backing".
A KMS rule in the bucket config → 501.

**Effort:** L (1 week, M1) + M (3 days, M2). **Tests:** `tests/s3/test_s3_sse_c.py`,
`test_s3_envelope.py`; also AES-GCM vectors, wrong-key rejection, rotation,
range read (per-chunk decryption), multipart.

---

## 3. PHASE N — Reporting configurations (16 operations, mostly CRUD + real generation)

AWS's "configuration" family: all of them are **config CRUD + scheduled output**.
Config CRUD is done with a single generic layer; output generation is real thanks
to the existing storage engine + Phase F outbox.

### N1 — Generic config store

`teledrive/s3/report_configs.py`: a single table `storage_report_configs`
(`bucket`, `kind` ∈ {analytics, inventory, metrics, tiering}, `config_id`,
`document` JSON, `created/updated`). Strict XML parse, one record per id,
`List*` returns ordered. **12 operations** come from here.

### N2 — Inventory (real CSV manifest)

`GetBucketInventoryConfiguration` etc. → a **real CSV manifest** is written to the
config's `Destination` bucket (AWS inventory CSV schema: Bucket, Key,
VersionId, IsLatest, Size, LastModifiedDate, ETag, StorageClass).
Daily/weekly scheduler (next to `lifecycle_scheduler_loop`).
`IncludedObjectVersions=All` is genuinely supported (we have a version journal).
ORC/Parquet → 501 (CSV + gzip is what is real).

### N3 — Analytics (real report, format deviation documented)

Same skeleton; output is JSON Lines (AWS uses Parquet). The deviation is stated
explicitly in `docs/S3_SPECS.md`. Filter (prefix/tag) is really applied.

### N4 — Metrics (no CloudWatch → its own real channel)

We cannot send to CloudWatch. Real backing: metrics are **actually computed**
under `/api/v1/admin/storage/metrics/{config_id}` (bucket size, object count,
request counter — the request counter comes from the HTTP middleware) and, if
requested, pushed to a destination via the Phase F webhook outbox. The
`Destination` field defines that channel. Documented: "not CloudWatch".

### N5 — Intelligent-Tiering (real access tracking)

Today there is no access counter — this phase adds it:
- `storage_objects.access_count`, `last_accessed_ns` (defensive ALTER)
- Atomic increment on every GetObject/HeadObject (single UPDATE, indexed)
- Based on the `Days`/`AccessTier` thresholds in the config, an object
  **actually** receives a `storage_class` label (`STANDARD` → `INFREQUENT_ACCESS` → `ARCHIVE`)
- The `ARCHIVE` label enters the lifecycle: chunks are kept on the replica, the
  primary is dropped from Telegram by GC → **RestoreObject now does real work** (below)

**Effort:** N1 2 days, N2/N3 3 days, N4 2 days, N5 4 days. **Tests:** CRUD +
generation tests for each kind, scheduler idempotency, access-counter race test.

---

## 4. PHASE O — Easy real wins

### O1 — RestoreObject (real, depends on N5)

Once the `ARCHIVE` class is real with N5:
- `ARCHIVE` object → `403 InvalidObjectState` (same as AWS)
- `ARCHIVE` + `RestoreObject` → chunks are brought back from the replica,
  `restore_until_ns` is set, `202 Accepted`; when the period expires it returns
  to archive
- Without N5: always `403 InvalidObjectState` — **still 100% AWS-conformant**
  (the object is already in an accessible class). So this operation behaves
  correctly independently of N5 too.

### O2 — Object annotations (4 op)

`storage_object_annotations` (`object_id`, `name`, `value`). Difference from a
tag: the name is free text, 50 entries, 1 KiB value. `ListObjectAnnotations` with
pagination. **Effort:** S (half a day).

### O3 — Bucket metadata configuration (9 op)

A real metadata journal: `storage_metadata_journal` (object mutations: create/
delete/tag/ACL change, time, actor). Config CRUD + `Get` paginate this journal.
AWS's "metadata table" (AWS-managed Iceberg) is not imitated; our table is real
and queryable. **Effort:** M (2 days).

### O4 — RenameObject (real atomic rename)

Because our catalog can move a head in a single transaction, rename is
`copy + delete` in a single transaction (chunks do not move, only key_hash).
AWS offers this only on directory buckets; we offer it on a standard bucket and
mark it as a **documented superset**. **Effort:** S (1 day).

### O5 — SelectObjectContent (real query)

Download chunks → CSV/JSON parse → S3 Select SQL subset
(`SELECT`/`FROM`/`WHERE`/`LIMIT`, comparison + `AND`/`OR`) → event stream
(`Records`, `Stats`, `End`). Bounded: ≤ 256 MiB scanned, ≤ 1 MiB/event.
Parquet → 501. **Effort:** M (3 days).

### O6 — RequestPayment / Accelerate (class B)

| Op | Real state | Accept | Refuse |
|---|---|---|---|
| `PutBucketRequestPayment` | `Payer=BucketOwner` (no billing) | `BucketOwner` | `Requester` → 501 |
| `PutBucketAccelerateConfiguration` | `Status=Suspended` (no edge) | `Suspended` | `Enabled` → 501 |

This way the operation becomes "supported" because it **correctly manages the
single state that exists**; it does not accept something that does not exist.
**Effort:** S (2 hours).

---

## 5. Permanently impossible (4)

| Operation | Why |
|---|---|
| `GetObjectTorrent` | No BitTorrent swarm/seeder infrastructure; producing a .torrent file without being able to seed it would be a lie |
| `CreateSession` | S3 Express One Zone session token; there is no directory bucket |
| `ListDirectoryBuckets` | There is no such thing as a directory bucket |
| `WriteGetObjectResponse` | S3 Object Lambda; there is no Lambda execution environment |

These remain `unsupported` and are listed in `docs/S3_SPECS.md` 3.3 with the
reason "no honest backing". **None of the four is a real customer need** —
TeleDrive's usage profile (personal/self-host backup) never calls them.

---

## 6. Ordering and dependencies

> This section is a planning record; all phases shipped with `f341691`, `fea11d9`
> and `565796b`. The current inventory is 110 supported / 2 partial /
> 4 unsupported.

```
PHASE L (policy + ownership + PAB)    8 op   ~6 days   independent
PHASE O2/O6 (annotations, R/P, accel) 8 op   ~2 days   independent
PHASE M (SSE-C → SSE-S3)              8 op   ~8 days   independent
PHASE N1+N2+N3 (config + reports)    12 op   ~5 days   independent
PHASE N5 (access tracking + tiering)  4 op   ~4 days   after N1
PHASE O1 (RestoreObject)              1 op   ~1 day    after N5 (correct even without)
PHASE O3 (metadata journal)           9 op   ~2 days   independent
PHASE O4/O5 (rename, select)          2 op   ~4 days   independent
PHASE N4 (metrics channel)            4 op   ~2 days   after N1
```

Total ~34 days for a single developer; ~12 calendar days with 3 parallel agents.

**Recommended order (value/effort):** O2+O6 (1 day, 6 op) → L (6 days, 8 op) →
N1+N2+N3 (5 days, 12 op) → M (8 days, 8 op) → O3 (2 days, 8 op) → N5+O1 (5 days, 5 op)
→ O4+O5+N4 (8 days, 6 op).

---

## 7. Mandatory ritual for every phase

1. New table → `MetaData` + defensive ALTER (SQLite `PRAGMA` / `information_schema`
   **schema-filtered**), `create_all` in `BucketCatalog.__init__` or the store ctor
   (**never** on the mutation hot path — SQLite deadlocked in Phase J).
2. Config CRUD → strict, bounded (16–20 KiB) defused XML; unknown field 400,
   unsupported semantics 501.
3. Permission: add `s3:Put*/Delete*` to `teledrive/s3/credentials.py`.
4. Route guard: method matrix in `teledrive/s3/route_guard.py`.
5. Adversarial tests: `tests/s3/test_s3_route_guard.py` (does not fall through to CRUD),
   `test_s3_compat_reads.py`, `test_s3_unsupported_sweep.py`.
6. Inventory sync: manifest → `S3_SPECS.md` 3.1/3.3 → totals row →
   route_guard Counter → meta totals → register the new test module in CI.
7. Live verification: PostgreSQL + MySQL (clean AND legacy schema) + boto3 round-trip
   + TLS.
8. At the end of every phase CI 6/6 green, then deploy.

---

## 8. Honesty contract (invariant)

Throughout this plan the following three things are **never** done:

1. **Fake acceptance.** Passing off an unsupported AWS feature with a 200
   (e.g. silently downgrading SSE-KMS to AES256) is forbidden; it returns 501.
2. **Silent permission widening.** Unknown policy condition, unknown ACL
   grantee, missing required field → reject. The default is always "do not allow".
3. **Fake report.** Counting a report that was not generated as "delivered" is
   forbidden; generation really happens or the operation stays 501.

Thanks to this contract the "supported" label means "tested and actually working"
— not a claim of S3 compliance but a claim of **measured behaviour**.
