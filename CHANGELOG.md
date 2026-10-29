# Changelog

All notable changes to TeleDrive are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries describe the behaviour change and why it mattered. A version is
listed only after its commits exist; a release tag is cut separately after
the mandatory checks pass on the exact SHA.

## [Unreleased]

Nothing yet.

## [1.0.8] - 2026-10-28

Release candidate. The S3 coverage counts below and in
[docs/S3_SPECS.md](docs/S3_SPECS.md) describe this tree, not the published
v1.0.7 binaries.

### Added

**S3 metadata parity, phases A–J**

- **GC-integrated deletes and lifecycle expiration (phase A).** Version
  deletes, per-entry batch deletes, aborts and due lifecycle rules now
  enqueue media for grace-fenced collection when physical GC is enabled.
  Before this, a delete did not queue the media itself: reclaiming it
  depended on a manual collect over a broader scope, and lifecycle
  expiration had no path to media at all. With GC disabled the old
  journal-retention behaviour is unchanged, so a deployment that leaves GC
  off keeps its recovery copy after upgrading.
- **Real versioning states (phase B).** `PutBucketVersioning` accepts
  Enabled and Suspended. A suspended bucket replaces the current version on
  write and deletes the head without a marker, matching unversioned client
  expectations. Earlier builds accepted only Enabled, so clients that
  suspended versioning were given a state the store did not honour.
- **Object lock with WORM semantics (phase C).** Bucket-level lock can be
  enabled once and never disabled; default retention is applied to every new
  version at publish. Retention and legal hold are enforced on explicit
  version deletes, batch deletes, the GC queue and lifecycle expiration.
  A lock label that did not block deletion would have been a false
  compliance claim.
- **ACL grants with a fail-closed intersection (phase D).** Bucket and
  object ACLs are stored as grants to active S3 access keys. A credential's
  effective permission is its own SigV4 scope intersected with the stored
  grants, so an ACL can narrow access but can never expand it. Object grants
  apply only to their exact key.
- **Public access block, policy status and ownership state (phase E).**
  The four PAB flags, the `IsPublic` scan and the object-ownership model are
  read from persisted bucket state instead of handler constants. The
  `IsPublic` answer is computed from the real grant rows and PAB flags, so it
  stays honest as ACLs change.
- **Notifications and logging configuration (phase F).** Bucket webhook
  configuration is stored with an encrypted secret, and events are written
  to a transactional outbox in the same SQL transaction as the mutation.
  A retry worker delivers them with exponential backoff and HMAC signing.
  A crash can no longer lose an event that the storage write committed.
  `PutBucketLogging` now stores a real target; delivering audit-log objects
  into that bucket remains a documented gap and is not claimed.
- **Replication API over the existing engine (phase G).** The S3
  replication document maps `Destination/Bucket` to a configured TeleDrive
  credential set and is consulted per object at upload and repair. This
  exposes the existing cross-account replica engine instead of building a
  second, incompatible replication path.
- **Full CORS grammar (phase H).** Wildcards match exactly one DNS label,
  the complete method set and header globs are accepted, and
  `MaxAgeSeconds` no longer has an artificial ceiling. Origin patterns are
  compiled once and cached. Real browser preflights now work without
  weakening the origin match.
- **Website hosting behind an explicit admin gate (phase I).** Index and
  error documents are stored per bucket and served at `/site/{bucket}/`
  only after an admin enables `public_read`. An S3 credential can write the
  website document but cannot expose the bucket. `DeleteBucketWebsite`
  clears the document and the gate in one transaction, so deleting a site
  cannot leave a public bucket behind.
- **Deferred object-tag journal (phase J).** Tagging the pending generation
  of an in-flight upload now journals the tags and applies them in the same
  transaction as the publish. Staging never becomes addressable through
  `GetObjectTagging`, and a failed publish rolls the tags back with the head
  move. This closed the last write-fence gap in the tagging contract.

**S3 full-coverage phases**

- **Policy engine, ABAC and real ownership models (phase L).** Bucket
  policies are IAM-style JSON documents, bounded to 20 KiB and 50
  statements, with deny-overrides and a validated condition allowlist.
  A matching Allow short-circuits the ACL layer; unknown operators or keys
  are rejected rather than ignored. ABAC makes principal-tag and
  existing-object-tag conditions mandatory when enabled. Ownership became
  a real setting: `BucketOwnerEnforced`, `ObjectWriter` and
  `BucketOwnerPreferred` now have different, enforced semantics.
- **Analytics, inventory and metrics configurations with real output
  (phase N).** Configuration CRUD is backed by a scheduler that writes the
  report into the configured destination through the storage engine.
  Inventory emits the AWS CSV column shape and really includes historical
  versions when requested. Analytics uses JSON Lines instead of Parquet and
  metrics are computed from catalog state instead of CloudWatch; both
  deviations are documented rather than presented as AWS parity.
- **Rename, Select, Restore and annotations (phase O).**
  `RenameObject` moves the head, manifest key and published-version key in
  one SQL transaction, so no Telegram bytes are copied.
  `SelectObjectContent` runs a bounded SQL subset over CSV or JSON and emits
  a real AWS event stream. `RestoreObject` returns the honest
  `403 InvalidObjectState` for an immediately readable object. Object
  annotations live in a separate store with their own permissions and
  bounded listing.
- **Intelligent-Tiering with a real access gate (phase N5/O1).** Reads
  maintain access counters, and a scheduler moves `storage_class` from real
  idle time. An archived object answers `403 InvalidObjectState` until a
  `RestoreObject` opens a bounded restore window, so the tier label has an
  observable consequence. No Telegram byte moves and no Glacier durability
  or retrieval pricing is claimed; this is an access gate in the catalog,
  documented as such.

- **Bucket metadata journal (phase O3).** AWS's metadata table is an
  AWS-managed Iceberg table; there is no Iceberg runtime here, so the
  honest backing is our own SQL mutation journal. Nine configuration
  operations expose it: every create, delete, version revocation, tag,
  annotation, ACL change, restore and rename is recorded with actor and
  timestamp, and the GET responses report real journal statistics. Journal
  rows are written in the same transaction as the mutation through a
  savepoint, so journaling can never fail a storage write. Identifiers are
  TeleDrive-shaped and no AWS table ARN is fabricated.
- **SSE-C (phase M).** Each Telegram chunk is encrypted with AES-256-GCM
  under a fresh 12-byte nonce and an AAD binding it to its object identity
  and ordinal, so a spliced or reordered chunk fails authentication. The
  client key is never persisted, logged or echoed; only the AWS-published
  key-MD5 fingerprint is stored, which lets HEAD reject a wrong key without
  reading ciphertext. Range reads decrypt only the chunks they overlap.
  Multipart binds an upload to one key, and `UpdateObjectEncryption`
  re-encrypts chunk by chunk in one bounded pass. SSE-S3 and SSE-KMS are
  rejected 501 rather than faked, because no server-side key exists.
  Encrypted objects are excluded from content-addressed dedup and from the
  plaintext search index.
- **S3 governance page.** Policy, ownership, public access block, object
  lock, website, notifications, replication, tiering and reports are
  operable from `/s3/governance` instead of requiring a signed API call.
  The page signs internally with a real credential, requires admin for
  writes, audit-logs them, and states the real consequence of each action
  rather than a friendly label.
- **S3 credentials console rebuilt around the 88-scope catalogue.** The
  catalog outgrew a single checkbox wall: it went from 18 scopes in 1.0.7
  to 88 enforced scopes, grouped here into 20 resource families (buckets,
  objects, tagging, annotations, ACL, policy and ownership, PAB, object
  lock, versioning, lifecycle, CORS, website, notifications, logging,
  replication, encryption/SSE-C, metadata configuration, tiering,
  reports, acceleration). Every scope the server will accept is present in
  the UI, and a regression test compares the groups against the server's
  `PERMISSIONS` set so a newly enforced scope cannot become ungrantable
  from the page. `/s3/credentials` now
  groups by family with a human description, filters groups and scopes
  live, offers group-level select-all/clear, and keeps a sticky
  "N of M selected" summary. Five presets (Read-only, Backup client, Sync
  client, Bucket administrator, Full access) state their consequence and
  remain a starting point: applying one shows which groups it enabled and
  leaves every checkbox editable. Scopes that destroy data or change
  governance (`s3:Delete*`, policy, object-lock configuration, ACL, SSE-C
  object encryption, metadata-retention updates, rename) carry a
  destructive/governance marker with an inline consequence; the grant is
  still allowed, so the operator is informed rather than blocked. Create,
  edit, rotate, revoke and reveal are all reachable from the page; rotate
  is issue-new-then-revoke-old in one confirmed step because an access key
  and secret are immutable, and both rotate and revoke state that existing
  clients stop working immediately. Expiry is shown as absolute plus
  relative time with an "expires soon" state, revoked and expired
  credentials stay listed but immovable, and the page has explicit
  loading, error and empty states. The S3 nav group on every page now
  reads Credentials · Buckets · Governance.
- **The credentials page never persists a secret.** The created/revealed
  secret lives only in the Alpine component that received it, is rendered
  into the page, and is discarded when the panel closes. It is not written
  to `localStorage` or `sessionStorage` and never appears in a URL;
  reveal keeps its explicit confirmation and audit note. A regression test
  asserts the absence of all three paths.

**Deployment and operations**

- **Env-only ports and TLS, with per-listener certificates.** The host port
  mapping, the in-container listener and the healthcheck now read the same
  `TELEDRIVE_WEB_PORT` / `TELEDRIVE_S3_PORT` variables. WebUI and S3 can
  each serve TLS with an independent certificate pair, and a combined `.pem`
  needs only the certificate variable. The old split between config.yaml
  and hardcoded container flags could silently ignore a port change.
- **Public certificate bootstrap.** `/server.cer` serves the DER certificate
  and `/server.crt` the PEM chain, unauthenticated, so a client can install
  trust before it can log in. Only certificate blocks are emitted; a
  combined `.pem`'s private key is stripped. The Settings page links both.
- **Service settings persisted in SQL.** A single encrypted
  `service_settings` row holds the whole configuration document.
  `config.yaml` seeds it on first boot and remains the bootstrap and
  disaster-recovery copy. After that the SQL row is authoritative, so a UI
  save survives a rebuild from a stale mounted file. An undecryptable row
  falls back to the file instead of breaking startup.
- **The container healthcheck reads the same environment as the service**,
  including TLS, so it cannot probe a port the app stopped listening on.

### Changed

- **The default ownership model is `BucketOwnerEnforced`.** Object-ACL
  grants are ignored in that mode; bucket ACLs still constrain bucket-level
  access. Deployments that relied on object ACLs must switch the bucket to
  `ObjectWriter` (or `BucketOwnerPreferred`). This is a deliberate
  behaviour change, documented in [docs/UPGRADING.md](docs/UPGRADING.md).
- **The S3 credential permission catalog grew from 18 to 88 scopes.** New
  credentials receive the full default set, but existing credentials keep
  their stored list. An existing credential that must call the new policy,
  ownership, object-lock, website, notification, replication, SSE-C,
  metadata-configuration, reporting, rename, select or tiering operations
  needs those scopes added. The console groups all 88 by resource family
  and marks the ones that can destroy data or change governance, so the
  difference between "this client needs to restore an object" and "this
  client can delete the bucket" is visible before it is granted.
- **`config.yaml` is no longer the live source for listener ports or TLS.**
  Those keys are deployment plumbing and are read only from the environment.
  Other service settings still use the file as their bootstrap source until
  the SQL document exists.
- **Several operations that were previously documented as unsupported or
  partial are now supported:** bucket policies, ACLs, ownership controls,
  PAB writes, object lock and retention, notifications, logging
  configuration, replication, website configuration, lifecycle expiration,
  analytics/inventory/metrics configuration, rename, select, restore,
  annotations and intelligent-tiering. The authoritative per-operation
  inventory is [docs/S3_SPECS.md](docs/S3_SPECS.md).

### Fixed

- **MySQL rejected the PAB default and the legacy-schema probe could skip
  the wrong database.** `storage_buckets.public_access_block` is now
  `VARCHAR(512)` because MySQL 8.4 rejects a server default on TEXT/BLOB.
  The `information_schema` probe now filters by `DATABASE()` on MySQL and
  `current_schema()` on PostgreSQL; without that filter it could see a
  same-named table in another database and silently skip the ALTER.
- **PostgreSQL rejected the Phase C boolean defaults.** Defensive ALTERs now
  use `DEFAULT false` instead of `DEFAULT 0`. Deployments still on the
  Phase B schema could otherwise fail every catalog initialisation.
- **A ranged GET returned the full-object checksum header.** A 206 response
  carried `x-amz-checksum-sha256` for the whole object, so boto3 and the AWS
  CLI rejected every ranged read as a checksum mismatch. The checksum is now
  emitted only on a complete-object read.
- **Intelligent-Tiering emitted the wrong XML element.** The wire element
  is the flattened `<Tiering>`, repeated per tier, not `<Tierings>`. An
  intermediate build rendered `<Tierings>`, which made boto3 parse a
  response with Id and Status only and silently drop the tiers. The
  renderer emits `<Tiering>` again; the parser accepts both spellings so a
  client written against the Python member name is not rejected.
- **Annotation bodies sent as aws-chunked were read raw.** boto3 often sends
  blob bodies with SDK checksum trailers. The annotation handler included
  the chunk framing and reported a missing CRC32, producing `BadDigest` on
  a valid call. A shared bounded reader now decodes aws-chunked and forwards
  the trailer checksum to the verifier.
- **Rename and Select used invented wire shapes.** `RenameObject` now uses
  `PUT /{bucket}/{destination}?renameObject` with the signed
  `x-amz-rename-source` header (`?rename` remains an alias). Select now
  accepts qualified column references and `FROM S3Object [AS] alias`, so
  the AWS-documented query form works.
- **A fresh database could fail every publish with a missing Phase J
  journal table.** The pending-tag table was created only when the tag
  store was constructed. `BucketCatalog` now creates it before any publish,
  so an upload-only process and a reset database both work.
- **`RestoreObject` raised `NameError` on every call.** A missing `update`
  import turned a valid request into HTTP 500; the import and the archive
  path are both fixed.

### Security

- **API-key delegation ceiling.** A bearer key could mint a key with any
  permission, rotate a more privileged key to obtain its secret, or revoke
  above its own authority. Mint, rotate and revoke now require the caller to
  already hold the authority being delegated. A key scoped only to
  key-management can no longer take over the deployment.
- **ACL bypasses in batch delete and copy.** Batch delete addressed no
  object key, so only the bucket ACL was checked; CopyObject and
  UploadPartCopy checked the destination but not the source. Every batch
  entry is now checked per key, and both copy paths enforce the source
  object's ACL.
- **ACL ownership is immutable.** A credential allowed to write an ACL could
  name a different Owner and lock the real owner out. The first write
  establishes the owner, later writes keep it, and a document naming another
  Owner is rejected.
- **Expired credentials can no longer reveal their secret.** `reveal()`
  refuses an expired credential, and presigning validates `s3:GetObject`
  instead of handing out a URL that could never work.
- **Physical GC is admin-only.** The GC toggle and collect trigger were
  reachable by the operator role although the documentation calls physical
  deletion an owner decision. Both routes now require admin.
- **Audit identity cannot be spoofed with an unverified Basic header.**
  The middleware previously logged the username from any Basic header
  without checking the password, so a rejected request could write "admin"
  into the audit trail. It now records `unverified-basic` unless the
  credential verifies, and it stops naming revoked or expired API keys.

- **Cross-connection reads could miss a row committed by another worker on
  MySQL.** Every store constructor runs schema probing (`create_all` plus
  `information_schema`), and under MySQL's default REPEATABLE READ the first
  statement freezes the connection's snapshot. A lease or head written by a
  different worker afterwards stayed invisible, which broke multipart
  recovery and the conditional-head CAS. Setup now ends its transaction
  (`Database.release_setup_snapshot`), so the first real read sees current
  data. SQLite is unaffected and short-circuits.
- **The live E2E workflows could not import the storage layer.**
  `pyproject.toml` declared only Telethon, PyYAML and SQLAlchemy, while SSE-C
  made the engine import `cryptography` at module load. Those workflows
  install with `pip install -e .` and never read `requirements.txt`, so
  collection aborted before a single test ran. `cryptography` and
  `defusedxml` are now declared, and a meta test pins the rule.
- **`RestoreObject` raised `NameError` instead of responding.** `web/s3.py`
  used `sqlalchemy.update` without importing it, so every restore call
  returned 500.
- **Intelligent-Tiering emitted the wrong XML element.** The tier list is a
  flattened list whose wire element is `<Tiering>`, not `<Tierings>`; with
  the wrong spelling boto3 parsed a response with no tiers at all.

### Performance

- **Database close no longer stalls for 30 seconds.** `close()` ran a WAL
  checkpoint on the same connection, often with an open transaction, and
  waited out the full 30-second busy timeout. The checkpoint now runs after
  the connection closes, on a separate raw connection, with a 200ms busy
  timeout. The measured 30.07-second close is gone, and the SQLite file is
  still self-contained for direct readers.
- **The test suite is parallel-safe.** Three parametrize lists generated
  random bytes or UUIDs at import time, so xdist workers collected different
  node IDs. They are deterministic now, `requirements-dev.txt` separates
  test tooling from the runtime image, and `pytest -n auto` is the documented
  fast command. Across these performance commits the full suite went from
  about 4m37s to 1m48s with `-n 4`; a serial run remains available for
  debugging.
