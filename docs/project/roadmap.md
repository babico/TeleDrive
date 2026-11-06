# Roadmap

The open work, grouped by theme. Completed milestones are summarised at the
top instead of kept as a checkbox wall; this page is a plan, not a changelog.
Evidence boundaries are in [Project status](status.md), CI mechanics in
[CI and tests](../reference/ci.md), and the S3 operation matrix in
[S3 compatibility](../reference/s3-specs.md).

## 1. Completed milestones (summary)

- [x] One Telethon USER MTProto transport; the Bot API, desktop app and
      separate uploader are removed.
- [x] Session + API-key authentication with admin/operator/viewer roles,
      CSRF, login throttling, and no HTTP Basic anywhere.
- [x] API-key delegation and lifetime ceilings; `admin:*` expands over the
      live route table; interactive-only S3 credential and config surfaces.
- [x] Complete AWS-compatible PutBucketTagging
- [x] S3 inventory at its honest end state: **114 supported / 0 partial /
      2 unsupported** of 116. The two exceptions are permanent
      (`GetObjectTorrent`, `WriteGetObjectResponse`).
- [x] Metadata-backed parity: versioning states, object lock, ACLs, bucket
      policy + ABAC, PAB/ownership, notifications + logging, replication,
      website hosting, CORS, deferred tags, reports, tiering, SSE-C.
- [x] Opt-in envelope encryption (SSE-S3 shape) with its capability limits
      reported, not hidden.
- [x] One serialized schema coordinator (27 steps when the split landed; schema
      30 in v1.0.10, 31 in the current tree, real cross-process lock);
      the bucket-delete orphan-table, MySQL portability and hot-index fixes.
- [x] Module split: `web/app.py` 6027 → 1074 lines (settings runtime and
      scheduler loops extracted to their own modules), `web/s3.py` 5106 →
      235, `web/static/app.js` 1469 → 218, `catalog.py` 1465 → 139, with
      the route surface frozen by a meta-test.
- [x] Raw SQL reduced to four annotated read-only aggregate call sites; no
      mutating handler SQL remains in `web/`.
- [x] Disposable 13-gate Docker acceptance, live user E2E and multiworker
      PostgreSQL E2E in CI; docs site built with `mkdocs --strict`.
- [x] Exception audit closed: no undocumented silent `except` remains in
      `web/` or `teledrive/storage/`; GC lease claims survive InnoDB
      deadlock elections with a bounded retry.
- [x] The race and restart matrices, including schema-init, run on real
      PostgreSQL 17 and MySQL 8.4 inside the CI database job.
- [x] Every schema step catalogued with its family, locking and undo
      residue in [Schema steps](../reference/schema-steps.md), linked from
      the upgrade guide.
- [x] One `make_app_env` test factory; every stateful root relocatable
      through `paths.data_dir` / `TELEDRIVE_DATA_DIR`; one shared JS fetch
      layer (`apiFetch`/`api`/`govCall`) with pinning tests.
- [x] **v1.0.10 (schema 30):** directory buckets with session credentials,
      a physical cold archive with a truthful RestoreObject, AWS-exact
      null-version/ACL/policy/lock semantics, GetObject part reads, the
      enforced bootstrap rotation, and the complete per-operation evidence
      program (114 operations x 7 classes).

## 2. S3 fidelity — delivered in v1.0.10

The [S3 fidelity and recovery execution
plan](plans/2026-11-02-s3-fidelity.md) and handoffs 06–09 are fully
implemented and shipped in v1.0.10:

- [x] **GetObject `?partNumber=N`** from the immutable MPU layout, with
      sparse-safe offsets, `206`/`Content-Range`/`x-amz-mp-parts-count`,
      `416 InvalidPartNumber` and `Range`+`partNumber` refused.
- [x] **Server-enforced first-boot password rotation**: every
      authenticated operation is refused until the seeded `admin/admin`
      is rotated, through gates that run before authorization; the
      self-service change endpoint is the only write the flow allows.
- [x] **Directory buckets and CreateSession**: `bucket_type`, immutable
      `base--zone-id--x-s3` names with a logical zone label, real
      paginated listing, short-lived session credentials (token hashed,
      secret encrypted, durable revocation), `s3express` zonal signing and
      zonal aws-chunked uploads.
- [x] **Physical cold archive and RestoreObject**: sealed blobs with
      fsync and hash-verified readback, a resumable state machine with
      leases and generation fences, real restores that open the read
      window only after verification, and a GC fence that permits hot
      deletion only when the cold blob readbacks with the exact digest.
- [x] **Lifecycle parity**: `Transition`, `NoncurrentVersionTransitions`,
      `NoncurrentVersionExpiration`, `ExpiredObjectDeleteMarker`,
      `Tag`/`And` filters and `Date` schedules.
- [x] **Submode parity**: AWS-exact suspended null-version slot, canned
      ACLs and header grants, the common policy condition operators with
      temporal date comparison, per-version lock fences on every mutation
      path, and a real `s3:BypassGovernanceRetention` scope gated to the
      retention route.

Handoff 10 (owner-run original-media DR and independent payload backup)
remains owner-executed; its tooling is complete (see §5).

## 3. Protocol evidence

The operation list and current status are **not duplicated here**; use the
[compatibility matrix](../reference/s3-specs.md),
`teledrive/s3/operation_manifest.json` and the
[per-operation evidence matrix](../reference/s3-evidence.md) as the
authority.

- [x] **Complete the per-operation evidence matrix.** All 114 supported
      operations now carry a named proving test in every applicable
      class — normal, auth-failure, malformed, over-limit, retry,
      crash-restart and race are each at 100% of applicable cells,
      enforced by `tests/meta/test_s3_evidence_matrix.py`, so a new
      operation cannot be added without its row. The audit itself found
      and fixed four real defects: `ListObjectVersions` 400 when the
      marker version was deleted between pages, a rename race escaping
      as a 500, `BucketEncryptionStore` surfacing an integrity error as a
      500 on PostgreSQL/MySQL, and `DeleteBucket` removing a same-name
      recreation by a stale conclusion.
- [x] **Extend the client matrix beyond boto3, AWS CLI and rclone.** A
      fourth independent wire implementation (minio-py 7.2.20, its own
      SigV4 signer, botocore-free) runs a live flow in CI, and Cyberduck
      is documented as explicitly untested with its reason — no implied
      "works".
- [x] **The parameter-level compatibility ledger**
      (`docs/reference/s3-parameters.md`) states SUPPORTED / REJECTED /
      UNVERIFIED per parameter, re-derived from the gateway source on
      every test run.

## 4. Code health (conditional)

- [ ] **Split the remaining `catalog_*` growth points only when a real change
      touches them.** `catalog_versions.py` (878) and `manifest.py` (712) are
      large but cohesive; do not split for line count alone. Acceptance: a
      concrete bug or feature that needs a new seam, not a refactor-only PR.

## 5. Owner-run recovery and production evidence (not a GC toggle gate)

These items are **owner-run operational tests** for disaster recovery and
production certification, not mandatory technical prerequisites for enabling
physical GC. The admin can enable GC with the existing typed confirmation,
and the collector must still protect live/retained/referenced chunks. No
mandatory signed acceptance bundle or two-person GC approval should be
introduced.

The tooling for them is complete and offline-testable: the DR rehearsal
script verifies full bytes plus first/middle/cross-boundary/last ranges,
unwraps envelope keys, cross-checks independent attestations and writes a
redacted evidence record, with `--self-test` proving the whole path
without network or Telegram; the [DR checklist](../operate/dr-checklist.md)
is the owner's single page. What remains below needs owner hardware,
owner credentials and the owner's own data.

- [ ] **Independent payload backup and isolated restore.** On separate
      hardware or a verified remote export, make encrypted media plus SQL
      and key-material backups, then prove bytes and cross-chunk ranges can
      be restored.
- [ ] **Authorized real-world capacity/rate-limit soak.** One hour on
      permitted real endpoints, record genuine observations; no synthetic
      429s represented as production.
- [ ] **Long-duration capacity profile on owner hardware.** The manual
      60–110 minute endurance workflow uses synthetic media and SQLite; it
      is not a production bandwidth or 429 measurement. Acceptance: a
      recorded run with real disk/network, p50/p95 timings and no
      fabricated rate limits.
- [ ] **Original-media recovery rehearsal.** Run the read-only sample test
      on the owner's sealed real SQL snapshot, actual credentials and known
      SHA-256. Never substitute CI fixtures.
- [ ] **Recover unknown original history without inventing metadata.**
      Candidate markers from a bounded channel scan are not an importable
      plan. This needs owner-supplied independent metadata plus byte
      verification; engineering can improve reconciliation but cannot
      create the missing identity. Acceptance: a verified plan restored
      into an isolated catalog, with no guessed bucket/key/hash.
- [ ] **Legacy cutover applicability.** Only run a migration if a real
      legacy source exists; otherwise record 'not applicable' without
      creating a fake test.
- [ ] **Production evidence bundle (optional certification).** Record host
      topology, RPO/RTO, durability and restore receipts. The offline
      verifier is for production certification, **not** for granting
      permission to click the GC toggle.
- [ ] **GC dry-run and owner decision.** The owner reviews eligible objects
      and independently chooses whether to enable irreversible physical
      deletion. Keep reference/retention/race fences mandatory regardless of
      this choice.

## 6. Standing rules (not tasks)

- **Keep the SSE-C / envelope boundary honest.** SSE-C is supported;
      envelope is opt-in and excludes dedup, replication and content
      search; SSE-KMS does not exist. Any new encryption surface must
      either have real key custody or return a named 501 — no silent
      plaintext.
- **Harden the documentation build in review.** The site test checks nav,
      links, language, one H1 and placeholders; keep it green in every PR
      and add a check only when a real doc regression slips through.

## 7. How this list is maintained

An item is checked only when its acceptance criterion genuinely passes on a
commit that can be named. Do not check an item because the code "looks
done"; link the test, the command output or the owner attestation. When a
completed item no longer needs to be visible, move it to the summary rather
than keeping a stale essay. The pinned completed PutBucketTagging line
above is kept as a contract for the documentation tests.
