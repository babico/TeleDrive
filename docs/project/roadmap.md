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
- [x] One serialized schema coordinator (27 steps, real cross-process lock);
      the bucket-delete orphan-table, MySQL portability and hot-index fixes.
- [x] Module split: `web/app.py` 6027 → 944 lines (settings runtime and
      scheduler loops extracted to their own modules), `web/s3.py` 5106 →
      191, `web/static/app.js` 1469 → 167, `catalog.py` 1465 → 132, with
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

## 2. Queued implementation track — S3 fidelity (planned, not delivered)

The [S3 fidelity and recovery execution
plan](plans/2026-11-02-s3-fidelity.md) and [handoffs 06–10](handoffs/)
describe the next implementation queue:

- GetObject `partNumber` and server-enforced first-boot admin password
  rotation ([handoff 06](handoffs/06-get-part-and-bootstrap.md)).
- True directory bucket and CreateSession / S3 Express credential
  behavior ([handoff 07](handoffs/07-directory-buckets-sessions.md)).
- Real archive bytes, RestoreObject and lifecycle cold-tier
  ([handoff 08](handoffs/08-physical-archive-restore.md)).
- S3 submode parity with IAM/STS and KMS boundaries
  ([handoff 09](handoffs/09-s3-submodes-and-identity.md)).
- Owner-run original-media DR and physically independent payload backup
  ([handoff 10](handoffs/10-owner-media-backup-and-dr.md)).

## 3. Protocol evidence still open

The operation list and current status are **not duplicated here**; use the
[compatibility matrix](../reference/s3-specs.md) and
`teledrive/s3/operation_manifest.json` as the authority.

- [ ] **Complete the per-operation evidence matrix.** For every supported
      operation, fill the normal / auth-failure / malformed / over-limit /
      retry / crash-restart / race columns the spec leaves open. The
      table-driven sweeps already cover unsigned, malformed, over-limit,
      restart and retry-race globally; this item is the per-operation rows
      that remain. Acceptance: a new operation cannot be added without its
      row, enforced by the existing meta-tests.
- [ ] **Extend the client matrix beyond boto3, AWS CLI and rclone v1.66.0.**
      Cyberduck and one S3-compatible SDK other than botocore are the named
      gaps. Acceptance: a pinned version and a live flow, or an explicit
      statement that the client is untested — never an implied "works".

## 4. Code health (conditional)

- [ ] **Split the remaining `catalog_*` growth points only when a real change
      touches them.** `catalog_versions.py` (775) and `manifest.py` (712) are
      large but cohesive; do not split for line count alone. Acceptance: a
      concrete bug or feature that needs a new seam, not a refactor-only PR.

## 5. Owner-run recovery and production evidence (not a GC toggle gate)

These items are **owner-run operational tests** for disaster recovery and
production certification, not mandatory technical prerequisites for enabling
physical GC. The admin can enable GC with the existing typed confirmation,
and the collector must still protect live/retained/referenced chunks. No
mandatory signed acceptance bundle or two-person GC approval should be
introduced.

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
