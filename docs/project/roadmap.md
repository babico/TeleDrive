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
- [x] Module split: `web/app.py` 6027 → 1576 lines, `web/s3.py` 5106 → 191,
      `web/static/app.js` 1469 → 167, `catalog.py` 1465 → 132, with the route
      surface frozen by a meta-test.
- [x] Raw SQL reduced to five annotated read-only aggregate call sites; no
      mutating handler SQL remains in `web/`.
- [x] Disposable 13-gate Docker acceptance, live user E2E and multiworker
      PostgreSQL E2E in CI; docs site built with `mkdocs --strict`.

## 2. Correctness and maintainability

- [ ] **Finish the `web/app.py` router split.** Move the remaining handler
      groups into `web/routers/*` per the handoff notes under
      `docs/project/handoffs/`. Prerequisite: keep
      `tests/meta/test_route_surface.py` byte-identical; a moved route that
      loses its `Depends(...)` is an unauthenticated route. Acceptance: no
      behaviour change, surface test unchanged, file under ~800 lines.
- [ ] **Split the remaining `catalog_*` growth points only when a real change
      touches them.** `catalog_versions.py` (775) and `manifest.py` (712) are
      large but cohesive; do not split for line count alone. Acceptance: a
      concrete bug or feature that needs a new seam, not a refactor-only PR.
- [ ] **Consolidate the WebUI page groups that still duplicate fetch/render
      helpers.** `telegram.js`, `buckets.js` and `admin.js` each carry a
      variant of the same table/toast code. Acceptance: one shared helper per
      behaviour, `test_page_composition.py` updated, no fragment loaded on a
      page whose `init()` does not need it.
- [ ] **Audit the remaining `except Exception` sites for silent work loss.**
      The swallowed-name test catches the two known shapes; it cannot catch a
      broad handler that hides a legitimate failure. Acceptance: each
      remaining broad catch in `web/` and `teledrive/storage/` either logs a
      reason class or has a comment explaining why silence is correct.

## 3. S3 parity and protocol evidence

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
- [ ] **Prove mutation invariants on both real databases.** The SQLite race
      matrices are fast but cannot prove PostgreSQL/MySQL semantics. Port the
      highest-risk mutation races (publish/delete, multipart completion,
      GC lease, schema init) into the `database` job. Acceptance: the job
      runs them against both services and fails on a dialect-specific write.
- [ ] **Write migration and rollback notes per metadata table.** The schema is
      append-only and idempotent, but an operator still needs to know what a
      step adds and what a downgrade would leave behind. Acceptance: one
      paragraph per table family in the upgrade guide, checked against
      `schema.py` step names.
- [ ] **Extend the client matrix beyond boto3, AWS CLI and rclone v1.66.0.**
      Cyberduck and one S3-compatible SDK other than botocore are the named
      gaps. Acceptance: a pinned version and a live flow, or an explicit
      statement that the client is untested — never an implied "works".
- [ ] **Recover unknown original history without inventing metadata.**
      Candidate markers from a bounded channel scan are not an importable
      plan. This needs owner-supplied independent metadata plus byte
      verification; engineering can improve reconciliation but cannot create
      the missing identity. Acceptance: a verified plan restored into an
      isolated catalog, with no guessed bucket/key/hash.
- [ ] **Keep the SSE-C / envelope boundary honest.** SSE-C is supported;
      envelope is opt-in and excludes dedup, replication and content search;
      SSE-KMS does not exist. Acceptance: any new encryption surface must
      either have real key custody or return a named 501 — no silent
      plaintext.

## 4. Operations and test realism

- [ ] **Make `/data` and `/uploads` test-configurable.** Two tests patch
      `pathlib.Path.mkdir` globally because the app still hardcodes those
      roots in a few places. Acceptance: the roots come from settings in every
      path, the global patch disappears, and the tests pass under xdist.
- [ ] **Consolidate the repeated tmp-app fixtures into a shared `conftest.py`.**
      Four fixtures re-implement setup with small drift. Acceptance: one
      factory, no behavioural change, full suite green.
- [ ] **Port the restart/retry matrices to PostgreSQL where SQLite is the only
      backend.** SQLite cannot prove row-lock or advisory-lock behaviour.
      Acceptance: at least the GC lease, schema init and publish/delete races
      run on both backends.
- [ ] **Harden the documentation build in review.** The site test already
      checks nav, links, language, one H1 and placeholders. Acceptance: keep
      it green in every PR and add a check only when a real doc regression
      slips through.
- [ ] **Run a long-duration capacity profile on owner hardware.** The manual
      60–110 minute endurance workflow uses synthetic media and SQLite; it is
      not a production bandwidth or 429 measurement. Acceptance: a recorded
      run with real disk/network, p50/p95 timings and no fabricated rate
      limits.

## 5. Owner gates — physical GC

These are owner actions, not engineering tasks. `deletion_permitted` stays
`False` and no Telegram media is deleted until all of them are satisfied.
Two-person GC approval is **not** required (owner decision).

- [ ] **Independent backup host.** A second physical host or a verified
      rclone/payload export that is not the TeleDrive data volume. Acceptance:
      a restore from that copy into an isolated environment.
- [ ] **Authorized rate-limit soak.** One hour on 2–8 HTTPS endpoints with
      genuine observed 429s, coherent shared counters, drained queues and no
      unresolved send ACK. Do not induce abuse to force 429s.
- [ ] **Original-media recovery rehearsal.** The owner's sealed SQL archive,
      independent SHA-256, real Telegram credentials and channel; verify one
      named object's whole-body SHA, size and cross-chunk range in an isolated
      restore.
- [ ] **Legacy cutover decision.** Either a verified cutover from a real
      legacy source or an independent signed no-legacy attestation. Never
      invent a legacy fixture.
- [ ] **Evidence bundle verification.** Produce the canonical JSON and check
      it with `scripts/ops/verify_production_bundle.py`, using two distinct
      Ed25519 keys and two independently attested hosts sharing one database.
      The `approvals` block is optional by owner decision; the technical
      families are required.
- [ ] **Authorize physical GC.** Only after all gates pass, with a signed
      dry-run plan, complete remote inventory and resolved references. The
      WebUI toggle and collect endpoint remain admin-only and refuse while
      the gate is off.

## 6. How this list is maintained

An item is checked only when its acceptance criterion genuinely passes on a
commit that can be named. Do not check an item because the code "looks done";
link the test, the command output or the owner attestation. When a completed
item no longer needs to be visible, move it to the summary rather than keeping
a stale essay. The pinned completed PutBucketTagging line above is kept as a
contract for the documentation tests.
