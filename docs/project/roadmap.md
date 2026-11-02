# Roadmap

The open work, grouped by theme. Completed milestones are summarised at the
top instead of kept as a checkbox wall; this page is a plan, not a changelog.
Evidence boundaries are in [Project status](status.md), CI mechanics in
[CI and tests](../reference/ci.md), and the S3 operation matrix in
[S3 compatibility](../reference/s3-specs.md).

## New queued implementation track (2026-11-02)

The [S3 fidelity and recovery execution plan](plans/2026-11-02-s3-fidelity.md) and [handoffs 06–10](https://github.com/babico/TeleDrive/tree/main/docs/project/handoffs) describe the next implementation queue. These are **planned, not delivered**: GetObject partNumber, true directory bucket sessions, cold payload archival/restore, versioning/Object Lock/lifecycle/ACL/policy submode parity, server-enforced first-boot admin password rotation, and expanded P1/P2/P3 tests, refactor and documentation checks. Original-media DR and independent-host payload backup are owner-run procedures. Physical GC remains an owner-operated toggle without a mandatory signed acceptance bundle.

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
- [x] Raw SQL reduced to four annotated read-only aggregate call sites; no
      mutating handler SQL remains in `web/`.
- [x] Disposable 13-gate Docker acceptance, live user E2E and multiworker
      PostgreSQL E2E in CI; docs site built with `mkdocs --strict`.

## 2. Correctness and maintainability

- [x] **Finish the `web/app.py` extraction — what is actually left.** The
      router split itself is complete: only four system routes
      (`/openapi.json`, `/docs`, `/redoc`, `/api/v1/metrics`), the three
      middlewares and the shared stream cores remain. What was still fused to
      app construction is (a) the settings/config machinery (roughly the
      first 500 lines: `read_raw_config`, `effective_config`,
      `_persist_settings_document`, secret scrubbing) and (b) the seven
      scheduler loops with their job cores. Both are now extracted into
      `web/settings_runtime.py` and `web/schedulers.py`, re-exported through
      `web.app` so callers and test monkeypatching keep working;
      `tests/meta/test_route_surface.py` stayed byte-identical. The result is
      **944 lines, not the estimated ~700**: what remains is exactly the
      parts this item reserved (system routes, middlewares, stream cores)
      plus the audit/log plumbing and the Prometheus renderer, and this
      roadmap's own rule is no split for line count alone. `teledrive/settings.py`
      gained `paths.data_dir` / `TELEDRIVE_DATA_DIR` so every stateful default
      hangs off one relocatable root (see §4).
- [ ] **Split the remaining `catalog_*` growth points only when a real change
      touches them.** `catalog_versions.py` (775) and `manifest.py` (712) are
      large but cohesive; do not split for line count alone. Acceptance: a
      concrete bug or feature that needs a new seam, not a refactor-only PR.
- [x] **Consolidate the WebUI page groups that still duplicate fetch/render
      helpers.** `telegram.js`, `buckets.js` and `admin.js` each carried a
      variant of the same table/toast code. Done: one `apiFetch()` base plus
      `api()`/`govCall()` as the only front doors (session cookie, CSRF
      header, JSON-or-text body handling in one place), shared
      toast/confirm helpers in `app.js`, and `bucketUrl()`/`govDeleteUrl()`
      builders for the URL shapes each page repeats. `settings.html` drift
      fixed in the same pass (the scheduler toggle is wired back to
      `jobs.auto_run`); four new pinning tests in `test_settings_ui.py` /
      `test_page_composition.py` lock the wiring.
- [x] **Audit the remaining `except Exception` sites for silent work loss.**
      The swallowed-name test catches the two known shapes; it cannot catch a
      broad handler that hides a legitimate failure. Done across 108
      handlers: four legitimate narrowings (`sqlite_database_path` to
      `ArgumentError`; the pins/content_index/gc-collect `_claim` paths to
      `IntegrityError`), a fail-closed 503 where the session-delete usage
      guard silently disabled itself on a DB error, and a log line with a
      severity matching the blast radius on every other best-effort catch.
      Exactly one documented exception remains silent — the file-log
      emitter, which cannot report its own failure without recursing.
      Startup-protection catches keep their broad shape with rationale
      comments.

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

- [x] **Make `/data` and `/uploads` test-configurable.** Two tests patched
      `pathlib.Path.mkdir` globally because the app still hardcoded those
      roots in a few places. Done: `paths.data_dir` /
      `TELEDRIVE_DATA_DIR` in `teledrive/settings.py` derives every stateful
      default (scratch, auth, sessions, logs, SQLite roots), the test
      factory points every root at `tmp_path` through the config file
      itself, and the global patches are gone — `grep 'Path, "mkdir"'
      tests/` is empty and the suite passes.
- [x] **Consolidate the repeated tmp-app fixtures into a shared `conftest.py`.**
      Four fixtures re-implemented setup with small drift. Done: one
      `make_app_env` factory in `tests/web/conftest.py` (tmp SQLite, config
      naming every root, transport/db patches, the knobs the special cases
      need); five modules build on it. No behavioural change, full suite
      green; `test_settings_persistence.py` stays separate on purpose (it
      tests the raw store path with its own master-key knob).
- [x] **Port the restart/retry matrices to PostgreSQL where SQLite is the only
      backend.** SQLite cannot prove row-lock or advisory-lock behaviour.
      Done: both matrices run on real PostgreSQL 17 and MySQL 8.4 via the
      opt-in `DB_TEST_*_URL` parameters, dropping TeleDrive-owned tables per
      test so inventories stay in sync; the CI database job executes them
      with the live URLs (and now installs the web stack they import).
- [ ] **Harden the documentation build in review.** The site test already
      checks nav, links, language, one H1 and placeholders. Acceptance: keep
      it green in every PR and add a check only when a real doc regression
      slips through.
- [ ] **Run a long-duration capacity profile on owner hardware.** The manual
      60–110 minute endurance workflow uses synthetic media and SQLite; it is
      not a production bandwidth or 429 measurement. Acceptance: a recorded
      run with real disk/network, p50/p95 timings and no fabricated rate
      limits.

## 5. Owner-run recovery and production evidence (not a GC toggle gate)

These items are **owner-run operational tests** for disaster recovery and production certification, not mandatory technical prerequisites for enabling physical GC. The admin can enable GC with the existing typed confirmation, and the collector must still protect live/retained/referenced chunks. No mandatory signed acceptance bundle or two-person GC approval should be introduced.

- [ ] **Independent payload backup and isolated restore.** On separate hardware or a verified remote export, make encrypted media plus SQL and key-material backups, then prove bytes and cross-chunk ranges can be restored.
- [ ] **Authorized real-world capacity/rate-limit soak.** One hour on permitted real endpoints, record genuine observations; no synthetic 429s represented as production.
- [ ] **Original-media recovery rehearsal.** Run the read-only sample test on the owner's sealed real SQL snapshot, actual credentials and known SHA-256. Never substitute CI fixtures.
- [ ] **Legacy cutover applicability.** Only run a migration if a real legacy source exists; otherwise record 'not applicable' without creating a fake test.
- [ ] **Production evidence bundle (optional certification).** Record host topology, RPO/RTO, durability and restore receipts. The offline verifier is for production certification, **not** for granting permission to click the GC toggle.
- [ ] **GC dry-run and owner decision.** The owner reviews eligible objects and independently chooses whether to enable irreversible physical deletion. Keep reference/retention/race fences mandatory regardless of this choice.

## 6. How this list is maintained

An item is checked only when its acceptance criterion genuinely passes on a
commit that can be named. Do not check an item because the code "looks done";
link the test, the command output or the owner attestation. When a completed
item no longer needs to be visible, move it to the summary rather than keeping
a stale essay. The pinned completed PutBucketTagging line above is kept as a
contract for the documentation tests.
