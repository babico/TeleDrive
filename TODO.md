# TeleDrive TODO & Roadmap

> **Purpose:** the single prioritized plan — completed milestones, active
> work, product roadmap, S3 parity track and owner gates. For decisions and
> evidence limits, see [Project Status](docs/IMPLEMENTATION_STATUS.md). For
> commands and CI contracts, see [CI and Test Guide](docs/CI_WORKFLOWS.md).
> Product/feature analysis that produced the roadmap phases:
> `.opencode/teledrive/10x/session-1.md` (git-ignored).
> Last updated: 2026-10-21.

---

## 1. Completed milestones

**Architecture purge & config-only settings (merged PRs #15–#21 + follow-ups)**
- [x] Bot API transport fully removed; everything is Telethon USER MTProto only.
- [x] Desktop app and website removed; single Docker/baremetal WebUI service remains.
- [x] Single `requirements.txt` + root `config.example.yaml`; `examples/` removed.
- [x] `storage:` config section with `apis:` list (multi api_id/api_hash);
      strategies `single | round_robin | failover | parallel`.
- [x] Scripts/tests regrouped (`scripts/ops|dev`, `tests/s3|storage|web|e2e|meta`).
- [x] Legacy direct-send uploader fully removed; folder ingestion only via the
      admin `import-legacy` endpoint.
- [x] Config-only settings: env is only TZ + TELEDRIVE_CONFIG (+ PUID/PGID for
      the container user); SSL, compose hardening, DB extra packages via config.

**Security & WebUI (2026-10 hardening session)**
- [x] Token-based auth with login page; session tokens stored as SHA-256
      digests; PBKDF2 password hashing with transparent legacy migration.
- [x] Central role policy (admin/operator/viewer) enforced on all
      `/api/v1/admin/*` endpoints; disabled users blocked everywhere; login
      brute-force throttling; CSRF on all mutating endpoints.
- [x] Per-bucket quotas enforced on REST and S3 uploads (simple PUT, POST
      policy, multipart complete).
- [x] Multi-page Alpine.js/Tailwind UI (bundled locally), audit logging with
      rotating compressed handler, user management, S3 bucket browser.
- [x] DB restore drill on PostgreSQL verified (20 tables identical); remote
      test deployment healthy.

**S3 protocol contracts (selected)**
- [x] Complete AWS-compatible PutBucketTagging with 50 UTF-16-aware bucket tags, idempotent replacement, MD5/CRC validation and boto3 regression coverage.
- [x] Complete ListBuckets, ListParts, ListMultipartUploads and
      GetObjectAttributes private general-purpose contracts (bounded SQL
      keyset pagination, immutable part snapshots, fail-closed tamper handling).
- [x] 116-operation machine-readable S3 manifest + fail-closed selector
      validation and adversarial CI coverage.
- [x] Get/PutBucketVersioning (Enabled only), Get/PutPublicAccessBlock
      (all-private only), lifecycle SQL-only incomplete-MPU abort.
- [x] Full non-destructive GC machinery (reference graph, dry-run plans,
      integrity checks, race tests); physical deletion stays disabled.

---

## 2. Phase 0 — Technical debt & S3 compatibility (COMPLETE)

- [x] Split `web/s3.py::_handle` into per-verb-family handlers
      (`_S3RequestContext` + `_handle_form_upload`, `_handle_batch_delete`,
      `_handle_bucket_controls`, `_handle_bucket_route`, `_handle_multipart`,
      object read/write paths). Behavior-preserving; S3 tests are the net.
- [x] Cache the SQLAlchemy engine + parsed config per database URL
      (`teledrive/db.py`): skip per-request YAML parse, `create_all` and
      dialect migrations; WAL checkpoint on shared-engine close.
- [x] `/api/logs` returns only structured `entries` (drop `lines` duplicate).
- [x] Canonical `/api/v1/auth/*`, `/api/v1/config`, `/api/v1/logs` endpoints
      with legacy paths as permanent aliases.
- [x] Remove the Bearer token from `localStorage`; httpOnly cookie is the only
      browser session mechanism.
- [x] **S3 read-compatibility package** (P2-C style, fail-closed): valid
      AWS-shaped read responses for GetBucketAcl/GetObjectAcl (private canned
      ACL), OwnershipControls (`BucketOwnerEnforced`), Policy (404),
      Replication (404), Website (404), Logging (empty), Notification (empty),
      RequestPayment (`BucketOwner`), Accelerate (`Suspended`), Encryption
      (404), ObjectLock (404), Retention/LegalHold (404) — and fail-closed
      501 on every configuration attempt. Update route guard, operation
      manifest, S3_SPECS matrix and adversarial tests.

---

## 3. Phase 1 — Quick wins (small effort, disproportionate value)

- [x] **Download button in the S3 browser** — stream object bytes through an
      authenticated UI route (engine + Range support already exist).
- [x] **Force first-login password change** — when the admin hash still
      matches the shipped default, redirect every page to a change-password
      screen.
- [x] **rclone first-class docs** — README section with a 10-line config
      against the S3 listener (mount-as-drive on any desktop).
- [x] **Quota usage bars on the dashboard** — used vs quota data already
      returned by `admin_list_buckets`.
- [ ] **Copy presigned URL button** in the S3 browser (moved to Phase 3:
      belongs with signed share links, which need an owned signing path).

## 4. Phase 2 — The file manager (WebUI usable without an S3 client)

- [ ] Drag-and-drop upload in the S3 browser (browser-driven multipart with
      progress, checksums and quota enforcement).
- [ ] Inline previews for images/audio/video via HTTP Range; capped text/JSON
      preview.
- [ ] Object actions: rename, cross-bucket move, bulk select + delete.
- [ ] Full-text search over the catalog (SQLite FTS5 / Postgres tsvector).
- [ ] Folder auto-sync: inotify watcher on the job source root auto-enqueues
      new/changed files.

## 5. Phase 3 — Sharing, visibility and governance

- [ ] Share links: signed public object links with expiry, max-download
      count and optional password; rate-limited public route.
- [ ] Usage & health analytics: per-bucket/channel usage over time, daily
      upload volume, FloodWait-risk indicator, quota history charts.
- [ ] Prometheus `/metrics` endpoint (job states, quota usage, floods).
- [ ] WebSocket live logs and live job progress (replace polling).
- [ ] Two-person approval for destructive actions (owner gate #4).
- [ ] UploadPartCopy (S3 P2-E): server-side part copy for efficient
      rclone/boto3 large-object copies.

## 6. Phase 4 — Strategic bets

- [ ] **Client-side end-to-end encryption** (zero-knowledge): WebCrypto
      AES-GCM before upload; per-object keys wrapped by a passphrase-derived
      master key; opt-in per bucket. Design key-recovery UX first.
- [ ] **Content-addressed deduplication**: refcounted identical objects +
      skip-upload when the client sends the hash first; co-design with GC.
- [ ] **Cross-account replication**: write each object to a second Telegram
      account (the `parallel` strategy exists); satisfies owner gate #1 and
      de-risks physical GC.

---

## 7. Advanced S3 parity track

- [ ] Deliver [P2 Advanced S3](docs/S3_SPECS.md#5-p2-advanced-s3-implementation-plan)
      from the [116-operation compatibility matrix](docs/S3_SPECS.md):
      fail-closed selectors, advanced multipart/checksums, policies,
      encryption, lifecycle and independent client tests. Keep partial
      capabilities explicitly partial until verified.
- [ ] Extend trustworthy recovery of unknown original Telegram history beyond
      candidate markers without inventing metadata.
- [ ] Establish longer-duration real-environment capacity benchmarks on
      owner-controlled infrastructure.

## 8. Owner gates — physical GC prerequisites (BLOCKED_OWNER_ACTION)

- [ ] Independent backup host (Phase 6 replication or rclone export job).
- [ ] Authorized 1h soak on 2–8 HTTPS endpoints.
- [ ] Original-media recovery rehearsal with the owner's sealed SQL archive,
      Telegram credentials and real channel.
- [ ] Legacy cutover only when a real legacy source exists, or the explicit
      signed no-legacy exemption.
- [ ] Independent owner/operator approvals via
      `scripts/ops/verify_production_bundle.py`; never infer sign-off from
      synthetic CI fixtures.
- [ ] **Authorize physical GC** only after ALL gates pass; `deletion_permitted`
      stays False; no Telegram media has been deleted.

## 9. Release decision rules

- [ ] Any new release candidate requires all mandatory checks green on that
      exact SHA; previous green commits cannot be reused as proof.
- [ ] Review binaries, tag, release metadata and supported-feature limits
      before publication; do not silently publish unreleased `main` features.
- [ ] Keep automatic physical Telegram deletion disabled until its
      independent safety conditions are verified.

**Reference:** [Project Status and Acceptance](docs/IMPLEMENTATION_STATUS.md) · [CI and Test Guide](docs/CI_WORKFLOWS.md) · [Backup and Restore](docs/BACKUP_RESTORE.md) · [S3 Specifications](docs/S3_SPECS.md) · [Security](docs/SECURITY.md).
