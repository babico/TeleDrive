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

- [x] Drag-and-drop upload in the S3 browser (session-authenticated single-shot
      streaming PUT with XHR progress, quota enforcement and generation CAS;
      files above web.rest_max_upload_bytes use rclone/S3 multipart).
- [x] Inline previews for images/audio/video via HTTP Range; capped text/JSON
      preview (8 KiB cap, extension-based type detection).
- [x] Object actions: rename, cross-bucket move (metadata-level copy + delete),
      bulk select + delete, cross-bucket search.
- [ ] Content search inside object bytes (key search shipped; FTS5/tsvector
      only if key search proves insufficient).
- [x] Folder auto-sync: periodic idempotent scan of the job source root
      (jobs.watch / jobs.watch_bucket / jobs.watch_interval_seconds).

## 5. Phase 3 — Sharing, visibility and governance

- [ ] Share links: signed public object links with expiry, max-download
      count and optional password; rate-limited public route.
- [x] Usage analytics DONE: GET /api/v1/admin/storage/usage?days=N —
      daily published objects + bytes series (Python-side aggregation,
      portable and split-DB defensive); the dashboard renders a
      dependency-free hover bar chart of the last 30 days with totals.
- [x] Prometheus `/metrics` endpoint (done: `GET /api/v1/metrics`,
      text exposition format — job states, bucket quotas+usage, Telegram
      session health, flood observations and live cooldowns; scrape with
      the same HTTP auth as any API route).
- [x] WebSocket live logs DONE: /api/v1/logs/stream pushes the backlog
      plus every new entry (thread-safe queue handoff from _log, with
      main-loop bootstrap for lifespan-less harnesses);
      cookie-authenticated handshake, unauthenticated close 4401. The
      logs page Live mode uses the socket and falls back to 3s polling
      automatically when WS is unavailable (e.g. proxy without upgrade).
- [x] UploadPartCopy DONE: PUT ?uploadId&partNumber with a signed
      x-amz-copy-source copies another object as a multipart part.
      The part bytes are staged through Telegram exactly like a normal
      UploadPart (completion physically re-owns chunk rows per part, so
      object-level alias parts are impossible by design — the first
      attempt proved it and was replaced). Copy-source RANGES are
      deliberately unsupported, consistent with CopyObject. Verified
      with a real boto3 MPU flow against a live gateway listener
      (copy part + uploaded part -> complete -> byte-identical GET).

## 6. Phase 4 — Strategic bets

- [ ] **Client-side end-to-end encryption** (zero-knowledge): WebCrypto
      AES-GCM before upload; per-object keys wrapped by a passphrase-derived
      master key; opt-in per bucket. Design key-recovery UX first.
- [x] **Content-addressed deduplication** DONE: `put_file` performs one
      local hashing pass before uploading; an identical READY object
      (matched by full sha256) turns the upload into a fresh alias
      object via the same GC-aware alias mechanism CopyObject uses —
      ZERO Telegram bytes for duplicate content. Failures degrade to a
      normal upload; concurrent identical uploads may both miss
      (harmless). Internal staging uploads (multipart parts) pass
      `dedup=False` because completion physically re-owns chunk rows.
      REST/S3 PUT/POST-policy uploads all dedup; alias readback is
      round-trip verified.
- [x] **Cross-account replication** DONE: `storage.replica_account`
      (config, hot-reloaded with the runtime) sends every new object's
      chunks to a second Telegram account — forced-account sends never
      rotate away from the replica, journal intents re-open cleanly for
      re-sends. `storage_replica_chunks` records the replica messages;
      reads fall back to them when a primary chunk is unavailable;
      `POST /api/v1/admin/storage/replication/repair` re-sends missing
      replicas (digest-verified before re-send). Telegram page: target
      dropdown + coverage stats + repair button. Best effort: replica
      failures never fail the upload; an account missing from the
      loaded credential sets degrades to disabled (logged). Multipart
      part staging is not replicated (completion re-owns chunk rows);
      completed MPU objects are covered by repair.

---

## 7. Phase 5 — Multi-account Telegram storage

The transport layer already supports N accounts: per-account send slots,
shared FloodWait cooldowns (SQL-published across workers),
round_robin/failover/parallel strategies, cross-account retry on flood,
chunks tagged with the storing account. This phase is the management and
visibility layer on top — capacity, parallel speed and flood failover
come from simply authorizing more accounts.

- [x] Multi-session API: `GET /api/v1/admin/storage/telegram-sessions` —
      every account with usage (objects, bytes from `storage_chunks`),
      active cooldown remaining and lifetime flood observation count.
- [x] Per-account session delete:
      `DELETE /api/v1/admin/storage/telegram-sessions/{account}` with a
      soft-guard: accounts that still store chunks require `?force=true`
      (the catalog keeps the data, but new uploads stop using the
      account; reads need the session re-authorized). The legacy
      delete-all endpoint stays for compatibility.
- [x] Storage page: authorized-accounts table (account, masked phone,
      api_id, channel, strategy, objects, size, flood status, updated)
      with per-account delete. Adding another account = logging in with
      a different phone number in the session card.
- [x] Per-account SOFT QUOTAS (monitoring increment) DONE:
      telegram_sessions.soft_quota_bytes + PUT .../telegram-sessions/
      {account}/quota; the accounts table shows used-vs-quota with an
      OVER badge, Prometheus exposes the gauge.
- [x] Placement SOFT-QUOTA ENFORCEMENT DONE: the transport's account
      selection prefers under-quota accounts when the strategy's choice
      is over its soft quota (60s usage cache, best-effort — all-over
      or DB errors keep the strategy choice; uploads never fail on
      monitoring). Unit tests cover preference, all-over, single-label
      and degradation paths.
- [x] Bucket→account pinning DONE: bucket_account_pins table +
      GET/PUT/DELETE /api/v1/admin/storage/buckets/{bucket}/pin (the
      account must exist; viewer blocked; audit-logged). The engine
      publishes the current upload bucket via a ContextVar (no transport
      signature changes) and _select prefers the pinned account —
      explicit operator intent wins over strategy rotation and soft
      quotas; unavailable pins fall through to the normal routing.
      Buckets page: Pin button with an account dropdown (empty = clear).
- [ ] Account health probes: periodic `is_authorized` check per session,
      dead/expired session detection with a UI warning and re-login hint.
- [x] Strategy control from the UI: one cross-account routing selector
      in the accounts card (PUT /api/v1/admin/storage/strategy) with an
      immediate runtime hot-reload. The runtime also reloads after
      session add/delete and channel activation, so new accounts take
      effect without a container restart.

---

## 8. Advanced S3 parity track

- [ ] Deliver [P2 Advanced S3](docs/S3_SPECS.md#5-p2-advanced-s3-implementation-plan)
      from the [116-operation compatibility matrix](docs/S3_SPECS.md):
      fail-closed selectors, advanced multipart/checksums, policies,
      encryption, lifecycle and independent client tests. Keep partial
      capabilities explicitly partial until verified.
- [ ] Extend trustworthy recovery of unknown original Telegram history beyond
      candidate markers without inventing metadata.
- [ ] Establish longer-duration real-environment capacity benchmarks on
      owner-controlled infrastructure.

## 9. Owner gates — physical GC prerequisites (BLOCKED_OWNER_ACTION)

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

## 10. UI/UX & infrastructure overhaul — user feedback round (2026-10-21)

### Done
- [x] Docker: migrated from rootless to the system daemon (down without
      sudo, up with sudo), PUID/PGID=1000 so the uid owns ./config and
      ./data (cap_drop:ALL removes CAP_DAC_OVERRIDE — root cannot read
      a 600 file it does not own).
- [x] Docker: joined the machine-local `local-bridge` network via the
      gitignored docker-compose.override.yml (redis reachable,
      PING → +PONG verified from inside the container). The override
      file is intentionally NOT in git — machine-specific.
- [x] docker-compose.yml audited and rewritten: every key justified in
      one line, NEW stop_grace_period: 30s (Telethon disconnect + WAL
      checkpoint need more than the default 10s).

### Open — ordered by priority
- [x] S3 request logging bug FIXED (b56e264): outermost audit
      middleware on the S3 app; unsigned probes, failed signatures and
      browser attempts all land on the logs page with the SigV4 access
      key id as the user. Verified live on the S3 port.
- [x] Route/page restructure DONE (b56e264): nested paths with legacy
      redirects; one shared dynamic nav (grouped sub-menus) on every
      page; S3 credentials moved to their own page.
- [x] S3 SSL DONE (per-listener TLS + reverse-proxy mode): storage.
      s3_ssl_certfile/s3_ssl_keyfile give the S3 port direct HTTPS while
      the WebUI stays HTTP (or vice versa); web.trusted_proxy=true makes
      the app honor X-Forwarded-Proto (Secure cookies) behind a
      TLS-terminating proxy. Verified live with openssl self-signed +
      curl --insecure (S3 https 200, plain http rejected). Also fixed on
      the way: uvicorn captured TLS settings BEFORE the config reload
      (TLS silently dropped — now materialized first), missing `global`
      declarations, and three hardcoded /data paths that broke
      non-Docker deployments.
- [x] Checkboxes themed (accent-color) on every page.
- [x] S3 credential SECRET VIEWING DONE: GET /api/v1/admin/
      s3-credentials/{id}/secret (admin-only, audit-logged) decrypts and
      returns the secret on demand; credentials page gained a Show
      secret button with a confirm + warning box. Revoked credentials
      and unknown ids are rejected; master-key changes surface as a
      clear error.
- [x] Permission UI modernization DONE: the S3 credential grids
      (create + edit) are grouped into explained categories (Read,
      Write objects, Object tagging, Bucket administration,
      Compatibility probes) with per-group tooltips and select-all
      toggles; all 39 permissions verified covered by script.
- [x] S3 credential EDITING DONE: PUT /api/v1/admin/s3-credentials/{id}
      edits name, permission set and expiry of ACTIVE credentials
      (revoked ones are immutable; access key and secret never change —
      rotation stays a new-credential flow). Credentials page gained an
      inline editor.
- [x] S3 sub-menu + bucket browser DONE (/s3/buckets): upload,
      download, inline previews, rename/move/copy, bulk delete,
      cross-bucket search, per-bucket quotas, and now PRESIGNED GET
      links — server-side SigV4 query signing (secret never leaves the
      process), verified end to end against the live gateway including
      signature-tamper rejection.
- [x] API management: documentation card with /docs, /redoc,
      openapi.json, GitHub docs and the S3 compatibility matrix.
- [x] Dashboard enrichment DONE: Telegram accounts card (per-account
      objects, size, live flood cooldown, health verdict) with the
      active routing strategy and an unresolved-alerts badge; existing
      quota bars and job stats stay.
- [ ] CI overhaul — CONTENT, not just names. Increment 1 DONE
      (naming scheme + the two Integration workflows genuinely merged
      into CI 2). Increment 2 DONE: the Docker build + single-container
      smoke + Trivy scan moved out of CI 1 into a dedicated CI 3 image
      job, leaving CI 1 as pure static analysis / security audit /
      unit tests; meta tests migrated first. The CI 1 vs CI 5 pytest
      overlap is INTENTIONAL and stays: CI 5 is the release gate and
      must re-verify the exact tagged commit, not trust a main-branch
      run. Proposed target structure
      (one concern per workflow, no overlap, consistent naming
      "CI N · <Area> — <Scope>"):
      1. CI 1 · Static — lint, compile, dependency audit, secret scan
         (merge from 01 Quality; keep quality-security.yml path).
      2. CI 2 · Unit & Contract — the offline storage/S3/API suite
         currently split between 01 and 05 (deduplicate the two
         pytest invocations).
      3. CI 3 · Integration — REST+S3 and Databases in one matrix
         workflow (merge 02a+02b).
      4. CI 4 · Image — Docker build, image scan, smoke probe, the
         fault-injection suite from 03.
      5. CI 5 · Live E2E — user + multiworker Telegram jobs (keep the
         manual dispatch gates).
      6. CI 6 · Delivery — release gate + packages (05).
      Execution notes: update tests/meta/test_ci_workflows.py to the
      new names/paths FIRST (it asserts names), keep workflow FILE
      paths stable to preserve run history where possible, renumber
      the display names, and delete jobs that only duplicate another
      workflow's pytest invocation.
- [x] Menu-wide consistency DONE: every destructive action across all
      pages goes through one confirmDelete helper with the same
      phrasing pattern ("Delete X?" + consequence hint + audit note),
      including the physical-GC owner-gate reminder on object deletes.

## 11. Release decision rules

- [ ] Any new release candidate requires all mandatory checks green on that
      exact SHA; previous green commits cannot be reused as proof.
- [ ] Review binaries, tag, release metadata and supported-feature limits
      before publication; do not silently publish unreleased `main` features.
- [ ] Keep automatic physical Telegram deletion disabled until its
      independent safety conditions are verified.

**Reference:** [Project Status and Acceptance](docs/IMPLEMENTATION_STATUS.md) · [CI and Test Guide](docs/CI_WORKFLOWS.md) · [Backup and Restore](docs/BACKUP_RESTORE.md) · [S3 Specifications](docs/S3_SPECS.md) · [Security](docs/SECURITY.md).
