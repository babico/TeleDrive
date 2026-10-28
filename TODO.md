# TeleDrive TODO & Roadmap

> **Purpose:** the single prioritized plan — completed milestones, active
> work, product roadmap, S3 parity track and owner gates. For decisions and
> evidence limits, see [Project Status](docs/IMPLEMENTATION_STATUS.md). For
> commands and CI contracts, see [CI and Test Guide](docs/CI_WORKFLOWS.md).
> Product/feature analysis that produced the roadmap phases:
> `.opencode/teledrive/10x/session-1.md` (git-ignored).
> Last audited: 2026-10-28 (tree at `45d40ff`). The last all-six-automatic-workflows
> green run recorded here is on `9c4769d`; later commits carry their own test
> evidence in their commit messages and must not inherit that green status.

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
- [x] **Copy presigned URL button** in the S3 browser DONE: per-object
      "Link" action opens the presign dialog (expiry selector, server-side
      SigV4 GET URL, audit-logged, one-click Copy URL).

## 4. Phase 2 — The file manager (WebUI usable without an S3 client)

- [x] Drag-and-drop upload in the S3 browser (session-authenticated single-shot
      streaming PUT with XHR progress, quota enforcement and generation CAS;
      files above web.rest_max_upload_bytes use rclone/S3 multipart).
- [x] Inline previews for images/audio/video via HTTP Range; capped text/JSON
      preview (8 KiB cap, extension-based type detection).
- [x] Object actions: rename, cross-bucket move (metadata-level copy + delete),
      bulk select + delete, cross-bucket search.
- [x] Content search inside object bytes DONE: full-text search over
      text-extractable uploads (extension-gated, 512 KiB extraction
      cap, NUL-byte binary rejection). teledrive/storage/
      content_index.py is dialect-aware: FTS5 virtual table on SQLite,
      generated tsvector ('simple', GIN index) + ts_headline on
      PostgreSQL — both answer (object, snippet) pairs with consistent
      [ ] match markers, and FTS5 query tokens are always quoted so
      user input can never parse as operators. The engine indexes at
      upload time from the still-local staged source (zero Telegram
      round-trips); GET /api/v1/admin/storage/search?mode=content
      returns matches joined to CURRENT heads (unlinked objects never
      appear); POST .../search/reindex backfills existing objects
      (downloads only the extraction cap per object, marks non-text
      objects as examined). UI: In keys / In file contents mode select
      with a Match snippet column and a Reindex button. Verified on
      real PostgreSQL (teledrivetest) and SQLite.
- [x] Folder auto-sync: periodic idempotent scan of the job source root
      (jobs.watch / jobs.watch_bucket / jobs.watch_interval_seconds).

## 5. Phase 3 — Sharing, visibility and governance

- [x] Share links DONE: signed public object links —
      POST /api/v1/admin/storage/buckets/{bucket}/shares creates a
      192-bit token URL bounded by expiry (60s..30d, optional), download
      count (CAS-claimed before streaming, optional) and an optional
      password (PBKDF2-HMAC-SHA256 200k, constant-time compare).
      GET/POST /share/{token} streams the object unauthenticated with a
      minimal dark HTML password form (urlencoded, no extra deps);
      invalid/expired/exhausted/revoked states answer a uniform 404.
      Per-IP sliding-window rate limit (60/min). Admin listing with live
      status + revocation (audit-logged). S3 browser: per-object Share
      action with expiry/count/password fields and a share management
      table with revoke.
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

- [x] **Client-side end-to-end encryption** (zero-knowledge) DONE:
      `web/static/teledrive-crypto.js` — WebCrypto AES-256-GCM in the
      browser before upload; PBKDF2-SHA256 (310k iterations,
      per-encryption random salt + IV) derives a non-extractable key
      from the user's passphrase. The blob is self-describing
      ("TDENC1" magic + version + iterations + salt + IV 39-byte
      header) so the server needs ZERO changes and sees only opaque
      bytes — true zero-knowledge, no key material ever transmitted.
      Opt-in per upload batch (checkbox + passphrase in the drop
      zone); download auto-detects encrypted blobs, prompts and
      decrypts client-side; 🔒 badges (localStorage) on known-encrypted
      objects; preview is blocked for them. Wrong passphrase and
      tampered bytes fail closed (GCM authentication). Key-recovery
      UX: an explicit unrecoverable-passphrase warning before upload —
      by design there is nothing to recover. Node-verified round-trip
      test suite (tests/web/test_e2e_crypto.py, CI 1 + release gate).
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
- [x] Account health probes DONE: `telegram_session_health_loop`
      probes every session every 30 minutes (connect + is_authorized),
      stores the authorized flag + health_checked_at, logs the moment a
      previously-healthy session dies, and the accounts card shows
      OK/UNAUTHORIZED with the last check time and a re-login hint;
      on-demand probe via POST .../telegram-sessions/{account}/
      health-check.
- [x] Strategy control from the UI: one cross-account routing selector
      in the accounts card (PUT /api/v1/admin/storage/strategy) with an
      immediate runtime hot-reload. The runtime also reloads after
      session add/delete and channel activation, so new accounts take
      effect without a container restart.

---

## 8. Advanced S3 parity track

- [x] Deliver [P2 Advanced S3](docs/S3_SPECS.md#5-p2-advanced-s3-implementation-plan)
      from the [116-operation compatibility matrix](docs/S3_SPECS.md):
      fail-closed selectors, advanced multipart/checksums, policies,
      encryption, lifecycle and independent client tests. Keep partial
      capabilities explicitly partial until verified. STATUS (evidence
      on the current SHA): P2-0 done (manifest + route guard); P2-1
      done (UploadPartCopy shipped with boto3-verified INCLUSIVE
      copy-source ranges; manifest now says 13 supported / 43 partial /
      60 unsupported — GetBucketLocation and UploadPartCopy honestly
      promoted, deprecated lifecycle aliases documented);
      P2-2 decided and shipped (immutable private-only model: honest
      AWS-shaped compat reads, 501 writes); P2-3/P2-4/P2-5 remain
      intentionally unsupported (fail-closed) per the spec's "no fake
      AWS semantics" rule. Checklist items closed: adversarial
      selector sweep (manifest-driven: every one of the 60
      unsupported operations is hit with a VALID signature and proven
      non-2xx, non-mutating, zero-Telegram — a mapping test keeps
      future operations from being skipped silently) and the
      version-pinned client matrix (boto3 + AWS CLI + rclone v1.66.0,
      pinned in CI). Partial→feature promotions this round:
      DeleteObjects per-entry VersionId (AWS per-entry Deleted/Error
      semantics: unknown versions report NoSuchVersion inside a 200
      response), UploadPartCopy copy-source ranges (signed, inclusive,
      416 on out-of-range), and aws-chunked streaming upload bodies
      (teledrive/s3/aws_chunked.py: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
      chunk-signature chains verified against the request's own
      Authorization seed, STREAMING-UNSIGNED-PAYLOAD-TRAILER with
      declared+verified trailer checksums, decoded-length accounting;
      wired into PutObject and UploadPart; a live-view bytearray regex
      bug was found and fixed on the way). Real-bug fixes:
      CreateBucket is now idempotent for existing owned buckets (AWS
      us-east-1 semantics) — rclone's DEFAULT pre-upload bucket
      preparation previously failed with 400; the default-config
      rclone flow (mkdir, nested copyto, ls, byte-identical cat, size,
      delete) is now a live regression test. Remaining open checklist
      items (per-op exhaustive normal/malformed/retry/race/crash
      coverage, both-DB mutation invariants, migration/rollback docs)
      stay tracked in the spec's engineering checklist.

      Historical snapshot: that paragraph quotes the counts at the time it
      was written. The metadata-parity and full-coverage phases superseded
      them; the current inventory is **93 supported / 7 partial (all by
      design) / 16 unsupported** (§13).
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
- [x] CI overhaul — CONTENT, not just names. DONE (two increments +
      final structure): CI 1 · Quality (static analysis, security,
      unit tests; quality-security.yml), CI 2 · Integration (REST, S3
      & Databases matrix; integration-storage.yml, unfiltered at every
      commit SHA), CI 3 · Image & Resilience (build, scan, smoke,
      fault injection; resilience-docker.yml), CI 4 · Live E2E
      (Telegram USER + Multiworker PostgreSQL, manual dispatch gates),
      CI 5 · Delivery (release gate & packages; re-verifies the tagged
      commit — the CI 1/CI 5 pytest overlap is INTENTIONAL), CI 6 ·
      Endurance (isolated capacity soak). Meta tests were migrated
      first and assert the names; every regression module must be
      scheduled by a real workflow (enforced).
- [x] Menu-wide consistency DONE: every destructive action across all
      pages goes through one confirmDelete helper with the same
      phrasing pattern ("Delete X?" + consequence hint + audit note),
      including the physical-GC owner-gate reminder on object deletes.

## 13. Metadata-backed parity program (2026-10-25)

Full design: [docs/METADATA_PARITY_PLAN.md](docs/METADATA_PARITY_PLAN.md).
Stance change: an emulated feature is honest when it has real SQL
state, enforcement on every violating path, and GET observability —
the backing is TeleDrive metadata, not AWS infrastructure. Phases in
dependency order, each independently shippable; A and B first.

- [x] **Phase A — GC-integrated deletes** DONE: storage_gc_queue +
      grace_seconds (on storage_gc_state, defensively ALTERed for
      existing deployments); DeleteObject(versionId), DeleteObjects
      per-entry versions and AbortMultipartUpload enqueue their media
      for grace-fenced physical collection when GC is enabled
      (disabled GC keeps journal-retention behavior); lifecycle rules
      gained Expiration (Days 1..3650, ExpiredObjectDeleteMarker,
      Prefix) alongside AbortIncompleteMultipartUpload, with the
      hourly evaluator creating delete markers for due current objects
      and enqueueing their media; queued collection scope in the
      collector drains the queue (collected + stale-skipped entries
      removed, failures retried); the GC card shows queue depth,
      grace and the queued scope. gc-owner-gate is now a RESOLVED
      design reason — 8 operations promoted to Supported. Inventory:
      **27 supported / 29 partial (0 by code) / 60 unsupported**.
- [x] **Phase B — bucket versioning states** DONE: storage_buckets
      gained versioning_state (Enabled default | Suspended, defensively
      ALTERed into existing deployments); PutBucketVersioning accepts
      real transitions (MFADelete still rejected — no MFA backing);
      GET reports the true state. In Suspended buckets a new write
      REPLACES the current version — the superseded version retires
      from the journal (removed_versions) in the same transaction —
      and DELETE removes the head without a marker (AWS
      unversioned-style semantics, no version-id headers); pre-
      suspension history is retained and versioning resumes appending
      when re-enabled. versioning-model is a RESOLVED design reason —
      2 operations promoted to Supported. Inventory: **29 supported /
      27 partial (0 by code) / 60 unsupported**.
- [x] **Phase C — object lock** (`839687c`): retention_until_ns/
      legal_hold columns on storage_objects (defensive ALTER),
      object_lock_enabled + default mode/days on storage_buckets;
      bucket-level one-way enable (lock can never be disabled, default
      only extendable), default retention applied to every new version
      at publish time; retention (COMPLIANCE extend-only) and legal
      hold with GET/PUT on current or selected published VersionId;
      enforcement on EVERY delete path — delete_version, batch
      per-entry deletes (AccessDenied inside the 200 DeleteResult),
      the GC queue consumer and lifecycle expiration all refuse
      locked/held versions; GOVERNANCE bypass header rejected 501
      (no governance-elevation model). 6 operations promoted
      (3 partial conversions + 3 P2-B writes). Inventory: **35
      supported / 24 partial (0 by code) / 57 unsupported**.
- [x] **Phase D — ACL grants** (`2f0b2ed`):
      storage_bucket_acl_grants + storage_object_acl_grants (grantee =
      CanonicalUser access key, READ/WRITE/FULL_CONTROL; owner implicit
      FULL_CONTROL row). PutBucketAcl/PutObjectAcl replace the stored
      ACL from AWS-shaped AccessControlPolicy XML (grantees validated
      as active credentials; email/group grantees rejected 501 — the
      private-only line; WRITE invalid on object ACLs). Enforcement is
      the fail-closed intersection: own SigV4 scopes first, then the
      resource ACL may only NARROW — a credential is denied when the
      bucket or exact key has a stored ACL and its grants for this
      access key do not cover the action class (READ = Get*/List*,
      WRITE = everything else). Object grants only affect their exact
      key, never siblings or bucket-level actions. Gate covers header
      auth, presigned queries and browser form uploads; ACL-less
      resources keep the unrestricted baseline; unknown ACL-scope
      credentials denied at auth. 4 operations promoted (2 partial
      conversions + 2 P2-C writes). Inventory: **39 supported / 22
      partial (0 by code) / 55 unsupported**.
- [x] **Phase E — PAB/policy status/ownership controls** (`6c30715`):
      storage_buckets.public_access_block (4 boolean JSON,
      default all-true; defensive ALTER) + object_ownership
      (BucketOwnerEnforced). PutPublicAccessBlock persists any flag
      combination (deliberate owner decision); BlockPublicAcls=on
      pins bucket AND object ACL authoring to the stored ACL owner
      (a real guard over the Phase D grant store — grantee takeovers
      are fenced). GetBucketPolicyStatus computes IsPublic from the
      actual stored grants + PAB flags (IgnorePublicAcls implements
      the AWS ignore semantics; validated access-key grantees keep
      the honest answer false). GetBucketOwnershipControls reads the
      persisted ownership state from bucket metadata; ownership
      writes fail closed 501. 4 operations promoted. Inventory: **43
      supported / 18 partial (0 by code) / 55 unsupported**.
- [x] **Phase F — notifications + logging** (`8b1bf9e`): real
      per-bucket webhook notification config (SQL, encrypted secret,
      owner-approved HTTP(S) destinations only — SQS/SNS/Lambda return an
      honest 501) and a transactional event outbox written in the SAME
      SQL transaction as every covered mutation (publish, copy, form
      upload, multipart complete/abort, delete marker, version
      revocation). A scheduler loop delivers with exponential backoff,
      bounded attempts and an HMAC signature. Event vocabulary:
      ObjectCreated:{Put,Copy,CompleteMultipartUpload,Post} and
      ObjectRemoved:{Delete,DeleteMarkerCreated} plus their wildcards.
      Get/PutBucketLogging store and return the real target (bucket +
      prefix); delivering audit-log OBJECTS into the target bucket is an
      explicit documented gap, not claimed. DDL runs at startup and in
      the store constructor only — issuing it inside the mutation hot
      path deadlocked SQLite against the caller's write lock. 6
      operations promoted. Inventory: **54 supported / 12 partial (0 by
      code) / 50 unsupported**.
- [x] **Phase G — replication API surface** (`ef19ee3`): real
      per-bucket replication config mapped onto the EXISTING
      storage-engine cross-account replication — `Destination/Bucket`
      names a configured TeleDrive credential set, never an AWS ARN;
      prefix filters are resolved per object at upload and again at
      repair; overlapping enabled rules are rejected (one replica per
      chunk). Unsupported AWS options (DeleteMarkerReplication,
      ReplicaModifications, storage classes, metrics, RTC) are rejected
      501 instead of silently ignored; `Role` is opaque metadata (no
      IAM). GET returns the real config or an honest 404. 3 operations
      promoted. Inventory: **48 supported / 15 partial (0 by code) / 53
      unsupported**.
- [x] **Phase I — website hosting** (`38209bc`): per-bucket
      index/error documents in `storage_website_configs`, served
      anonymously at `/site/{bucket}/...` ONLY when the bucket's
      `public_read` gate is on — a default-false column that only an
      admin (not operator, not an S3 credential) can flip, audit-logged.
      Serving resolves current ready heads only (no staging, no delete
      markers, no history), implements directory-index and error-document
      semantics, never lists directories, rejects traversal/absolute
      paths and serves an inert sandboxed CSP (`default-src 'none'`, no
      same-origin access to the app). DeleteBucketWebsite clears the
      config AND the gate together, and bucket deletion cleans up both.
      RedirectAllRequestsTo/RoutingRules return an honest 501. 3
      operations promoted. Inventory: **60 supported / 8 partial (0 by
      code) / 48 unsupported**.
- [x] **Phase H — CORS grammar widening** (`fd25e52`): one `*`
      anywhere in the host (`*.example.com`, `api-*.example.com`)
      matching exactly one DNS label — never a dot, slash or scheme, so
      a lookalike suffix can never be echoed; the complete method set
      (GET/HEAD/PUT/POST/DELETE), AllowedHeader/ExposeHeader globs, and
      MaxAgeSeconds with the artificial 24-hour ceiling removed (AWS
      documents none). Origin and header patterns are compiled once and
      LRU-cached instead of rebuilt per preflight. CORS remains browser
      policy only, never authentication. 2 operations promoted.
      Inventory: **45 supported / 16 partial (0 by code) / 55
      unsupported**.
- [x] **Phase J — tagging scope** (`cac820b`): deferred tag
      journal. `Put/DeleteObjectTagging` on the current head's pending
      generation now journals into `storage_pending_tags` instead of
      refusing; `BucketCatalog.publish` applies the journal in the SAME
      transaction as the head CAS (rollback takes the tags with it), and
      the journal is never exposed by `GetObjectTagging` — a
      non-published version still answers NoSuchVersion, so staging is
      not addressable through tags. Journal rows are reclaimed on
      version revocation, physical GC collection and bucket deletion.
      3 operations promoted. Inventory: **57 supported / 9 partial (0 by
      code) / 50 unsupported**.
- [x] **Full S3 coverage plan — phases L, N and O** (`4831a67`, fixed
      by `2e461d1`): policy engine + ABAC + real ownership models (8
      ops), analytics/inventory/metrics configurations with real report
      generation (12 ops), and rename/select/restore/annotations plus
      the only-real-state RequestPayment/Accelerate writes (9 ops). 29
      operations promoted. Inventory: **89 supported / 7 partial (all by
      design) / 20 unsupported**.
- [x] **Phase N5 + O1 — access tracking, tiering and RestoreObject**
      (`f341691`, wire shape fixed by `45d40ff`): real access counters,
      a scheduler that transitions `storage_class`, a 403
      `InvalidObjectState` gate on archived objects and a bounded restore
      window. No Telegram byte moves; documented as an access gate, not
      Glacier. Inventory: **93 supported / 7 partial / 16 unsupported**.
- [ ] **Full S3 coverage plan — remaining phases** — see
      [S3_FULL_COVERAGE_PLAN.md](docs/S3_FULL_COVERAGE_PLAN.md).
      Still open: O3 bucket metadata journal (9 ops) and M1
      SSE-C/SSE-S3 (8 ops, `PutBucketEncryption` pair and
      `UpdateObjectEncryption`). The plan quotes a target of **112
      supported / 0 partial / 4 unsupported**; note that
      RequestPayment and Accelerate are listed there as kept by design,
      so the honest reachable end state is 110 supported / 2 partial / 4
      unsupported unless those two read probes are also promoted. The 4
      permanently impossible operations (BitTorrent swarm, S3 Express
      directory buckets, Object Lambda) stay unsupported.
- [ ] **S3 governance WebUI page (`/s3/governance`)** — one page over the
      SQL state the API already uses: policy, ownership, PAB, object-lock
      defaults, website gate, notifications, replication, tiering and
      report configurations. It is being built in parallel; the README
      describes it as the intended surface. Nothing on the S3 API depends
      on it.
- [ ] **Phase K — SSE envelope** (owner decision, conflicts with
      dedup/replication/search). Converts 1.
- Kept by-design forever: RequestPayment, Accelerate — no honest
  backing exists (billing/network).

## 12. User feedback round 2 (2026-10-23)

- [x] **By-code partial closures (round 3)** DONE — the LAST by-code
      gap is closed and section 3.2 is now EMPTY: presigned CopyObject
      works through SigV4 query authentication with the source header
      and the empty-body digest bound into the signature (a leaked URL
      cannot be replayed against a different private source; expiry
      and tamper checks shared with all presigned URLs). Inventory:
      **19 supported / 37 partial (0 by code, 37 by design) / 60
      unsupported** — every remaining partial is an architectural
      (fail-closed) decision, nothing is "just missing code" anymore.
- [x] **API permission catalog descriptions** DONE: the registry now
      derives per-route summaries from the live FastAPI route table
      (zero drift) and ships 73 curated group descriptions; the
      permission picker shows each group's purpose under its header
      and a one-line summary next to every method+path row. The
      catalog is restricted to the JSON API surface (HTML pages are
      session views, not permissionable endpoints).
- [x] **Triage and land the open GitHub PRs** DONE (2026-10-26).
      All three were branched from older main states and **all three
      are closed as superseded**, with comments pointing at the main
      commits that carry their intent — nothing unique was lost and no
      stale surface was re-merged:
      - **#25** — its gc_collect.py change (static SQL instead of an
        interpolated `base` predicate) is already on main in a stronger
        form (`288520e`: fully static statements + `# nosec B608` with
        justification at each site, CI 1 Bandit green). The doc
        reconciliation landed as `398de8b`.
      - **#24** — the six-automatic-workflows wording was applied
        directly on main as `398de8b` (README, CI guide, TODO,
        IMPLEMENTATION_STATUS) with the audit pointer refreshed to
        `9c4769d`.
      - **#22** — `is_connected()` is already synchronous in main, the
        config-driven job-root test semantics (403/503/422) are already
        asserted against `webapp.JOB_SOURCE_ROOT`, and its verification
        report carried stale SHAs and stale S3 counts. The doc count
        correction it also carried is in `398de8b`.
      Decision rule applied: **preserve the newest main**, never
      blind-merge a branch that predates five metadata-parity phases.

- [x] **Unified per-endpoint permissions for EVERY API route** DONE.
      The permission registry is derived from the live FastAPI route
      table (method + path template — it can never drift); the 9 REST
      bearer endpoints keep their curated short names, every other
      route carries a canonical "method:path" permission. require_auth
      accepts bearer API keys on ANY route when the key holds exactly
      that route's permission (no role policy for keys; session/Basic
      behavior unchanged). admin:* stays a legacy REST wildcard that
      does NOT unlock admin routes. Key creation validates against
      registry ∪ legacy scopes; the API management UI builds a
      per-endpoint grid with select-all/category shortcuts. This is
      the foundation for permission-group-based user management.
- [x] **GC status, toggle and physical/logical metrics in the UI** DONE.
      GET /api/v1/admin/storage/gc (state + logical vs physical
      objects/bytes + reclaimable backlog + collected totals); PUT
      toggles GC behind typed confirm "PHYSICAL-GC" with loud audit;
      POST /gc/collect dry-runs the fail-closed candidate set
      (scope=revoked: version-revoked objects; scope=deleted: also
      delete-marker/unlinked keys — never historical versions of live
      keys, never dedup-alias sources) and executes with confirm
      "DELETE-RETAINED" only when enabled. Execution re-verifies each
      candidate, deletes Telegram messages through the new
      UnifiedUserTransport.delete, journals into storage_gc_collected,
      drops chunk rows and hides the object from history and dedup.
      Dashboard gained a Physical GC card (state badge, logical/
      physical/retained/collected metrics, scope selector, preview,
      collect). The gc-owner-gate is now an explicit owner-controlled
      UI toggle rather than a hardcoded False.
- [x] **By-code partial closures (round 1)** DONE: per-object Owner in
      ListObjects (V1 always) and ListObjectsV2 (fetch-owner=true,
      route-guard allowlisted); CopyObject date-based copy-source
      conditions (if-(un)modified-since with AWS precedence and
      malformed-date rejection); CompleteMultipartUpload COMPOSITE
      SHA-256 validation from staged part digests + per-part
      ChecksumSHA256 verification + checksum echo in the result XML;
      UploadPart's stale spec row corrected (CRC64NVME was already
      verified).
- [x] **By-code partial closures (round 2)** DONE: ListObjectVersions
      delimiter grouping (CommonPrefixes share the max-keys budget
      exactly like AWS, NextKeyMarker carries the cut) and
      encoding-type=url — now fully SUPPORTED; CopyObject inclusive
      ranged copy-source (bytes=first-last, 416 InvalidRange,
      destination staged as a NEW payload through Telegram with
      REPLACE metadata/tags applied on publish); CompleteMultipartUpload
      FULL_OBJECT checksums (SHA-256/SHA-1/CRC32/CRC32C/CRC64NVME over
      the assembled bytes in one streaming pass) and non-SHA COMPOSITE
      modes (CRCs from concatenated little-endian per-part values) —
      now fully SUPPORTED. Non-SHA declarations require an explicit
      x-amz-checksum-type. Inventory: 18 supported / 38 partial (1 by
      code, 37 by design) / 60 unsupported. Sole remaining by-code gap:
      presigned CopyObject.
- [x] **API management + S3 credentials page redesign** DONE (owner
      feedback: the pages looked terrible). Both pages rebuilt on the
      GitHub/Stripe token-page pattern: create flows hidden behind a
      Generate button; expiry PRESETS (7d/30d/90d/1y/never/custom);
      permission pickers as grouped collapsible cards with per-group
      tri-state toggles, selected counters and (API page) a search box
      filtering by method/path/description; HTTP METHOD chips (GET
      green, POST blue, PUT amber, DELETE red); key tables show
      permission chips with +N overflow, relative timestamps, expiry
      and status badges (active/expired/revoked), last-used; secret
      reveals are amber callouts with separate copy buttons and an
      explicit "Done — I saved it" dismissal; REST keys gained a
      Rotate action (backend existed, UI did not expose it).
- [x] **Research: ACL-style grants through S3 credentials** DONE —
      design documented in the spec's P2-C group. Grantee
      CanonicalUser maps to an S3 access key's owner identity; bucket/
      object grants stored per (bucket, grantee, permission);
      enforcement is a fail-closed INTERSECTION with the credential's
      own scopes (ACLs can only narrow, never expand); no public/
      group/email grantees (private-only unchanged). Bounded work
      (one table, two XML parsers, one enforcement hook) — awaiting
      owner approval to implement best-effort.
- [x] **Dashboard/history vs bucket-browser inconsistency** FIXED
      (owner report: "uploaded 2 objects, deleted them — still visible
      in the dashboard, gone from the bucket browser, nothing in
      history"). GC itself is correctly OFF (owner-gated;
      deletion_permitted=False — Telegram media retention is BY
      DESIGN, that part is not a bug). What WAS wrong:
      a) FIXED: the accounts card counted PHYSICAL storage
         (storage_chunks per account) — deleted-but-retained objects
         kept counting. It now shows CURRENT (heads-joined)
         objects/bytes plus a separate retained (GC-reclaimable)
         backlog line labeled as such ("+N retained" / "clean").
      b) FIXED: the History page only listed terminal upload JOBS —
         S3-browser uploads never create jobs and object version /
         delete-marker history was invisible. New admin endpoint
         GET /api/v1/admin/storage/versions (published versions +
         delete markers, bucket-filterable, newest first) and an
         "Object versions" section on the History page with a bucket
         selector, type (version/delete marker), size and current/
         historical state.
- [x] **S3 spec: reason groups + full-support recommendations** DONE.
      Section 3.3 now documents the five by-design reason groups
      (private-only, gc-owner-gate, versioning-model, tagging-scope,
      cors-grammar) with a "To fully support" recommendation per group
      (policy engine, GC gate opening, versioning-state column,
      write-fence tradeoff, grammar widening). Section 4 groups
      (P2-C/B/D/E/F, P3-G/H) each carry a concrete best-effort
      recommendation: policy engine on the credential-principal model;
      envelope-encryption SSE (conflicts with dedup/replication) and
      SQL-level retention; exposing the EXISTING storage-engine
      replication through the S3 replication API; P2-E now empty
      (UploadPartCopy shipped); notifications-first for P2-F behind a
      public-mode owner decision; P3-G as conventional report
      schedulers; P3-H mostly unmappable (keep unsupported).
- [x] **Per-endpoint API key permissions** DONE. Every REST bearer
      endpoint is individually permissionable: 9 fine-grained
      permissions (rest:buckets:list/create/delete,
      rest:objects:list/list-versions/get/head/put/delete) with a
      machine-readable registry (ENDPOINT_PERMISSIONS + descriptions
      doubling as UI labels). LEGACY grouped scopes remain valid and
      expand to their endpoint sets — existing keys work unchanged;
      admin:* expands to everything. authorize() checks the expanded
      set. New catalog endpoint GET /api/v1/admin/keys/permissions;
      the API management UI builds a per-endpoint checkbox grid from
      it with select-all/category shortcuts and a collapsible legacy
      section. A drift test proves every require_api_scope call site
      uses a registered permission.

## 14. Remaining work after 1.0.8

Nothing here is required for the release to be correct; it is the honest
backlog that the release notes link to.

### 14.1 Open refactor backlog

[Codebase Review](docs/CODEBASE_REVIEW.md) §4 lists fifteen items. Items 1, 2, 3, 5 and 6 are closed with regression tests
(`9c4769d` for the key-delegation ceiling, the batch/copy ACL gate, the
admin-only GC gate and the immutable ACL owner; `4365694` for audit identity
spoofing). The rest are still open:

- [ ] **#4 Bucket delete leaves orphan metadata** — `delete_bucket` does not
      remove `storage_bucket_acl_grants`, `storage_object_acl_grants`,
      `bucket_quotas`, `bucket_account_pins` or `share_links`. Re-creating a
      bucket with the same name can revive old grants. This is a security
      bug, not cosmetics (O10).
- [ ] **#7 Schema init race and scattered migrations** — every store
      constructor calls `create_all` outside the schema lock, and manual
      ALTERs stand in for a migration system. See 14.2.
- [ ] **#8 MySQL SQL leaks** — `ON CONFLICT` in the quota and pin upserts
      and `INSERT OR IGNORE` in the reindex path still fail on MySQL,
      although README and CI list MySQL as supported (O9).
- [ ] **#9 Three permission catalogs** — `ENDPOINT_PERMISSIONS`,
      `CURATED_PERMISSIONS` and handler string literals still duplicate the
      same nine REST permissions.
- [ ] **#10 Canonical `Principal`/`authorize`** — the session, Basic, bearer
      and S3 paths remain separate decision points.
- [ ] **#11 Split `web/app.py`** — still one large router module.
- [ ] **#12 Split `web/s3.py`** — dispatch still lives in one file.
- [ ] **#13 Raw `text()` in `web/app.py`** — users, sessions, quota, pin and
      share still bypass a store layer.
- [ ] **#14 Missing indexes/FKs** — `aliases.source_object_id` and the
      version/bucket FKs are still unindexed or absent.
- [ ] **#15 Dead/duplicate helpers in `user_mode.py`** —
      `_session_from_file` and the first `_session_from_file_for` remain
      defined and unused.

### 14.2 Schema-initialisation race (O4/O6)

[Codebase Review](docs/CODEBASE_REVIEW.md) files this as **O6** in §2.2
("schema-init race") and as **O4** in the §0.1 status table; both names
refer to the same defect. Only `_setup_schema` takes a PostgreSQL advisory
lock. `BucketCatalog`, `ManifestStore`, `StorageUploadJobs`, `ApiKeyStore`,
`S3CredentialStore`, `MultipartStore`, `MtprotoRateGuard`,
`UserSessionRuntime` and `RetainedMediaGC` all call `create_all` outside it,
and `ensure_versioning_column` is guarded only by a process-local flag. Two
workers starting together can race `CREATE TABLE` and a double `ALTER TABLE`.
This needs a migration baseline and a cross-process lock, not a patch.

### 14.3 Open design decisions

Both change the backward-compatibility contract, so neither was fixed
silently.

- [ ] **P5 — session/bearer asymmetry.** A viewer session can read every GET
      API route, while an API key for the same user needs an explicit
      permission per route. "Viewer" therefore means two different things.
      The decision is whether sessions should shrink to the route
      permission set or bearer keys should gain a role-derived default.
- [ ] **P6 — legacy HTTP Basic is unconditional admin.** The configured
      `web.user`/`web.password` bypasses the database user and role system.
      Keeping it for scripts is defensible, but it needs a separate
      principal identity and an additional guard on admin-only routes, or
      removal.

## 11. Release decision rules

- [ ] Any new release candidate requires all mandatory checks green on that
      exact SHA; previous green commits cannot be reused as proof.
- [ ] Review binaries, tag, release metadata and supported-feature limits
      before publication; do not silently publish unreleased `main` features.
- [ ] Keep automatic physical Telegram deletion disabled until its
      independent safety conditions are verified.

**Reference:** [Project Status and Acceptance](docs/IMPLEMENTATION_STATUS.md) · [CI and Test Guide](docs/CI_WORKFLOWS.md) · [Backup and Restore](docs/BACKUP_RESTORE.md) · [S3 Specifications](docs/S3_SPECS.md) · [Security](docs/SECURITY.md).
