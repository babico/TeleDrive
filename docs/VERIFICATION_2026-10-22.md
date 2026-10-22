# Engineering Verification — 2026-10-22

> **Scope:** current TeleDrive USER-MTProto-only service, live REST/S3 CI,
> documentation consistency, outstanding roadmap items and production safety.
> This is an **engineering evidence snapshot**, not a production
> acceptance certificate or an assertion that all remaining work is done.
> Read the live [Actions](https://github.com/babico/TeleDrive/actions)
> before treating a newer commit as validated.

## 1. Exact baseline and observed evidence

| Item | 2026-10-22 verified observation |
| --- | --- |
| Inspected source | [`3aa70d18dc227ff06d9a0d735785ced0e46cfccf`](https://github.com/babico/TeleDrive/commit/3aa70d18dc227ff06d9a0d735785ced0e46cfccf), main at audit start |
| Git branches | Only `main` when checked, after previously merged branches were removed |
| Mandatory main-push workflows | **6**: CI 1 Quality, CI 2 Integration (two jobs), CI 3 Image & Resilience, CI 4 USER, CI 4 Multiworker, CI 5 Delivery |
| Passing workflows at baseline | **5 of 6**: Quality, Image/Resilience, live USER, live Multiworker, Delivery |
| Failing workflow at baseline | [CI 2 Integration](https://github.com/babico/TeleDrive/actions/runs/39813109048): storage/API job failed, database job passed |
| Integration failure detail | `tests/storage/test_storage_jobs.py::test_admin_job_endpoints_require_root_auth_csrf_and_do_not_expose_tokens` — **1 failed, 1,040 passed** |
| Additional warning | Four `RuntimeWarning` entries: test-only multi-credential `FakeClient.is_connected` was async, while the Telethon client API and runtime expect a synchronous bool |
| AWS S3 inventory | **116 operations: 11 supported, 42 partial, 63 unsupported**, from `teledrive/s3/operation_manifest.json` |
| Independent original-data proof | **Not provided**; real test-channel E2E does not prove original-channel disaster recovery |

**CI failure diagnosis:** the job source root is loaded from
`jobs.source_root` in `config/config.yaml`, not from the old
`TELEDRIVE_JOB_SOURCE_ROOT` environment variable. When it is unconfigured
the admin job POST must fail with **503**. When it is configured but the
requested source file is **outside** that directory, the operation is
rejected with **422**. The old test removed an irrelevant environment
variable and expected 503 despite the configured source-root boundary.
That is a **test-fixture regression**, not evidence that the server should
allow arbitrary host paths. The audit changes the fixture to verify both
negative cases and retains CSRF/auth/allowed-root enforcement. The
multi-credential fake `is_connected()` is corrected to a synchronous
method to match the real client interface.

**Acceptance rule:** these changes are only *candidate fixes* until CI 2
and the other required workflows succeed on the audited commit's **exact
head SHA**. Never cite the successful 5/6 baseline as a 6/6 acceptance.

## 2. What the inspected implementation supports

- **One service**: Docker WebUI/REST `:8080` and SigV4 S3 `:9000`,
  one SQL catalog, durable jobs and versioned Telegram object manifests.
- **Telethon USER MTProto only**: no Bot API writer or Saved Messages in the
  unified live engine. Multiple authorized user sessions share the
  configured channel; supported placement strategies are `single`,
  `round_robin`, `failover`, and `parallel`.
- **Per-account controls**: tracked session usage and flood cooldowns,
  hot-reload strategy changes, soft-quota *placement preference* and
  bucket-to-account pins. A pin to an unavailable account falls back
  to the normal routing strategy; neither mechanism provides redundancy.
- **History/DR**: user-authorized read-only channel-history candidates,
  strict marker reconciliation and isolated reconstruction tools. These
  never infer unknown historical bucket/key/whole SHA and do not justify
  physical Telegram deletion.
- **Current S3 subset**: see the [compatibility matrix](S3_SPECS.md);
  "supported" is bounded to the documented private TeleDrive contract.
- **Testing**: boto3, actual AWS CLI and rclone against synthetic Telegram
  bytes, plus separate real Telegram USER and multiworker E2E runs.
  A real test channel does not substitute for production original data.

## 3. Remaining engineering work

| Priority | Area | Status / next evidence required |
| --- | --- | --- |
| P0 | Integration CI reliability | Fix source-root test contract; require exact-SHA six-workflow green result before declaring a new release candidate |
| Verified UI | Existing time-limited presigned GET link | The S3 bucket page has a Link/Generate/Copy URL flow backed by an admin signing endpoint; **not** a password-protected or download-count-limited public sharing service |
| P1 | Authorized Telegram sessions | Implement periodic `is_authorized` probes and clear UI health/re-login cues for dead/expired sessions; test recovery without sending bytes |
| P1 | CI consolidation | Finish the planned content-level workflow refactor (unit-vs-integration ownership, duplicate suite execution, accurate summaries), preserving coverage; **not** complete |
| P2 | Sharing & indexing | Expiring signed public links with controlled access; opt-in content search only if justified; all require design, threat model and tests |
| P2 | Durability & security | Optional client-side encryption with key recovery design, content-addressed deduplication with retention/GC integration, independently proven cross-account replication (**not** an independent off-Telegram backup) |
| P2 | S3 parity | **42 partial and 63 unsupported** operations; see [S3 workstreams](S3_SPECS.md#5-p2-advanced-s3-implementation-plan). No blanket AWS parity claim |
| P2 | History | Independently validate unknown original-channel inventory and mapping without guessing missing object metadata |
| P2 | Performance | Owner-authorized long-duration real-media capacity benchmarks with real rate-limit telemetry, no synthetic 429 substitutions |

The TODO roadmap tracks the exact task-level status. **A checked implementation
milestone is not necessarily a published release or production approval.**
Avoid creating a second competing TODO list here.

## 4. Production-only blockers — preserve fail-closed behavior

All of these require actual owner/operator evidence and remain unchecked:

1. Independent, complete payload archive **outside both SQL and Telegram**,
   verified against a new isolated restoration; a SQL dump alone is not enough.
2. Original Telegram channel/account authorization plus sealed original SQL,
   complete object SHA-256 and byte/range readback of owner-selected data.
3. Physically separate application hosts, verified shared DB identity and
   authorized real-time soak/flood telemetry. Containers on one host are not
   separate physical hosts; do not fabricate 429 responses.
4. If a preexisting legacy source actually exists, controlled cutover with
   original bytes; otherwise independent signed no-legacy attestation.
5. Two genuinely independent owner/operator approvals and verified
   production bundle **for the exact release SHA**.
6. Only then could a separate, reviewed physical-GC implementation be
   considered. **Current Telegram physical deletion is disabled** and must
   not be enabled by a docs/CI-only change.

See [owner-local test mission](LOCAL_AGENT_ACCEPTANCE.md),
[backup/restore procedures](BACKUP_RESTORE.md) and
[production acceptance gates](IMPLEMENTATION_STATUS.md#3-production-acceptance-not-yet-signed-off).

## 5. Maintenance protocol

Run the targeted fixes, then re-evaluate the complete matrix, using
only redacted Actions job output. For a future code change:

```bash
python -m pytest -q tests/storage/test_storage_jobs.py tests/storage/test_mtproto_multi_credentials.py
python -m pytest -q tests/meta/test_ci_workflows.py tests/s3/test_s3_route_guard.py
python -m compileall -q teledrive web tests
docker compose config --quiet
```

Do not run actual owner Telegram media recovery, physical GC or a production
soak during CI-only documentation cleanup. Record the precise merge SHA,
workflow outcomes and any remaining failures after merging; revise
[TODO](../TODO.md), [Telethon operations](TELETHON_STORAGE.md) and this
report when verified behavior changes.
