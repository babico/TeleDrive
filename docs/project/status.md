# Project status

What is development-validated, what is production-signed-off, and what the
owner still has to decide. A green CI run is development evidence; it is not
approval to operate on production data or to delete Telegram messages.

## 1. Release boundary

| Item | Value |
| --- | --- |
| Current release line | **v1.0.9** |
| Tag / commit | `v1.0.9` resolves to `69a503ab07b4d372d3dcdba887204228c3e52c4f` in this repository |
| Previous release | `v1.0.8` at `7d2aa773d3839a65899815dd9f3fa2ed2e534324` |
| Previous release | `v1.0.7` at `747747652cd1ca36878453d49daf627d8c0a60ad` |
| Package version | `1.0.9` in `pyproject.toml` |
| Schema version | 27 recorded, append-only steps in `teledrive/storage/schema.py` |
| S3 inventory | **114 supported / 0 partial / 2 unsupported** of 116 operations |

The tag message and [release notes](releases/v1.0.8.md) state that the six
mandatory workflows were green on the tagged SHA. This page does not copy
run logs: confirm the exact SHA in
[Actions](https://github.com/babico/TeleDrive/actions) before treating it as
evidence. Commits after `7d2aa77` are post-release and are not in the image or
the release notes.

Do not claim a newer SHA than the one a check actually ran on. A green commit
elsewhere in history does not transfer to a release candidate.

## 2. P0 / P1 / P2 status

| Level | Scope | State | What the evidence covers |
| --- | --- | --- | --- |
| **P0** | Basic upload, authentication, integrity, supported REST/S3 subset, one-container deployment | **Development-validated** | SQLite/PostgreSQL/MySQL integration, immutable manifests, SHA-256 and ranged reads, session/API-key/RBAC auth, quotas, signed S3 requests, the documented supported subset. Not full AWS parity. |
| **P1** | Disposable Docker acceptance with real PostgreSQL; live test-channel USER MTProto; multiworker PostgreSQL | **Development-validated** | 13 fault-injection gates with four evidence stages; real Telethon user round-trip; three workers sharing PostgreSQL. Telegram I/O in the Docker suite is synthetic. |
| **P1** | Production operation on independent hosts with the owner's data | **Not signed off** | No independent host attestation, owner media recovery rehearsal, authorized 1-hour soak or signed evidence bundle. |
| **P2** | Advanced recovery, physical GC, exhaustive protocol verification | **In development / owner-gated** | Rebuild and offline verification components exist and are race-tested; physical GC is disabled; per-operation crash/restart coverage is partially complete. |

### P0 boundaries

- **State:** SQLAlchemy with SQLite/PostgreSQL/MySQL; immutable object and chunk
  manifests; SHA-256 verification; persistent jobs; engine cache keyed by
  database URL.
- **Authentication:** login session (`teledrive_session` cookie or `td_sess_`
  bearer, 7 days, SHA-256-digested server-side), PBKDF2-HMAC-SHA256 at 260,000
  iterations with transparent legacy migration, login throttling, and the
  role → per-route-permission map. HTTP Basic is removed; first boot creates
  `admin`/`admin` only when no admin row exists.
- **Credentials:** API keys with per-endpoint scopes and a delegation/lifetime
  ceiling; S3 SigV4 credentials with Fernet-encrypted secrets. S3 credential
  management, presign and config writes require a human session.
- **Interfaces:** one process, WebUI/REST and S3 listeners, one SQL catalog.
  REST and S3 observe the same published object and generation; copying a file
  into `/uploads` does not import it — an authenticated job must be queued.
- **Encryption:** SSE-C supported; envelope (SSE-S3 shape) opt-in with dedup,
  replication and content search disabled for encrypted objects; SSE-KMS does
  not exist here. Client-side encryption is available in the browser.
- **S3:** the [compatibility matrix](../reference/s3-specs.md) is the authority.
  The two unsupported operations are permanent: `GetObjectTorrent` (no
  seeder) and `WriteGetObjectResponse` (no Lambda runtime).

## 3. What "development-validated" means

It means the named checks ran and passed on a specific commit, using either
synthetic Telegram I/O or a dedicated test channel. It does **not** mean:

- the owner's original Telegram account, channel or media were exercised;
- production hardware, network or rate limits were measured;
- a skipped test ran, or a cancelled workflow passed;
- physical GC, legacy cutover or disaster recovery of original data is safe.

The service validation matrix is six workflows: CI 1 Quality, CI 2
Integration, CI 3 Image & Resilience, CI 4 Live E2E (user and multiworker),
and CI 5 Delivery. The endurance soak is manual, and the docs site build is a
separate automatic workflow. Details and the exact job contents are in
[CI and tests](../reference/ci.md).

## 4. Production acceptance — not signed off

These gates require owner-provided infrastructure and data. None can be
closed by a commit on this repository.

| Gate | Evidence required | State |
| --- | --- | --- |
| Independent physical hosts | At least two different machines, distinct machine-id hashes, one shared SQL database identity | Missing |
| Authorized rate-limit soak | ≥ 1 hour, 2–8 HTTPS endpoints, genuine observed 429s, coherent shared counters, no unresolved send ACK | Missing |
| Original-media recovery | Sealed original SQL archive, independent checksum, real credentials/channel, isolated restore, whole-object SHA and range verification | Missing |
| Legacy cutover or exemption | Verified cutover from a real legacy source, or an independent signed no-legacy attestation | Missing |
| Evidence verification | `scripts/ops/verify_production_bundle.py` over `release_sha`, `topology`, `soak`, `dr`, `cutover`, `original_telegram_data_attested` and independent owner/operator keys | Not run |

The verifier is offline: it validates receipts and signatures, it does not
poll hosts. It requires two distinct Ed25519 public keys and two to eight
independently attested hosts sharing one database. The `approvals` block is
optional by owner decision; the technical evidence families are not.

```bash
python scripts/ops/verify_production_bundle.py \
  --bundle /secure/acceptance/production-bundle.json \
  --release-sha REVIEWED_40_HEX_COMMIT_SHA \
  --owner-public-key /secure/keys/owner.pub \
  --operator-public-key /secure/keys/operator.pub
```

Even a verified bundle is not an automatic deployment action and is not
authorization to delete Telegram media. See
[Local acceptance](plans/local-acceptance.md) for the executable mission and
[Backup and restore](../operate/backup-restore.md) for the procedures.

## 5. Physical garbage collection: disabled

`deletion_permitted` is `False`. The collector, reference graph, leases and
dry-run planner are implemented and race-tested, but no Telegram media has
been deleted by TeleDrive.

Two-person approval is **not** required — an owner decision. What is still
required:

1. an independent backup host or verified payload export;
2. a successful isolated restore drill of original media;
3. owner-authorized rate-limit and recovery evidence;
4. a signed dry-run plan with complete remote inventory and resolved
   references;
5. explicit owner authorization for physical deletion.

Deleted Telegram message IDs cannot be restored from SQL. A SQL backup alone
restores metadata, not payloads. The WebUI toggle and `POST
/api/v1/admin/storage/gc/collect` remain admin-only and refuse execution while
the gate is off.

## 6. Recovery limits

- `scripts/ops/rehearse_telegram_dr.py` verifies **one named object** against a
  sealed snapshot; it does not prove a complete archive recovery.
- `scripts/ops/inventory_telegram_history.py` produces **unverified candidate
  markers** from a bounded channel scan; it downloads no media and writes no
  SQL.
- `scripts/ops/rebuild_from_telegram.py` requires an independently supplied
  whole-object SHA and builds a **new isolated** catalog; it never overwrites
  the live database.
- A candidate marker is not an importable plan and not proof of the original
  bucket/key mapping.

## 7. Open engineering work

Tracked in the [roadmap](roadmap.md): the final `web/app.py` extraction
(settings machinery and scheduler loops), the exhaustive per-operation
crash/restart and multiworker-race matrices, and test-realism items from the
reviews. None of
these is required for the 1.0.8 release to be correct; they reduce future
risk.

Update this page only when the verified **behaviour or acceptance boundary**
changes, not for each transient CI result.
