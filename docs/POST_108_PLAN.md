# Post-1.0.8 work plan

Tracking file for the work requested after the S3 parity push. Owner
instructions are quoted where they constrain the outcome.

## Phase 1 — close the last S3 gaps (4 agents running)

| Item | Scope | State |
|---|---|---|
| Two remaining partials | **DONE** (`ccd76b4`). The accelerate renderer emitted `<TransferAcceleratedStatus>`, so boto3 parsed nothing; it now emits `<Status>` and a real boto3 client over uvicorn asserts the value. RequestPayment was already correct and is proven the same way. | done |
| `ListDirectoryBuckets` | **DONE** (`ccd76b4`). Real always-empty `200`, strict `continuation-token`/`max-directory-buckets` validation. | done |
| `CreateSession` | **DONE** (`ccd76b4`). `400 InvalidBucketName` / `400 InvalidRequest` for an existing general bucket / `404 NoSuchBucket`; required accepting the real `s3express` SigV4 scope for this and ListDirectoryBuckets. | done |
| `WriteGetObjectResponse` | **DONE** (`ccd76b4`). Stays unsupported; the rejection now names the missing Lambda runtime. | done |
| `GetObjectTorrent` | Owner decision: stays unsupported. | settled |
| Schema-init race (O4/O6) | **DONE** (`b91df33`). `teledrive/storage/schema.py` with flock / `pg_advisory_xact_lock` / `GET_LOCK`, 19 recorded steps, 5-process proof on all three backends. Warm constructor costs 4.9 us and emits zero SQL. | done |
| S3 credentials UI refresh | **DONE** (`ca28afe`). 21 families, live search, 5 presets, 37 risk-marked scopes, rotate/revoke confirmations, no secret ever persisted client-side. | done |
| Release docs | **DONE** (`ca28afe`), corrected again against the tree: 114/0/2 inventory, 90 scopes. | done |

## Phase 2 — authentication: remove Basic entirely

**Landed in `b97bf62`.** **Owner:** *"basic authu komple kaldır istemem bu sıfır kurulum admin userınıda admin:admin olarak ilk kurulumda ekle eğer databasede zaten eklenmiş admin varsa üzerine yazma ve bunu harcode yap bi confige bağlama, P5 güzel devam"*

- [x] Delete HTTP Basic authentication completely — no `Authorization: Basic`
      anywhere, no `WEB_PASSWORD` credential path, no fallback that treats the
      config password as a principal.
- [x] First-boot admin is created **unconditionally in code**, hardcoded as
      `admin` / `admin`, with `role=admin`, `enabled=1`.
- [x] Never overwrite an existing `admin` row: if the username already exists,
      leave the row (and its password hash) untouched.
- [x] Not driven by config: no `web.password`, no env var, no YAML switch
      controls whether the bootstrap admin exists.
- [x] Keep P5: ONE permission model for session and API key (explicit
      role→permission map, no "GET is universally allowed").
- [x] Update `docs/UPGRADING.md`: Basic is gone, the bootstrap admin is
      `admin`/`admin`, change it on first login.
- [x] Startup must still refuse to run without a way to authenticate if the
      users table is somehow empty — the bootstrap covers that, so remove the
      `WEB_PASSWORD` startup requirement and say why.

## Phase 3 — exhaustive API review (4 agents per wave, repeat until done)

**Owner:** *"bütün ajanlar bittikten sonra tek görevi sadece bir apiyi incelemek olan 4 tane ajan aç ve bunu tüm apiler incelenene kadar devam ettir"*

Every permissioned route gets its own reviewer with one job: read that route's
implementation end to end and report defects. Waves of 4 until the list is
exhausted.

- [ ] Build the authoritative route list from the live FastAPI table.
- [ ] Wave 1 (4 routes), wave 2, … until every route is reviewed.
- [ ] Each review is appended to `docs/API_REVIEW.md` in a fixed format:
      route, handler, auth model, inputs, failure modes, findings by severity,
      and the test that should exist.
- [ ] Findings that are real bugs become Phase 4 work orders.

## Phase 4 — multi-agent refactor with handoffs

**Owner:** *"ardından multiagent birbirleriyle handoflar aracılığıyla haberleşen refactor ajanalraı aç kaç tane lazımsa codebasein kocaman kısımlarını düzeltsinler"*

- [ ] Split the giant modules (`web/app.py`, `web/s3.py`, `teledrive/storage/catalog.py`,
      `web/static/app.js`) into focused units.
- [ ] Agents coordinate through handoff documents in `docs/handoffs/` — each
      refactor agent writes what it changed, what it left, and what the next
      agent must know, then the next one reads it before starting.
- [ ] Every step keeps the suite green; no behaviour change without a test.

## Standing rules

- Each phase: compileall + bandit + full suite (`-n 4`), then deploy
  (down without sudo, build and up with sudo), then watch CI to green on the
  exact SHA.
- Inventory bookkeeping is centralized: `scripts/ops/sync_s3_inventory.py`.
- Never claim a tag, a count or a test result that the tree does not show.
