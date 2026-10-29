# Post-1.0.8 work plan

Tracking file for the work requested after the S3 parity push. Owner
instructions are quoted where they constrain the outcome.

## Phase 1 — close the last S3 gaps (4 agents running)

| Item | Scope | State |
|---|---|---|
| Two remaining partials | `GetBucketAccelerateConfiguration` emits `<TransferAcceleratedStatus>` but AWS's element is `<Status>`, so boto3 parsed nothing. Same audit for `GetBucketRequestPayment`. Promote both to supported with a **real boto3** round-trip test. | in flight |
| `ListDirectoryBuckets` | Honest answer for an account with zero directory buckets is 200 + empty result. Implement as a real always-empty listing, strict query validation. | in flight |
| `CreateSession` | No directory buckets ever, so return the most accurate AWS error (`NoSuchBucket`) rather than a generic 501, rejecting malformed input 400. | in flight |
| `WriteGetObjectResponse` | No Lambda runtime. Stays unsupported, but the rejection must name the reason. | in flight |
| `GetObjectTorrent` | Owner decision: stays unsupported. | settled |
| Schema-init race (O4/O6) | One serialized migration coordinator with a real cross-process lock (SQLite file lock, PG advisory, MySQL GET_LOCK) and a `schema_version` row. Multi-process test. | in flight |
| S3 credentials UI refresh | 84 scopes are a wall of checkboxes. Group by resource family, live search, presets, risk markers, rotate/revoke confirmations, relative timestamps. | in flight |
| Release docs | CHANGELOG/UPGRADING/RELEASE up to date with the tree. | in flight |

## Phase 2 — authentication: remove Basic entirely

**Owner:** *"basic authu komple kaldır istemem bu sıfır kurulum admin userınıda admin:admin olarak ilk kurulumda ekle eğer databasede zaten eklenmiş admin varsa üzerine yazma ve bunu harcode yap bi confige bağlama, P5 güzel devam"*

- [ ] Delete HTTP Basic authentication completely — no `Authorization: Basic`
      anywhere, no `WEB_PASSWORD` credential path, no fallback that treats the
      config password as a principal.
- [ ] First-boot admin is created **unconditionally in code**, hardcoded as
      `admin` / `admin`, with `role=admin`, `enabled=1`.
- [ ] Never overwrite an existing `admin` row: if the username already exists,
      leave the row (and its password hash) untouched.
- [ ] Not driven by config: no `web.password`, no env var, no YAML switch
      controls whether the bootstrap admin exists.
- [ ] Keep P5: ONE permission model for session and API key (explicit
      role→permission map, no "GET is universally allowed").
- [ ] Update `docs/UPGRADING.md`: Basic is gone, the bootstrap admin is
      `admin`/`admin`, change it on first login.
- [ ] Startup must still refuse to run without a way to authenticate if the
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
