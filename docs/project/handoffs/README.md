# Refactor handoffs

Each refactor agent reads every document in this directory **before** touching
code, does one bounded unit of work, then writes `NN-<unit>.md` describing:

1. What it changed (files, symbols, why).
2. What it deliberately left alone and why.
3. What the next agent must know: invariants, landmines, test commands.
4. Evidence: the exact commands run and their results.

Rules that apply to every handoff:

- The suite must be green after each step: `pytest tests/s3 tests/web
  tests/storage tests/meta -q -n 4`, plus `bandit -q -r teledrive web -ll`
  and `python -m compileall -q teledrive web`.
- No behaviour change without a test that would fail before it.
- Never touch the S3 inventory files by hand:
  `scripts/ops/sync_s3_inventory.py` is the only writer, and `--check` gates CI.
- Do not reformat unrelated code. A move-only change should stay move-only so
  review can trust it.
- Anything you discover but cannot fix belongs in the handoff, not silently
  dropped.

## New implementation handoffs (2026-11-02)

Handoffs 06–10 are **work orders**, not completed-work reports. They follow the [S3 fidelity execution plan](../plans/2026-11-02-s3-fidelity.md):

- [06 — GetObject partNumber and bootstrap password](06-get-part-and-bootstrap.md)
- [07 — Directory buckets and session credentials](07-directory-buckets-sessions.md)
- [08 — Real archive and restore](08-physical-archive-restore.md)
- [09 — S3 submodes, IAM/STS and KMS](09-s3-submodes-and-identity.md)
- [10 — Owner-run original media DR and independent backup](10-owner-media-backup-and-dr.md)

Do not check them off until code, live behavior and exact-commit CI agree. Physical GC remains the owner's existing opt-in setting; do not add a signed acceptance prerequisite.
