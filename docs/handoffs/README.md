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
