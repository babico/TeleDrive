# Handoffs

Work orders for implementation agents. The completed refactor handoffs
(00–05: the web/s3 split, the app router split, the store layer, the JS
pages, the catalog mixins) were removed once their content was fully
absorbed into the tree — the structure they describe is documented in the
[module map](../../reference/module-map.md). Handoff 11 (legacy branch
retirement) closed with the archived tags named `archive/2026-11-02/*`.

## Work orders

Handoffs 06–09 followed the [S3 fidelity execution
plan](../plans/2026-11-02-s3-fidelity.md) and are **delivered in v1.0.10**.
Handoff 10 is the owner-executed DR/payload-backup plan: the tooling is
delivered, the run itself is not (and must not be run from CI).

- [06 — GetObject partNumber and bootstrap password](06-get-part-and-bootstrap.md) — delivered
- [07 — Directory buckets and session credentials](07-directory-buckets-sessions.md) — delivered
- [08 — Real archive and restore](08-physical-archive-restore.md) — delivered
- [09 — S3 submodes and identity](09-s3-submodes-and-identity.md) — delivered
- [10 — Owner media backup and DR](10-owner-media-backup-and-dr.md) — tooling complete, owner-run

## Rules that apply to every handoff

- The suite must be green after each step: `pytest tests/ -q`, plus
  `bandit -q -r teledrive web -ll` and `python -m compileall -q teledrive web`.
- No behaviour change without a test that would fail before it.
- Never touch the S3 inventory files by hand:
  `scripts/ops/sync_s3_inventory.py` is the only writer, and `--check` gates CI.
- Do not reformat unrelated code. A move-only change should stay move-only so
  review can trust it.
- Anything you discover but cannot fix belongs in the handoff, not silently
  dropped.
