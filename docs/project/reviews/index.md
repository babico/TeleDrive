# Reviews

Read-only audits of the codebase and the fixes they produced. These are
ledgers, not tutorials: each document states the tree or commit it examined,
what was fixed, what was declined on purpose, and what remained open at the
time. A finding is only "fixed" when the document names the commit or test
that closed it; check the current tree before treating an old finding as live.

## Documents

| Document | Scope | Why read it |
| --- | --- | --- |
| [Full-codebase review 2026-10-31](review-2026-10-31.md) | Six independent reviewers across storage, the S3 data plane, web/API, persistence, and S3/web test realism. | The most recent whole-tree review: correctness bugs fixed before shipping, false positives dropped, and explicitly declined test-realism items. |
| [API review](api-review.md) | Seven waves over 25 endpoints — the authority surface, not the whole route list. | Per-endpoint defect reports with fix status. Sixty-four real defects were closed before the 1.0.8 tag, including four takeovers; one finding was disproved with evidence. |
| [Codebase review](codebase-review.md) | Structural review of `teledrive/`, `web/`, the UI, tests and scripts at `054af3a`. | Fifteen refactor findings with a correction-status table; the closed ones carry commits, the open ones are carried into the [roadmap](../roadmap.md). Parts of the document are written in Turkish. |
| [Audit 2026-10-29](audit-2026-10-29.md) | TODO/docs/roadmap claims checked against the tree at `08a7c8e`. | Shows which documentation claims were true, which were stale, and how the bucket-delete, MySQL, permission-catalog and schema-race findings were closed. Keeps its pre-fix state visible. |

## How to read a review

- **The heading date is the review date**, not the current state. Later
  commits can close or reintroduce an item.
- **"Fixed" means evidence exists.** A commit hash, a named test, or both.
  A prose claim without either is a finding, not a closure.
- **"Declined" is a decision, not an omission.** It usually means the change
  would remove a deliberate fail-closed behaviour or does not pay for itself.
- **A review is not a production sign-off.** It is development evidence; the
  owner gates are in [Project status](../status.md).
