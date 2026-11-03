# Plans

Executable missions and design records for work that is still open. A
completed plan is deleted once its reasoning is either absorbed into the
tree or captured by the [reference docs](../../reference/) — the
[roadmap](../roadmap.md) is the only queue.

## Documents

| Document | Status | What it contains |
| --- | --- | --- |
| [S3 fidelity and recovery 2026-11-02](2026-11-02-s3-fidelity.md) | Not implemented | Real S3 Express sessions, physical cold-tier restore, GetObject partNumber, submode parity, bootstrap password enforcement, owner-run DR and independent payload backup. Work orders: handoffs 06–10. |
| [Local acceptance](local-acceptance.md) | Executable mission; owner gates remain blocked | Instructions for an agent on the owner's machine: isolated Docker setup, byte fixtures, independent SQL and payload backups, recovery drills, GC race tests and evidence files. It explicitly forbids using production data or treating one host as two. |

## Using a plan

A design record answers "why is it shaped this way", not "what do I do
next". For current work use the [roadmap](../roadmap.md). For an owner-run
acceptance mission use [Local acceptance](local-acceptance.md) with the
boundaries in [Project status](../status.md) unchanged.
