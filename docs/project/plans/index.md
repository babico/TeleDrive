# Plans

Design records and executable missions. A plan is kept after completion so
the reasoning and the rejected alternatives remain auditable; **a file in this
folder is not automatically open work.** Check its status banner first, then
the [roadmap](../roadmap.md) for the current queue.

## Documents

| Document | Status | What it contains |
| --- | --- | --- |
| [Local acceptance](local-acceptance.md) | Executable mission; owner gates remain blocked | Instructions for an agent on the owner's machine: isolated Docker setup, byte fixtures, independent SQL and payload backups, recovery drills, GC race tests and evidence files. It explicitly forbids using production data or treating one host as two. |
| [Metadata parity](metadata-parity.md) | Complete design record | The stance change that made SQL-backed S3 metadata honest, and the phases (GC deletes, versioning states, object lock, ACLs, PAB/ownership, notifications, replication, website, CORS, tagging) that were implemented from it. Final inventory 114/0/2. |
| [Post-1.0.8 plan](post-108.md) | Tracking file, mostly complete | The work requested after the S3 parity push: the last S3 gaps, removal of HTTP Basic, the first-boot admin, the schema coordinator, credentials UI, and the module-split handoffs. Its "Released" section records the 1.0.8 tag. |
| [S3 full coverage](s3-full-coverage.md) | Complete design record | The operation-by-operation plan that took the inventory to its honest end state. It keeps the counts as they stood when written and explains why `GetObjectTorrent` and `WriteGetObjectResponse` are permanent exceptions. |

## Using a plan

A design record answers "why is it shaped this way", not "what do I do next".
For current work use the [roadmap](../roadmap.md). For an owner-run acceptance
mission use [Local acceptance](local-acceptance.md) with the boundaries in
[Project status](../status.md#4-production-acceptance-not-signed-off)
unchanged. Do not copy a completed phase back into the roadmap as new work.
