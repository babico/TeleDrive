# Garbage collection

Physical garbage collection deletes the Telegram messages that hold logically deleted TeleDrive objects. It is disabled by default, it never runs on a schedule, and it is the only TeleDrive action that destroys payload bytes irreversibly. This page explains the safety model, the owner gates and the exact preview/collect workflow. Do not enable it without the evidence described below.

## What GC is and why it exists

A normal S3 or REST delete is a **logical** delete. It removes the head pointer, writes a delete marker or records a version revocation, and deliberately keeps the Telegram messages as a recovery journal. That is why a deleted object can still be read from an older version, why a pinned share link can still resolve until it is retired, and why a mistaken unlink is recoverable from SQL history.

Telegram storage is finite. Every logical delete therefore leaves a growing backlog of messages that no current object references. `RetainedMediaGC` turns that backlog into reclaimable space by deleting the exact Telegram messages recorded in `storage_chunks` and `storage_replica_chunks`, then journaling the result and hiding the object from version history.

| Scope | What it targets |
| --- | --- |
| `revoked` | A proven-published version that was explicitly revoked and is no longer a head anywhere |
| `deleted` | A proven-published version whose key has no live non-delete-marker head, for example after an unlink or a lifecycle expiration |
| `queued` | A specific object enqueued by a version delete, multipart abort, lifecycle rule or manual request, after the configured grace period |

The collector does **not** delete failed, staged or never-published uploads. A failed object can appear in `GET /api/v1/admin/storage/gc-candidates`, but that endpoint is a read-only planning preview with `approved_for_deletion: false`. The collector requires `objects.status = 'ready'` plus a `storage_published_versions` row, so an abandoned or never-published upload is retained forever by this code path.

## The safety model

Every candidate passes the filters below. The same checks are repeated inside `_collect_object` in a fresh transaction immediately before any Telegram delete.

| Control | Behaviour |
| --- | --- |
| Fail-closed enumeration | `candidates()` only returns `status='ready'` objects that have a published version, no current head, and no dedup alias pointing at them |
| Age window | For `revoked`/`deleted`, age is measured from the later of the upload and the revocation. Default minimum is 86,400 seconds; the hard floor is 3,600 seconds. For `queued`, the stored grace period measured from enqueue time applies instead |
| Durable lease | One expiring row per object in `storage_gc_leases` (900 seconds). A second collector reports the object as `skipped`, never as a second delete |
| Fresh re-verification | After claiming the lease the collector ends the preview transaction and re-reads status, head, aliases, live key and locks. A writer that published during the preview makes the object ineligible |
| Object lock and legal hold | A retained or legal-held object is skipped even when queued |
| Send-intent fence | An unresolved pre-send intent (`message_id IS NULL`) skips the object. If the intent table cannot be inspected, the object is skipped rather than guessed |
| Replica handling | Replica messages are deleted through the transport before their SQL rows are dropped. A replica failure fails the object instead of leaving unaccounted bytes |
| Journal and completion | After the Telegram deletes, `storage_gc_collected` records the object, scope, chunk count, bytes and exact deleted message coordinates in the same SQL transaction that removes the chunk rows and hides the object from history. A SQL failure leaves the object retryable but cannot undo a Telegram delete already issued |
| Idempotent completion | The removed-version row is inserted only when absent; a retry after a partial failure does not collide with the revocation record |
| Per-object isolation | One failure is reported in `failed[]` and the run continues. A failed Telegram delete does not mark the object collected |
| Kill switch | `collect()` refuses to start unless `enabled` is true. It reads the toggle once, so disabling during a run does not cancel the remaining candidates |

The plan contract adds a SQL reference fingerprint. `scripts/ops/gc_dry_run.py` writes a fingerprint over the head, published/removed versions, aliases, writer fence, multipart parts, send intents, durable jobs and chunk journal. `verify_plan()` rejects a plan if any reference changed, if the plan is not a dry run, or if `deletion_permitted` is not exactly `false`.

## Owner control, evidence and `deletion_permitted`

**GC is an explicit admin choice.** Its actual execution gate is the persisted `enabled` toggle plus the typed `PHYSICAL-GC` and `DELETE-RETAINED` confirmations. The dry-run/evidence contract's `deletion_permitted: false` indicates that the report itself cannot authorize deletion; it does **not** prevent an admin from deliberately enabling GC. No signed acceptance bundle, second-person approval, independent host attestation or production soak is required by the current API for the owner to use this switch.

A separate independent payload backup, a successful isolated restore and a reviewed dry-run/reference inventory are strongly recommended **before choosing to delete media**. They remain owner-operated safety practices, not application-level enablement gates. Once enabled, the collector still checks live heads, aliases, retention/legal holds, unresolved send intents and concurrent writer fences. It must never use the toggle to bypass object-level safety.

!!! danger
    Physical Telegram message deletion is irreversible through TeleDrive. A SQL backup restores metadata but **not** the missing Telegram payload bytes. The owner assumes this risk when enabling GC. GC defaults to off, and switching it off does not cancel a collection already in progress.

## Preview and collect workflow

All routes require authentication and the `admin` role; a human session is checked by the role policy, and an API key is accepted only because an admin deliberately minted it with that exact route permission. The toggle and collect routes also require the same-origin CSRF header (`X-TeleDrive-CSRF: 1`) for a browser session.

| Step | Endpoint | Purpose |
| --- | --- | --- |
| 1 | `GET /api/v1/admin/storage/gc` | Read the toggle state, logical versus physical usage, reclaimable backlog and collected totals |
| 2 | `POST /api/v1/admin/storage/gc/collect` with `"dry_run": true` | Enumerate the exact candidate set without deleting anything |
| 3 | `PUT /api/v1/admin/storage/gc` with `"enabled": true, "confirm": "PHYSICAL-GC"` | Record the owner decision and optional grace period |
| 4 | `POST /api/v1/admin/storage/gc/collect` with `"dry_run": false, "confirm": "DELETE-RETAINED"` | Execute the collection |
| 5 | `GET /api/v1/admin/storage/gc-audit` | Read the broader non-destructive inventory, including unjournaled receipts and unresolved intents |
| 6 | `GET /api/v1/admin/storage/gc-candidates` | Read-only failed-object planning preview; never a deletion authorization |

Preview request:

```json
{
  "scope": "revoked",
  "dry_run": true,
  "min_age_seconds": 86400,
  "limit": 50
}
```

Execution request, only after the preview has been reviewed:

```json
{
  "scope": "revoked",
  "dry_run": false,
  "min_age_seconds": 86400,
  "limit": 50,
  "confirm": "DELETE-RETAINED"
}
```

Enable request:

```json
{
  "enabled": true,
  "confirm": "PHYSICAL-GC",
  "grace_seconds": 86400
}
```

The exact confirmation strings are `PHYSICAL-GC` for enabling and `DELETE-RETAINED` for execution. A missing or different string is `422`. Execution while disabled is `409`. `grace_seconds` is accepted only between 3,600 and 7,776,000 seconds (1 hour to 90 days) and is used by the `queued` scope.

Disabling needs no confirmation:

```json
{"enabled": false}
```

!!! warning
    Disabling stops future collections, not one already in progress. The collector reads `enabled` once per run and does not re-check it per object. Wait for the current request to finish and read the report before assuming deletion has stopped.

## Reading the report

Execution returns the candidate report plus fresh metrics:

| Field | Meaning |
| --- | --- |
| `collected[]` | Object, bucket, key, reason, chunk count and bytes whose Telegram messages were deleted and whose SQL side committed |
| `skipped[]` | Object is no longer eligible: new head, alias, lock, unresolved intent, missing chunk journal, or a lease held by another collector |
| `failed[]` | Per-object failure with a truncated reason. The object may have had some messages deleted before the failure; inspect before retrying |
| `metrics.logical_objects` / `logical_bytes` | Objects and bytes reachable through current heads |
| `metrics.physical_objects` / `physical_bytes` | Chunks still held in Telegram, including retained history |
| `metrics.retained_objects` / `retained_bytes` | Physical minus logical: the retained backlog |
| `metrics.reclaimable.revoked` / `.deleted` | Counts that mirror the candidate filters, not a promise that every row will pass re-verification |
| `metrics.queued` | Queue rows waiting for grace or for eligibility |
| `metrics.collected_objects` / `collected_bytes` | Historical totals from `storage_gc_collected` |

The durable evidence is `storage_gc_collected`, not the log. Log lines only say `physical gc collect START/DONE` and the counts; the log buffer is bounded and the file can rotate. The security audit also records `gc.collect.start` and `gc.collect.done` with the scope, candidate count, outcome and collected bytes.

## What can go wrong and how to recover

| Symptom | Cause | Recovery |
| --- | --- | --- |
| Some Telegram messages are gone but the object still reads `ready` | The process failed after the Telegram delete and before the SQL commit | Stop collection. Do not delete SQL rows. Attempt one controlled retry only after confirming the remaining chunk messages still exist. If bytes are partially gone, the object is damaged; restore the SQL backup and accept that the deleted media cannot be restored |
| `failed[]` names a replica or account error | The replica account is unavailable or the primary account cannot see the message | Restore access to that account and retry the same object; replica coordinates remain until the object completes |
| `skipped` with no reason in the log | A head, alias, live key, lock, unresolved intent or lease fence won the race | This is the safety model working. Re-preview later; do not bypass the filter |
| `409 Physical GC is disabled; enable it first (owner gate)` | The toggle is off | Complete the owner gates first. Do not enable it just to clear the error |
| `422` on collect | Missing `DELETE-RETAINED`, invalid scope, or `min_age_seconds` outside 1 hour to 90 days | Correct the request; the API refuses unsafe values by design |
| A queue row never drains | The queued object is staged, failed or otherwise not `ready` + published, or the grace period has not elapsed | Inspect the object and queue reason. This code path cannot collect an ineligible queue row |
| The toggle was disabled but deletion continued | A run already in flight; `enabled` is read once | Wait for the request to finish and read the report. The in-memory log line and `gc.collect.done` are the completion signal |
| A dry-run plan is rejected | The SQL reference graph changed after planning | Re-plan. `gc_dry_run.py` writes a new fingerprint and refuses to reuse a stale one |
| The object is under retention or legal hold | The lock gate skipped it | This is WORM behaviour, not a bug. Do not remove the lock merely to collect |
| Metrics disagree with the audit inventory | They answer different questions: metrics use the same filters as candidates, the inventory counts every reachable manifest and unjournaled receipt | Use `gc-audit` for reachability questions and `gc` metrics for reclaimable estimates |

A run is not resumable at chunk granularity. The lease makes the object retryable, and chunk deletion is idempotent at the SQL level, but Telegram messages deleted before a crash are not recorded individually. That is the reason the safety interval, the backup gate and the restore drill exist.

## Operator checklist

| Done | Item |
| --- | --- |
| [ ] | `GET /api/v1/admin/storage/gc` shows `state.enabled: false` before any change |
| [ ] | A verified SQL backup and a matching master-key/session backup exist |
| [ ] | An independent payload backup exists and has been read back |
| [ ] | The restore drill has been repeated against a disposable database |
| [ ] | The writer barrier is in place; no queued or running job can publish the candidate key |
| [ ] | The dry-run candidate list has been reviewed object by object |
| [ ] | The owner has accepted that Telegram deletion is irreversible |
| [ ] | `confirm: "PHYSICAL-GC"` was typed deliberately, not scripted by accident |
| [ ] | `gc.collect.start` and `gc.collect.done` appear in the audit trail |
| [ ] | `failed[]` was empty, or every entry was investigated before retry |
| [ ] | GC was disabled again after the approved window |

For the backup half of these gates, see [Backup and restore](backup-restore.md). For the audit endpoint and metrics, see [Monitoring](monitoring.md).
