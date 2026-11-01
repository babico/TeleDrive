# Local file jobs

The durable job queue uploads files that already exist on the server's filesystem. A job row is metadata only: the source file stays where it is until a worker reads it, streams it to Telegram through the normal storage engine, and publishes the resulting object into the shared catalog. Jobs survive restarts, can be claimed by more than one worker without double-publishing, and are visible to S3 and REST the moment they finish.

This is the supported path for importing a folder or a legacy upload tree. There is no separate CLI uploader and no second catalog: a job is another writer of the same immutable object versions that the S3 gateway and REST data plane create.

## Source root rules

A job may read only a regular file that lives under the configured job root.

| Setting | Default | Meaning |
| --- | --- | --- |
| `jobs.source_root` | `/uploads` | The only directory a job may read from |
| `paths.source_roots` | `/uploads` | Source-path allowlist used by the legacy uploader's own file checks |
| `jobs.auto_run` | `true` | Run a worker loop inside the service |
| `jobs.watch` | `false` | Scan the source folder periodically and enqueue new files |
| `jobs.watch_interval_seconds` | `30` | Minimum 5 |
| `jobs.watch_bucket` | empty | Destination bucket for the watcher; required for watch to do anything |

The root is resolved with `strict=True`; if it is empty, missing or not a directory, enqueue answers `503` instead of guessing. A source path is then resolved and must be:

- inside the root and not equal to the root itself;
- a regular file, not a directory, device or FIFO;
- not a symlink, including not a symlink in its final component.

The job records the file's device, inode, size and modification time at enqueue. A worker re-checks that identity before reading and again before publishing, so a file that was replaced or truncated while queued fails instead of publishing bytes that do not match the queued snapshot.

`jobs.watch` uses `upload.source_dir` as its scan root and additionally requires that directory to sit under the job root. It enqueues at most 100 files per pass, skips files that do not pass the legacy extension and size filters, and never uploads anything itself.

## Enqueueing a job

### REST, one file

```bash
curl -sS -b td.cookies \
  -H 'X-TeleDrive-CSRF: 1' \
  -H 'Content-Type: application/json' \
  -d '{"bucket":"backups","key":"import/report.pdf","source_path":"/uploads/report.pdf"}' \
  http://127.0.0.1:8080/api/v1/admin/storage/jobs
```

The destination bucket must already exist. The object key is validated with the normal 1–1024 UTF-8 byte rule. The response is:

```json
{"id": "0f0c...", "state": "queued"}
```

An operator or admin may enqueue; a viewer cannot. Queueing does not require a live Telegram session, but a worker that cannot obtain one leaves the job queued and the health endpoint reports the reason.

### REST, a legacy folder

`POST /api/v1/admin/storage/jobs/import-legacy` previews or queues every eligible file under `upload.source_dir`:

```bash
curl -sS -b td.cookies \
  -H 'X-TeleDrive-CSRF: 1' \
  -H 'Content-Type: application/json' \
  -d '{"bucket":"backups","prefix":"legacy","max_files":100,"execute":false}' \
  http://127.0.0.1:8080/api/v1/admin/storage/jobs/import-legacy
```

| Field | Rule |
| --- | --- |
| `bucket` | Existing destination bucket |
| `prefix` | Relative safe key prefix; empty allowed, no leading `/`, no `..` segments |
| `max_files` | 1–1000, default 100 |
| `execute` | `false` (default) previews only; `true` enqueues |

The response reports `would_queue`, `queued` (zero in a preview), `already_queued`, `excluded`, `job_ids` (only when executing) and `uploads_started` (always zero — this endpoint never uploads). The import takes the legacy uploader lease for the duration and fails with `409` if another legacy uploader holds it, so an old background uploader and the durable worker cannot both process the same tree. Repeated scans are idempotent: the job id is a UUIDv5 over bucket, key, resolved path, device, inode, size and modification time.

### Web UI and folder watch

The dashboard surfaces the queue rather than offering a single-file form:

- **Queue** lists jobs with source path, state, attempts, account and last error.
- **Dashboard → Run next job** calls `POST /api/v1/admin/storage/jobs/run-next` and processes one queued job immediately.
- The opt-in `jobs.watch` setting on `config/config.yaml` enqueues new or changed files from `upload.source_dir` into `jobs.watch_bucket` every `watch_interval_seconds`. There is no UI toggle for it.

There is deliberately no browser form that accepts an arbitrary host path: a path is validated against the operator-configured root, and allowing it from a dashboard would only move the same risk into a text box.

## Idempotency and crash recovery

Each manual `POST /api/v1/admin/storage/jobs` creates a new UUIDv4 job. Two identical requests therefore produce two jobs, even for the same file and key; the storage engine may deduplicate the physical bytes, but the jobs are separate. The legacy folder importer is the idempotent path: its stable UUIDv5 means a rescan returns the existing id instead of a duplicate.

A job moves through a durable state machine:

1. `queued` — row committed, no worker owns it.
2. `running` — a worker claimed it with a lease and is streaming bytes.
3. `staged` — every chunk is on Telegram and a READY manifest exists; publication has not happened yet.
4. `publishing` — the worker is committing the head in SQL.
5. `done` — the head is published.
6. `failed` — the attempt ended with an error; the Telegram chunks are retained.
7. `cancelled` — an inactive job was cancelled by an operator.

Crash recovery follows from those states. If a worker dies while `running` or `staged`, its lease expires and another worker may claim it. A job that references a **pending** object resumes the existing chunk journal (`resume_file`) instead of re-sending bytes; a job that references a **ready** staged manifest publishes it without another Telegram upload. A failed or missing journal cannot be resumed, so an explicit retry starts a fresh object and leaves the old chunks for later GC evidence.

!!! warning "Retries and cancellation never delete Telegram media"
    A failed or cancelled job can leave already-sent chunks behind. They are retained deliberately as a recovery journal until physical garbage collection removes them, and GC is owner-gated. Retrying does not overwrite or erase the old chunks, and cancelling cannot interrupt a live Telegram writer: only `queued` and `failed` jobs may be cancelled.

The source file must still exist and match its snapshot at retry time. If it was deleted, replaced or modified, the job fails again; the queue is not a copy of your data.

## Leases and multiple workers

Claiming is a single conditional SQL update. A worker may claim a job whose state is `queued`, or a `running`/`staged`/`publishing` job whose lease has expired. The update sets `state=running`, a fresh random lease token and `lease_until=now+120 seconds`, and increments `attempts`; exactly one contender gets `rowcount == 1`. The loop retries SQLite write-contention errors a bounded number of times and lets every other database error surface.

The worker renews its lease every third of the TTL. If renewal fails, the worker marks the lease lost and refuses to publish, even if bytes were already sent. Every state transition (`mark_pending`, `mark_staged`, `finish`, `fail`) is fenced on the token, so a worker whose lease expired cannot commit after a newer owner took over. Lease tokens are never returned by the job listing.

Several workers can therefore share one database safely: one service scheduler, a manual `run-next` call, or multiple service processes. Physical work is serialized per job, not globally; different jobs can run concurrently.

## Statuses, retry and cancellation

| Operation | Endpoint | Rule |
| --- | --- | --- |
| List | `GET /api/v1/admin/storage/jobs?limit=100` | Limit 1–1000; lease tokens stripped |
| Process one | `POST /api/v1/admin/storage/jobs/run-next` | Claims and runs the next eligible job |
| Retry | `POST /api/v1/admin/storage/jobs/{id}/retry` | Only `failed`; reuses a READY object when one exists |
| Cancel | `POST /api/v1/admin/storage/jobs/{id}/cancel` | Only `queued` or `failed` |

Retry does not reset the attempt count; it clears the error and re-queues. Each claimed attempt increments `attempts`, so a job that keeps failing shows how often it was tried. There is no automatic retry loop for a failed job: the scheduler only processes `queued` jobs and expired leases, and an operator decides when to retry.

A quota breach is a policy outcome, not a transient fault. It is enforced once before any byte is sent and again immediately before publication, and a breach marks the job `failed` with the quota message in `last_error`.

## Inspecting a queue

The dashboard is the friendliest view, but the same data is available over REST:

```bash
# Job rows
curl -sS -b td.cookies \
  'http://127.0.0.1:8080/api/v1/admin/storage/jobs?limit=100'

# Aggregate state counts, alerts and stale-upload samples
curl -sS -b td.cookies \
  http://127.0.0.1:8080/api/v1/admin/storage/health

# Prometheus counters by state
curl -sS -b td.cookies http://127.0.0.1:8080/api/v1/metrics
```

`storage/health` reports `job_states` (the same `queued`/`running`/`staged`/`publishing`/`done`/`failed`/`cancelled` vocabulary), plus alerts for unresolved MTProto sends, stale pending writers, stale multipart completions and failed jobs. Those alerts are diagnostic; they never retry or delete anything.

Related but distinct recovery routes:

- `GET /api/v1/admin/storage/pending-stale` previews aged PENDING uploads from interrupted writers; the `abandon` route fences one of them without deleting Telegram content.
- `GET /api/v1/admin/s3-multipart/stale` and the `recover` route do the same for expired multipart completion leases.
- `GET /api/v1/admin/storage/mtproto-unresolved` lists send intents whose remote acceptance is unknown. Do not retry them until the original channel message has been independently verified.

## Relationship to S3, REST and the catalog

A completed job publishes through the same `catalog.publish` call as an S3 `PUT`, a REST upload or a multipart completion. Therefore:

- the object appears immediately in `aws s3 ls`, `GET /api/v1/buckets/{bucket}/objects` and the dashboard;
- it gets a generation and a published version, visible in **History → Object versions**;
- a versioning-enabled bucket and object lock apply exactly as they do to any other write;
- bucket quotas, key validation and the 2 GiB body policy apply to the job path too.

Jobs only write. Reads never go through the queue, and there is no way to schedule a download or a re-upload of an existing object as a job.

The reverse direction is not true: a job run does not appear in the object list until it is `done`, and a failed or cancelled job never creates a head. The **Queue** and **History** pages are views of the job table; **Object versions** is the view of the catalog.

For the operational recovery tools that inspect Telegram history or rebuild an isolated catalog, see [Command line](cli.md) and [Backup and restore](../operate/backup-restore.md).
