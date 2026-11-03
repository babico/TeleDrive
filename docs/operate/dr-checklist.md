# Original-media DR checklist

This is the single page an owner follows to rehearse a **read-only** recovery of one original Telegram-backed object on isolated hardware. The rehearsal verifies a sealed SQL snapshot, restores it into a disposable clone and reads one owner-named object back through the production engine. It never writes to the source database, never uploads to Telegram and never deletes a Telegram message. A pass is a **sample DR** for one object; it is not proof of a complete archive recovery and it does not authorize garbage collection.

Before starting, read [Backup and restore](backup-restore.md) for what a recoverable set contains. Development agents and CI must never run these steps: only the owner supplies the hardware, credentials and original data.

## 0. Prepare the isolate

- [ ] A disposable machine or VM that is **not** the production host and has **no** ability to mutate production: no production database URL, no shared Docker daemon, no mounted production volumes.
- [ ] A fresh clone of the repository at the exact commit under review, with `.venv` created per the README.
- [ ] A private evidence directory outside the Git checkout:

```bash
export EVIDENCE="$HOME/teledrive-dr-evidence/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVIDENCE"
chmod 700 "$EVIDENCE"
umask 077
```

- [ ] Prove the tooling itself before touching original data — this is fully offline:

```bash
python scripts/ops/rehearse_telegram_dr.py --self-test
```

The self-test prints `{"self_test": "PASS", ...}` with one entry per scenario (sample object, encrypted restore, refused snapshot digest, missing object, refused scope, corrupt chunk, missing chunk, missing key). Any `FAIL` stops the rehearsal: fix the tooling first.

- [ ] Record the reviewed commit and tool versions in the evidence directory:

```bash
git rev-parse HEAD | tee "$EVIDENCE/commit-sha.txt"
python --version | tee "$EVIDENCE/python-version.txt"
```

## 1. Seal the snapshot

Take the SQL snapshot from the real installation exactly as [Backup and restore](backup-restore.md) describes, then seal and receipt it. For SQLite:

```bash
python scripts/ops/backup_metadata.py \
  --database /data/state.db \
  --output "$EVIDENCE/sealed-original.db"
sha256sum "$EVIDENCE/sealed-original.db" | tee "$EVIDENCE/sealed-original.sha256"
python scripts/ops/verify_metadata_backup.py \
  --database "$EVIDENCE/sealed-original.db" \
  --sha256 "$(cut -d' ' -f1 "$EVIDENCE/sealed-original.sha256")"
```

For PostgreSQL use `pg_dump --format=custom`, for MySQL a `--single-transaction` dump; in both cases record the SHA-256 of the dump file the same way. Never seal a snapshot by copying a live SQLite file with `cp`.

- [ ] The receipt file is `0600`, the evidence directory stays `0700`, and neither the snapshot nor any secret is ever committed.

## 2. Record the identities

On the isolate, write down (private notes, never the repo) the facts the rehearsal will check:

- [ ] The reviewed commit SHA (step 0).
- [ ] The database schema version of the snapshot.
- [ ] The original Telegram **account label** under which the object's chunks were journaled (for example `api-bot` or the USER account label from `storage.apis`).
- [ ] The original **channel chat id** (a `-100…` number) and, if you use `--target`, its username or id.
- [ ] The chosen sample object: **bucket, key, optional VersionId**, and its **independently known full-object SHA-256 and size** — from your own records of the original file, not from the TeleDrive catalog. A synthetic or generated object cannot substitute for this attestation.
- [ ] The Telethon USER session file (`0600`), its `api_id` and `api_hash`, held in private files on the isolate only.

## 3. Run the rehearsal

```bash
export TELEDRIVE_STORAGE_MTPROTO_API_ID=...      # from your private notes
export TELEDRIVE_STORAGE_MTPROTO_API_HASH=...    # from your private notes
export TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE=/secure/mtproto-user.session

python scripts/ops/rehearse_telegram_dr.py \
  --snapshot "$EVIDENCE/sealed-original.db" \
  --sha256 "$(cut -d' ' -f1 "$EVIDENCE/sealed-original.sha256")" \
  --bucket "$ORIGINAL_BUCKET" \
  --key "$ORIGINAL_KEY" \
  --account "$ORIGINAL_ACCOUNT" \
  --chat-id "$ORIGINAL_CHAT_ID" \
  --object-sha256 "$ORIGINAL_OBJECT_SHA256" \
  --object-size "$ORIGINAL_OBJECT_SIZE" \
  --evidence-dir "$EVIDENCE"
echo "exit=$?"
```

Notes:

- `--target` is optional and defaults to the numeric `--chat-id`; pass a username when the channel is easier to identify that way.
- `--version-id` selects a specific published version instead of the current head.
- `--object-sha256`/`--object-size` are optional but strongly recommended: they cross-check the catalog against your independent records and fail the run on any disagreement.
- `--master-key-file` supplies the deployment master key (the Fernet `s3-master.key` file) when the sample object is envelope-encrypted (SSE-S3). SSE-C objects are refused: customer key material is not accepted by this rehearsal.
- The script connects a read-only USER MTProto session against the original channel only, refuses bot sessions, and exposes no upload or delete path.

## 4. What PASS looks like

- Exit code `0`, and a JSON report on stdout with:

```json
{
  "claim": "sample DR (one object); not complete archive recovery",
  "encrypted_key_restore_verified": false,
  "readback_bytes": 65537,
  "sha256": "…independent digest you recorded…",
  "size": 65537,
  "source_database_modified": false,
  "telegram_deletions": 0,
  "telegram_uploads": 0,
  "verified": true,
  "verified_object_count": 1,
  "verified_ranges": [["first", 0, 37], ["middle", …], ["cross-boundary-1", …], ["last", …]]
}
```

- `verified_ranges` contains the **first, middle, every (bounded) cross-chunk-boundary and last** windows, each compared byte-for-byte against the fully verified file, in addition to the full-object SHA-256 and size check.
- A `dr-rehearsal-…json` evidence record was written into `--evidence-dir` (`0600`, directory `0700`) containing the status, commit SHA, tool versions, script SHA-256, snapshot SHA-256, verified object count, size, digest, verified ranges and redacted stdout/stderr.
- Label the result **sample DR** in your notes. One object passing never means the archive is recovered.

## 5. What the other exit codes mean

| Exit | Meaning | Owner action |
| --- | --- | --- |
| `0` | PASS — one sample object fully verified | Record evidence; this is a sample DR only |
| `1` | Unexpected failure or missing MTProto environment | Check `TELEDRIVE_STORAGE_MTPROTO_*`; re-run; do not improvise |
| `2` | Sealed snapshot rejected (SHA-256 receipt, SQLite integrity, schema) | The snapshot or its receipt is wrong; re-seal — never edit the receipt to match |
| `3` | Object or remote chunk not found | Wrong bucket/key/VersionId, or the Telegram message is gone; pick another sample or record the loss |
| `4` | Account/channel scope refused, or the object exceeds `--max-bytes` | Fix the account label/chat id, or raise the explicit budget deliberately |
| `5` | Payload, range or attestation verification failed | Bytes or catalog disagree with independent evidence; treat the object as damaged and investigate |
| `6` | Encrypted object without usable key material | Supply `--master-key-file`, or accept that the object cannot be verified |

A failure exit is a real result — record it. Never re-run with looser flags just to turn it into a pass.

## 6. BLOCKED_OWNER_INPUT

`BLOCKED_OWNER_INPUT` means a required owner-supplied input does not exist or was not authorized: no sealed snapshot, no independent digest, no USER session, no original channel access, or no isolated hardware. In that case the DR rehearsal is **not run** — record `BLOCKED_OWNER_INPUT` with the missing input named, and never substitute synthetic data, a production database, a fabricated digest or a second container on the same host for the real thing. A missing input is never a PASS and never a reason to touch production.

## 7. Redaction rules for anything you share

The evidence record is already redacted, but apply these rules to **anything** that leaves the isolate (bug reports, issues, messages):

- Replace the bucket name, object key, account label, channel username, chat id, phone numbers, `api_id`/`api_hash`, session file content and master key with `[REDACTED]`.
- Never paste the session file, the master key, the sealed snapshot or the receipt file itself — only their SHA-256 values.
- Telegram channel ids (`-100…`) are scrubbed as `[REDACTED:channel-id]` by the script; check your own notes for the same pattern before sharing.
- Safe to share: exit code, the JSON report, the redacted evidence record, commit SHA, tool versions, verified ranges, object size and digest.
- When in doubt, share only the `dr-rehearsal-…json` file — it is produced redacted for exactly this purpose.

## 8. After the rehearsal

- [ ] Copy the evidence record and the JSON report into your private change record.
- [ ] Destroy the isolate (VM) or clean the disposable directory; keep only the redacted evidence.
- [ ] Do not enable physical GC on the strength of a sample DR; the GC gates in [Garbage collection](garbage-collection.md) are unchanged.
- [ ] A complete archive recovery claim requires the independent payload backup and full-inventory verification described in [Backup and restore](backup-restore.md), not this checklist.
