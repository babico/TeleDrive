# Handoff 10 — Owner-run original Telegram DR and physically independent payload backup

**State:** Instructions and test plan only. **Owner executes; development/CI must not touch original media.** Start with `docs/project/plans/local-acceptance.md`, `docs/operate/backup-restore.md`, `scripts/ops/rehearse_telegram_dr.py`.

## A. Read-only original Telegram media recovery rehearsal

1. Owner seals a transactionally consistent SQL snapshot from the real installation and records its SHA256, version/commit, schema and Telegram account/channel identity in a private `0700` evidence directory (receipts `0600`). Never commit secrets or snapshots.
2. On **isolated equipment or a disposable VM**, restore the snapshot to a separate DB/catalog with no ability to mutate production. Supply the original authorized Telethon USER credentials using private secret files.
3. Pick a **known original** bucket, key and optional version with independently known full-object SHA256, size and cross-chunk boundaries. A synthetic/generated object cannot substitute for the original-data attestation.
4. Execute `scripts/ops/rehearse_telegram_dr.py --snapshot "$ORIGINAL_SEALED_DB" --sha256 "$ORIGINAL_SEALED_SHA256" --bucket "$ORIGINAL_BUCKET" --key "$ORIGINAL_KEY" --account "$ORIGINAL_ACCOUNT" --chat-id "$ORIGINAL_CHAT_ID"` on that isolate; do not log the real credentials or target. Verify full bytes and first/middle/cross-boundary/last Range and encrypted-key restore where applicable.
5. Record redacted stdout/stderr, commit SHA, tool versions, exact verified object count, size and digest and failures. Label one-object success **sample DR**, never complete archive recovery. No Telegram deletion or production writes.

## B. Independent physical payload backup and isolated restore

1. Select an owner-controlled physically separate backup host (different actual machine-id and storage failure domain) OR verify an independently hosted encrypted payload export; a second container on one machine is NOT an independent backup.
2. Export and encrypt a consistent set: all live and retained object bytes, historical versions, multipart/dedup alias dependencies, SQL catalog, config, master KEK, Telethon sessions and versioned manifest. Treat key material as independent secrets; no plaintext copy in GitHub artifacts.
3. Store immutable integrity inventory: for each version record bucket/key/versionId, size, SHA256, archived/retention status, chunk identity mapping, timestamp, source catalog SHA and encrypted backup object identifier. Verify completeness, not just one sample. Include key-rotation/recovery instructions.
4. Disconnect the source. Restore metadata and payload into a **new** DB, service instance and disposable private Telegram test channel or another isolated byte backend; reconstruct/verify new message IDs when reuploading. Never assume an old Telegram message ID can be undeleted.
5. Read back entire inventory or a documented statistically meaningful sample plus all risk categories (0/1B, > chunk, multipart, historical, copy/alias, encrypted, locked, archived), SHA and ranges, and record measured RPO/RTO. For a claim of **complete** restore, verify all objects.
6. Deliver owner-only JSON report with `status: PASS | FAIL | BLOCKED_OWNER_INPUT`, evidence hashes, independent host identity hashes, recovery times and explicit limitations; redact private bucket names and phone/channel IDs in shareable summaries.

## C. GC owner choice (no new approval machinery)

GC remains admin-toggle-driven with existing typed confirmations and dry-run. **Never add a required cryptographic acceptance bundle or forced multi-person signoff** to enable it. Present clear destructive consequences and display independent-backup/restore status as warnings, not gates. Owner decides whether and when to delete; collectors still must enforce real object reference, retention, hold, send intent and race fences to prevent deleting live bytes.

## D. Output and boundaries

Agent can prepare repeatable non-destructive scripts, test data and checklists. Owner supplies hardware/credentials and runs real-original-data actions. Failure or missing inputs is `NOT_RUN`/`BLOCKED_OWNER_INPUT`, never a fabricated PASS. No `docker system prune`, production DB overwrite, Telegram broad deletion, or credentials in CI logs.
