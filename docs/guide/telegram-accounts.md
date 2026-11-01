# Telegram accounts

TeleDrive stores payload chunks by sending them through an authorised
**Telegram user account** over Telethon MTProto. There is no Bot API, no
Saved Messages target and no second transport. This page explains what that
session is, how to create and rotate one or more, and what happens when one
expires.

## What a USER session is

A Telethon `StringSession` is an authorised login for a real Telegram account.
It is not a bot token and not an API key:

- It carries the account's identity and can read and post as that account.
  Treat it exactly like the account password.
- TeleDrive uses it to upload chunks to one **dedicated private broadcast
  channel** where the account has posting rights.
- Saved Messages, groups and ordinary chats are rejected. The startup code
  requires a `Channel` with `broadcast` set and checks `creator` or the
  `post_messages` admin right.
- The client identifies itself as `TeleDrive Storage Client` (with an account
  label appended when several are loaded). That is an honest MTProto device
  name, not a claim to be an official Telegram app. MTProto has no HTTP
  User-Agent.
- Phone numbers, login codes and 2FA passwords are used once interactively.
  Login codes and 2FA passwords are never stored; the account row keeps the
  phone number for identification and masks it in the UI.

Use a dedicated account if you can. A session that leaks gives full access to
whatever account it belongs to, including chats unrelated to TeleDrive.

## Get API credentials

Create an application at [my.telegram.org/apps](https://my.telegram.org/apps)
and note its `api_id` and `api_hash`. Telegram rate-limits login attempts, so
do not loop on code requests. One application normally serves several sessions.

## Provision from the UI (recommended)

The WebUI writes the session to SQL and reloads the runtime immediately. This
is the path used by the shipped Docker deployment.

1. Open **Settings -> Telegram**.
2. Under **Channels**, add the private broadcast channel and activate it.
3. Under **Telegram session (USER MTProto)**, submit the `api_id`,
   `api_hash` and phone number in international format.
4. Choose **Send code**, then enter the code from the Telegram app and the 2FA
   password if the account has one, and choose **Verify & save session**.

The verified account appears in the account table with `authorized = OK`.
Behind the form the UI calls:

```text
POST /api/v1/admin/storage/telegram-session/request-code
POST /api/v1/admin/storage/telegram-session/verify-code
```

Both are interactive-session and CSRF protected. A pending code request lives
for five minutes, is bound to the unauthorised session that requested it, and
is destroyed after five wrong codes. The service stores the authorised
session string in `telegram_sessions` and also mirrors it to
`/data/sessions/<account>.session` (mode `0600`) for compatibility.

## Provision a session file on the host

For a pre-provisioned file that the container reads at startup, run the
interactive helper on a trusted machine:

```bash
export TELEDRIVE_STORAGE_MTPROTO_API_ID=123456
export TELEDRIVE_STORAGE_MTPROTO_API_HASH=0123456789abcdef0123456789abcdef
python scripts/dev/create_storage_user_session.py \
  --output config/mtproto-user.session
chmod 600 config/mtproto-user.session
```

The script asks Telegram for the phone, login code and optional 2FA through
Telethon's interactive `start()`. It refuses to overwrite an existing file and
writes with mode `0600`. It reads the API credentials from the environment;
the server itself does not.

Then reference the file in `config/config.yaml`:

```yaml
storage:
  channel: "-1001234567890"
  strategy: round_robin
  apis:
    - api_id: 123456
      api_hash: "0123456789abcdef0123456789abcdef"
      session_file: "/config/mtproto-user.session"
      account: mtproto-user

    - api_id: 654321
      api_hash: "fedcba9876543210fedcba9876543210"
      session_file: "/config/mtproto-user-2.session"
      account: mtproto-user-2
```

| Field | Required | Meaning |
| --- | --- | --- |
| `api_id` | yes | Numeric Telegram application id. |
| `api_hash` | yes | 32-character application hash. |
| `session_file` | yes, unless `session_string` is used | Path to an authorised session, inside the `./config` mount. |
| `session_string` | alternative | Inline session string. Works, but puts the credential directly in the config and the settings document. |
| `account` | no | Label used by routing, health and logs. Defaults to `mtproto-user`, `mtproto-user-2`, ... |

Every set in `apis` must resolve the **same** channel. The service validates
this at startup and refuses to run if two sets resolve different channel IDs.

!!! note "SQL sessions win"
    Sessions created from the UI are stored in the `telegram_sessions` table
    and take precedence over `storage.apis`. A deployment that used the UI
    does not need `apis` at all. When the table has no usable rows, the
    config list is used.

## How the channel is resolved

- A numeric private ID such as `-100...` must be visible in the signed-in
  account's dialogs. The runtime searches the first 5,000 dialogs.
- A username or public link is resolved directly. If that fails, the runtime
  falls back to a case-insensitive match on dialog titles, which is why the
  display name in the UI can help.
- The target must be a broadcast channel with posting rights, and every
  credential set must agree on it.
- The channel that is **active** in SQL is the write target. `storage.channel`
  in the file is a fallback when no channel row exists.

Uploads go to the active channel only. Adding a second channel does not
shard objects across channels; it changes where new objects are written.

## Rotation strategies

`storage.strategy`, or the strategy selector on the Storage page, controls how
one upload is distributed across the configured accounts.

| Strategy | Behaviour |
| --- | --- |
| `single` | Use only the first credential set. No rotation. |
| `round_robin` (default) | Rotate to the next set before each send, so concurrent chunk sends receive distinct accounts. |
| `failover` | Stay on the current set. Advance only after a **definite** flood-wait rejection. |
| `parallel` | Rotate like round-robin and expose concurrency equal to the number of sets, so chunks are uploaded in parallel across accounts. |

Two rules apply to every strategy:

- **Bucket-to-account pins win.** A bucket can be pinned to an account in the
  UI; that explicit choice overrides rotation and quota preference.
- **Ambiguous outcomes never move to another account.** A network failure that
  cannot prove the send was rejected stops with "send outcome uncertain" and
  leaves a durable send intent in SQL. Retrying the chunk on a different
  account could create a duplicate or lose the real message id. Only a
  definite `FloodWaitError` clears the rejected intent and retries elsewhere.

Cross-account replication is a separate, optional feature
(`storage.replica_account`). It sends a copy to another account best-effort;
reads fall back to the replica when the primary message is unavailable. It is
not a substitute for a real backup and is disabled for envelope-encrypted
objects.

## Soft quotas

Each account row has `soft_quota_bytes` (nullable = unlimited). It is set per
account on **Settings -> Telegram** and is checked against the account's
current catalog usage.

It is a **routing preference**, not a hard cap. When the selected account is
over quota and another is under it, the sender prefers the other account. If
every account is over quota, the strategy's original choice is used and the
upload still proceeds. The check result is cached for 60 seconds.

Bucket quotas and HTTP request size limits are hard limits and are described in
[Configure](../start/configure.md#limits-and-quotas).

## Health, flood waits and expiry

| Signal | Where it comes from |
| --- | --- |
| `authorized` / `OK` / `UNAUTHORIZED` | A lightweight `connect` + `is_user_authorized` probe. It runs in the background every 30 minutes and on demand with **Check**. |
| Usage and retained bytes | Catalog aggregates over current heads versus all chunks. Retained bytes are deleted objects awaiting owner-gated GC. |
| Cooldown | Shared per-account, per-chat cooldown written by every worker after a Telegram flood wait. A send waits it out; the recorded wait is capped at one hour. |
| Flood observations | Cumulative count from the MTProto flood table, shown next to the health state. |
| Login flood | `GET /api/v1/admin/storage/telegram-session/floodwait` and the red banner on the Storage page. |

When a session expires or is revoked:

- the probe marks the account `UNAUTHORIZED` and logs a warning;
- uploads fail closed instead of falling back to another transport;
- re-authenticate the same account with a new code. Restarting the container
  does not repair an invalid session string.

The probe checks authorization, not channel membership. A channel removed from
the account, or posting rights revoked, surfaces when the runtime starts or
when an upload fails.

## Adding and removing accounts

- **Add:** log in again with a different phone number. A new row is created per
  account (the account label is unique). The runtime reloads.
- **Remove:** **Delete** on the account row. If the catalog still has chunks
  stored by that account, the API answers `409` unless `force=true`; the
  catalog rows survive either way, but those objects can only be read after
  the account is authorised again.
- Removing the last account stops uploads; existing objects remain in the
  catalog and become unreadable until a session that can access their channel
  is authorised.

A new account whose channel is inaccessible or differs from the others makes
the runtime fail to start, which takes uploads down for every account until it
is fixed. Add accounts one at a time and check the Logs page.

## Security

- A session string is a credential with full account access. Store it `0600`,
  never commit it, and never paste it into an issue, CI log or chat.
- `/data/sessions/` contains a plaintext mirror of UI-created sessions, and a
  database dump contains `telegram_sessions.session_string`. A database backup
  is therefore also a credential backup; encrypt it and restrict it.
- `GET /api/v1/config` redacts fields whose names look like credentials,
  including `api_hash` and `session_string`, and the durable audit trail
  refuses to store credential-shaped values. That does not make the database
  or the session file safe to publish.
- If a session leaks, terminate it in Telegram under **Settings -> Devices**
  (or Active Sessions) and create a new one. Deleting the TeleDrive row alone
  does not revoke the Telegram login.
- Two-step verification is supported during login; TeleDrive never stores the
  2FA password.

## What is not supported

- Bot tokens and the Bot API.
- Saved Messages (`me` / `self`) as the storage target.
- Groups or channels without post rights.
- Reading Telegram credentials from server environment variables. The runtime
  reads SQL first, then `storage.apis`; only the standalone session-creation
  script reads `TELEDRIVE_STORAGE_MTPROTO_*`.
- Automatic migration of objects uploaded by the retired Bot transport. A
  catalog row that still points at an accessible message can be read through
  the user session, but there is no Bot-token fallback.

Physical deletion of Telegram messages remains disabled (`deletion_permitted`
is `False`). See [Garbage collection](../operate/garbage-collection.md) and
[Backup and restore](../operate/backup-restore.md).
