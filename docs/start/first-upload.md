# First upload

This walkthrough takes a fresh installation to a verified object: log in,
replace the shipped administrator password, connect a Telegram account, create
a bucket, upload a file in the browser, and read the same bytes back over S3.
It assumes the container is running and healthy; if it is not, start with
[Install](install.md).

## 1. Log in and change the password

Open `http://127.0.0.1:8080` and sign in with:

- username: `admin`
- password: `admin`

!!! danger "The first-boot account is public knowledge"
    Every installation starts with `admin` / `admin`. The server enforces the
    rotation: until the password is changed, **every** authenticated
    operation — REST data, S3 (including credential issue and presigning),
    API keys, user management, even the WebSocket log stream — answers
    `403` with a `bootstrap_password_change_required` error. Only login,
    current-user info, logout and the password change itself are allowed.
    Nothing else can be done with the default credential, by anyone.

After signing in, the login page itself shows the change-password form.
Enter the current password (`admin`) and a strong new password:

- at least 8 characters,
- mixing letters with digits or symbols,
- different from the shipped default.

The change rotates the session: the browser stays signed in with a fresh
cookie, and every other session of the account (including the one the
login created) is revoked. The equivalent API call is
`POST /api/v1/auth/password` with `{"current_password": "...",
"new_password": "..."}` plus the `X-TeleDrive-CSRF: 1` header.

The `admin` username cannot be renamed, and restarting the container never
resets an existing password. If you prefer the Users page, an admin can
also force-change any account's password there (**Users -> the row ->
Password**), but the self-service form above is the intended first-boot
path because the user-management API is itself gated until the rotation
completes.

API keys and S3 credentials issued while the default password was still
active are refused until the rotation completes — on a genuine first boot
none can exist yet (issuing is part of the gated surface), so anything
that still answers was minted under the public credential. They work
unchanged once the admin password has been changed.

If the password is lost later, recovery requires filesystem and database
access; see [Upgrade](../operate/upgrade.md#locked-out-admin).

## 2. Create a bucket

1. Open **S3 -> Buckets**.
2. Choose **New bucket**.
3. Enter a name of 3 to 63 characters and create it.

The bucket is a row in the SQL catalog, not a Telegram object. Uploading into
it later creates the first object version and its chunk messages.

## 3. Connect a Telegram account

Do this on **Settings -> Telegram**. The page has two independent parts:
channels and sessions.

### Add and activate the channel

1. Under **Channels**, choose **Add channel**.
2. Enter a display name and the channel ID or username. A private channel
   usually looks like `-100...`; a public one can be `@name` or the plain
   username.
3. Choose a rotation strategy (the default `round_robin` is fine for one
   account) and keep the scratch directory `/data/tmp`.
4. Create it, then choose **Activate**.

The channel must be a **broadcast channel** where the account has posting
rights. Saved Messages, groups and channels the account cannot post to are
rejected when the session starts, not when the form is submitted.

### Request and verify the login code

1. In **Telegram session (USER MTProto)**, enter the `api_id`, `api_hash`
   from [my.telegram.org/apps](https://my.telegram.org/apps) and the phone
   number in international format (`+...`).
2. Choose **Send code**. Telegram sends the code to that account's Telegram
   app, not by SMS in the normal case.
3. Enter the code, plus the 2FA password if the account has one, and choose
   **Verify & save session**.

The service stores the authorized session in SQL and mirrors the string to
`/data/sessions/<account>.session` for compatibility. The verified account
appears in the account table with health `OK`. Neither the phone code nor the
2FA password is stored.

### What can go wrong

| Symptom | Cause and fix |
| --- | --- |
| `api_id, api_hash and phone are required` | One field is blank, or the phone lacks the leading `+` and country code. |
| `The code has expired` | Codes are valid for a short window. Request a new code and use the newest Telegram message; every request invalidates earlier codes. |
| `No pending code request` | The token expired after five minutes, was already used, or the request was destroyed after five wrong codes. Start again. |
| `SessionPasswordNeededError` / 2FA prompt | The account has two-step verification. Enter the 2FA password in the optional field. |
| `FloodWait` with seconds remaining | Telegram rate-limited code requests or sign-in. Wait the displayed time; retrying sooner extends it. |
| `Use a real Telegram USER session, not a bot token` | The credentials belong to a bot. TeleDrive needs a user account. |
| Channel not found in dialogs | For numeric private IDs the runtime searches the first 5,000 dialogs of the signed-in account. Join or open the channel with that account, or use its username. |
| `User must have channel posting rights` | The account is not an administrator with "Post messages" in that channel. |
| Uploads still `503` after the session is saved | No channel is active, or the runtime reload failed. Check the Logs page and activate a channel. |

For multiple accounts, file-based sessions, rotation semantics and recovery,
see [Telegram accounts](../guide/telegram-accounts.md).

## 4. Upload from the UI

1. Return to **S3 -> Buckets** and open the bucket you created.
2. Drag a file onto the drop area, or click it and choose a file.
3. Wait for the progress indicator to finish. The object appears in the
   bucket listing with its size.

The browser sends `PUT` to
`/api/v1/admin/storage/buckets/{bucket}/content?key={key}` with the CSRF
header. The server splits the payload into 16 MiB chunks, uploads each chunk
as a document message to the active channel, and commits the object head and
chunk manifest in SQL. Partially uploaded objects are not published.

## 5. Read it back over S3

S3 clients need an access key pair, which is separate from the WebUI login.

1. Open **S3 -> Credentials** and choose **Generate new credentials**.
2. Give it a name and a permission preset. Creating a credential without an
   explicit permission list grants a **read-only** set (list buckets, list
   bucket, get location, get object, get attributes); it no longer grants
   every permission.
3. Copy the secret immediately. It is shown once, and only an interactive
   login session can reveal it again.

The gateway signs SigV4 in the single region `us-east-1`. The read-only
default is enough for the commands below; add `s3:PutObject` if you also want
to upload over S3. The examples assume the object you uploaded in step 4 is
named `hello.txt`.

```bash
export AWS_ACCESS_KEY_ID='TD...'
export AWS_SECRET_ACCESS_KEY='...'
export AWS_DEFAULT_REGION=us-east-1

aws --endpoint-url http://127.0.0.1:9000 s3 ls
aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://my-bucket/
aws --endpoint-url http://127.0.0.1:9000 s3 cp s3://my-bucket/hello.txt ./hello.copy
```

The same read with boto3, including a real integrity check:

```python
import base64
import hashlib

import boto3

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:9000",
    region_name="us-east-1",
    aws_access_key_id="TD...",
    aws_secret_access_key="...",
)

response = s3.get_object(
    Bucket="my-bucket", Key="hello.txt", ChecksumMode="ENABLED"
)
body = response["Body"].read()
remote_sha256 = base64.b64decode(response["ChecksumSHA256"])
assert hashlib.sha256(body).digest() == remote_sha256
print(len(body), remote_sha256.hex())
```

`ChecksumMode="ENABLED"` makes the gateway return
`x-amz-checksum-sha256`, the SHA-256 of the full plaintext object from the
immutable manifest. Without it you can still hash the downloaded bytes and
compare them with the local file:

```bash
sha256sum hello.txt hello.copy
```

For SSE-C objects the checksum headers are not returned without the customer
key; see [Encryption](../guide/encryption.md).

## 6. What you should see

| Check | Expected |
| --- | --- |
| UI bucket listing | The object with the size you uploaded. |
| `aws s3 ls s3://my-bucket/` | The same key and size. |
| `sha256sum` of source and download | Identical digests. |
| S3 `HEAD` / `GET` with checksum mode | `x-amz-checksum-sha256` matches the local digest. |
| **Settings -> Telegram** account table | The account is `OK`, and its usage grew by the object size. |

## 7. Where the object actually lives

- **Payload:** one Telegram message per 16 MiB chunk in the active private
  channel, sent as a document with the caption
  `teledrive:<object_id>:<ordinal>:<checksum-prefix>`. Telegram holds the
  bytes.
- **Metadata:** the bucket, object head, version, chunk coordinates
  (`account`, `chat_id`, `message_id`), size and full-object SHA-256 live in
  SQL.
- **Both are required to read an object.** Deleting a Telegram message behind
  TeleDrive's back makes the object unreadable; losing the database leaves the
  bytes in Telegram but unindexed.

Deleting an object in the UI unlinks it from the catalog. Physical deletion of
the Telegram messages is a separate, owner-gated operation and remains
disabled (`deletion_permitted` is `False`); see
[Garbage collection](../operate/garbage-collection.md).

## Next

- Query the object with the REST API: [REST API](../guide/rest-api.md).
- Use `rclone`, presigned URLs and the full S3 surface:
  [S3 API](../guide/s3-api.md).
- Import a directory from `./uploads`: [Local file jobs](../guide/local-jobs.md).
- Make the first backup before uploading anything you cannot replace:
  [Backup and restore](../operate/backup-restore.md).
