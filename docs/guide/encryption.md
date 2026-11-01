# Encryption

TeleDrive has three encryption states for object payloads: none, SSE-C with a key the client supplies per request, and opt-in envelope encryption (the SSE-S3 shape) where the deployment holds the keys. They protect different things. None of them protects against a compromised running server, and none replaces an independent backup.

This page describes what the code actually implements. The operation-level contract for encryption headers and bucket configuration is in [S3 compatibility](../reference/s3-specs.md); the threat model is in [Access model](../security/model.md).

## What each mode protects

| Mode | Telegram sees | A database or disk copy | A compromised running server | Lost key |
| --- | --- | --- | --- | --- |
| None (default) | Plaintext | Plaintext manifests and plaintext payloads on disk/Telegram | Everything | Not applicable |
| SSE-C | Ciphertext per chunk | Ciphertext; the key is never stored | Attacker can read request memory and plaintext | Client loses the key: object unreadable |
| Envelope (SSE-S3) | Ciphertext per chunk | Ciphertext plus wrapped data keys; the master key is outside the database | Attacker with the master key can decrypt | Master key lost: object unreadable |

What no mode protects:

- **Object metadata.** Bucket names, keys, sizes, SHA-256 digests, versions, tags, annotations, timestamps and access history stay in SQL in plaintext. Encryption hides bytes, not the shape of your data.
- **The staging file.** An upload is written to `storage.scratch_dir` before it is chunked and encrypted. During an upload the plaintext exists on the server's filesystem and in process memory. The scratch file is removed after the attempt, but a live-host attacker or an unclean crash can observe it.
- **A server that is already compromised.** Envelope encryption keeps the master key in a file the service reads; SSE-C keeps the customer key in request memory. An attacker who can read either can read the plaintext.
- **Telegram account compromise.** The Telegram session can post and read messages in the channel. Ciphertext limits what is readable, but the attacker can still disrupt or delete storage.

Ordinary Telegram cloud chats are not end-to-end encrypted. Without SSE-C or envelope encryption, Telegram itself can read uploaded bytes.

## Mode 1: none

This is the default. `storage.encryption` is unset or `none`, no customer headers are sent and no bucket default is configured. Payloads reach Telegram as plaintext, deduplication and replication work on plaintext, and content search can index text-extractable objects.

SSE-C still works in this mode: it is always available and does not depend on the deployment setting.

## Mode 2: SSE-C (customer-supplied key)

The client generates a 32-byte AES-256 key and sends three headers with the request:

```http
x-amz-server-side-encryption-customer-algorithm: AES256
x-amz-server-side-encryption-customer-key: <base64 of 32 bytes>
x-amz-server-side-encryption-customer-key-MD5: <base64 of MD5(raw key)>
```

All three are required together, must be signed by SigV4, and are parsed before any byte is staged. A partial family, an unsigned family, a non-`AES256` algorithm, a wrong key length or a mismatched MD5 is `400 InvalidArgument`. Key material is never persisted, never logged and never placed in an error message.

How the bytes are protected:

- Every Telegram chunk is encrypted with AES-256-GCM under a fresh 12-byte random nonce.
- The AAD binds the ciphertext to its object identity: the immutable object UUID in ASCII (36 bytes) followed by the chunk ordinal as an unsigned 8-byte big-endian integer.
- Multipart parts are encrypted for their own staged part object; completion moves the chunks and records the authenticated identity in each chunk's metadata. A spliced chunk, a cross-object copy or a reordered layout fails GCM authentication or the structural layout check.
- The key never enters SQL. Only a non-secret key MD5 fingerprint is stored so `HEAD` can tell you that you supplied the wrong key without decrypting.
- `HEAD` verifies the fingerprint and returns the SSE-C algorithm and key-MD5 response headers.
- Every read needs the same key. A missing or wrong key is `400 InvalidRequest` before any plaintext is emitted. The REST API and the Web UI cannot supply a customer key, so they refuse SSE-C objects instead of streaming an empty body.
- Multipart initiation binds the upload to the key fingerprint; every `UploadPart`, `ListParts` and `CompleteMultipartUpload` must present the same key.
- `PUT ?encryption` (UpdateObjectEncryption) re-encrypts an existing object's chunks to a new customer key in a bounded pass and swaps the references in one transaction. The old key goes in the `x-amz-copy-source-*` SSE-C headers when the object is already encrypted.
- An interrupted SSE-C upload cannot be resumed: the server does not retain the key, so it fails closed rather than uploading the remaining chunks in plaintext.

SSE-C objects are excluded from deduplication, replication and the content index by construction: identical plaintext under different keys must not share ciphertext, and indexing plaintext would defeat the point.

### Using SSE-C

`aws s3 cp` and many tools do not implement SSE-C. With the AWS CLI, provide the key material per command:

```bash
KEY_B64=$(openssl rand -base64 32)
KEY_MD5=$(printf '%s' "$KEY_B64" | base64 -d | openssl dgst -md5 -binary | base64)

aws --endpoint-url http://127.0.0.1:9000 s3api put-object \
  --bucket backups --key secret.bin --body ./secret.bin \
  --sse-customer-algorithm AES256 \
  --sse-customer-key "$KEY_B64" \
  --sse-customer-key-md5 "$KEY_MD5"
```

Store the raw key somewhere safe and out of band. There is no recovery path if it is lost: the server never had it.

A bucket can also store an empty encryption rule set (`PutBucketEncryption` with no default) to document that clients are expected to supply SSE-C keys. It does not create or manage keys.

## Mode 3: envelope encryption (SSE-S3)

Envelope encryption makes "encrypted at rest" a server property, so clients that cannot do SSE-C still get ciphertext.

### Key hierarchy

1. The deployment has one **master key**: a Fernet key loaded from `storage.s3_master_key_file` (default `/config/s3-master.key`), or from `TELEDRIVE_S3_MASTER_KEY` if no file is configured.
2. A **KEK** is derived from it with HKDF-SHA256 and the fixed info string `teledrive-envelope-v1`. The derivation is domain-separated from the credential store's use of the same master secret, so compromising one use does not directly hand over the other.
3. Each object gets a fresh 32-byte random **DEK**. The DEK encrypts that object's chunks exactly like an SSE-C key, with the same nonce and AAD scheme.
4. The DEK is wrapped with AES-256-GCM under the KEK, using the object UUID as AAD. Only the base64 wrapped form is stored in SQL, in the object encryption row.
5. Reads look up the object's wrapped key, unwrap it with the deployment KEK, and decrypt each chunk. A replaced master key fails the unwrap and is reported as a named error, not garbage.

A database dump without the master key therefore yields ciphertext and wrapped keys that cannot be opened. A dump *with* the master key yields everything.

### Enabling it

Set the deployment mode in `config/config.yaml`:

```yaml
storage:
  encryption: envelope
  s3_master_key_file: "/config/s3-master.key"
```

`TELEDRIVE_ENCRYPTION=envelope` is accepted as a fallback when the config key is absent, but the config file is the documented source. The value is validated at startup: anything other than `none` or `envelope` is a configuration error, not a silent fallback. Restart after changing it.

The master key must be a valid Fernet key (32 random bytes encoded as a 44-character URL-safe base64 string). Generate one once and keep it out of Git:

```bash
.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' \
  > config/s3-master.key
chmod 600 config/s3-master.key
```

The file is read with `O_NOFOLLOW` and its first 256 bytes are stripped and validated as a Fernet key. A missing, unreadable or malformed key makes S3 credential operations and envelope reads fail closed. The same key also encrypts issued S3 credential secrets and the SQL settings document, so it is not optional for an S3 deployment even with encryption set to `none`.

Enabling envelope mode is **not retroactive**. Existing objects keep the mode they were written with. Apply it to new writes in either of two ways:

- **Per bucket default:** `PutBucketEncryption` with one `AES256` rule. Every plain `PUT` to that bucket is then envelope-encrypted. This is accepted only while `storage.encryption` is `envelope`.
- **Per request:** send `x-amz-server-side-encryption: AES256` on the `PUT`.

```bash
aws --endpoint-url http://127.0.0.1:9000 s3api put-bucket-encryption \
  --bucket backups \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

`GetBucketEncryption` reads the real stored document. `DeleteBucketEncryption` removes the bucket default but does not decrypt anything already written; objects remain readable with the same master key.

### What it disables

Encrypted objects are not deduplicated, not replicated and not content-indexed. All three operate on plaintext:

- **Deduplication** would let a dedup hit reveal that two objects have identical plaintext, and identical ciphertext must never be shared across objects.
- **Replication** would need the wrapped DEK on another Telegram account; a partial replica is worse than none.
- **Content search** indexes plaintext text; indexing an encrypted object would defeat encryption.

The engine enforces this by disabling dedup whenever a customer key or envelope KEK is present, and by skipping content indexing for encrypted objects. `teledrive.storage.envelope.capabilities()` reports the same facts as data:

```json
{
  "mode": "envelope",
  "algorithm": "AES256",
  "deduplication": false,
  "replication": false,
  "content_search": false
}
```

If you need deduplication, replication or full-text search, leave the deployment at `none` and use SSE-C only for the specific objects that need client-held keys.

## Failure modes

| Symptom | Cause | Behaviour |
| --- | --- | --- |
| `501` naming `storage.encryption` | `AES256` requested while the deployment is `none`, or a bucket `AES256` default exists without the setting | Refused before staging; never a silent plaintext write |
| `501` for `aws:kms` | No AWS KMS exists | Refused by name; use `AES256` under envelope mode or SSE-C |
| `400 InvalidRequest`: wrapped key missing / truncated / not base64 | Corrupt or partially deleted encryption row | Fail closed; no plaintext is produced |
| `400 InvalidRequest`: cannot decrypt with this deployment's master key | The master key was replaced or rotated | Fail closed with a named error; restore the original key |
| `400` saying the deployment no longer has envelope enabled | The object is SSE-S3 but the setting is now `none` | Re-enable the setting with the same key; do not rewrite the object |
| `400 InvalidRequest` on SSE-C read | Missing, incomplete, unsigned or wrong customer key | Refused before any plaintext is emitted |
| SSE-C upload cannot resume | An interrupted upload has no retained key | The job/request fails; retry with the key |
| S3 credential create/reveal `503` | Master key missing, unreadable or invalid | Fail closed; fix the key file |
| Object is `403 InvalidObjectState` | It was tiered to an archive access class | Restore it first; this is tiering, not encryption |

Envelope encryption is a read-time dependency on the master key. Back up the key separately from the database, because a database restore without it leaves every envelope object and every S3 credential secret unreadable. Storing the key in the same backup set removes that specific protection: a thief who takes the backup gets both.

## Key rotation and recovery

There is **no automatic master-key rotation** and no re-wrap command. The master key is a single deployment secret that wraps every object DEK and encrypts every S3 credential secret and the SQL settings row. Replacing it does not re-encrypt existing data; it makes existing envelope objects and credentials fail closed.

- **Lost master key:** there is no recovery. The wrapped DEKs cannot be opened. The only path is to restore the original key from backup, or to accept that the encrypted payloads are gone and re-upload plaintext from the original source.
- **Suspected key exposure:** treat every S3 credential and every envelope object as compromised. Issue new credentials, and plan an offline migration: read objects with the old deployment, write them into a new deployment or catalog with a new master key, then retire the old one. Test that migration on a copy; there is no in-place tool that swaps the KEK of existing objects.
- **S3 credential secrets:** these use the same master key but a different encryption context (Fernet, not the envelope KEK). A new key makes existing credential secrets undecryptable; re-issue them. The settings document in SQL is also encrypted with the master key, so a replaced key makes the service fall back to `config/config.yaml` until the next save re-seeds it.
- **SSE-C key rotation:** use `UpdateObjectEncryption` (`PUT ?encryption`) with the old key in the copy-source headers and the new key in the customer headers. That operation exists for SSE-C only; it cannot re-wrap an envelope object.

Store the master key in a secret manager or a protected file outside the backup that contains the database, document where it is, and rehearse restoring both together. An untested key backup is a hope, not a recovery plan.

## Choosing a mode

| Requirement | Recommended mode |
| --- | --- |
| Maximum compatibility, deduplication, replication, content search | None |
| Client-controlled keys, no server-held key for those objects | SSE-C per object |
| Encryption at rest for clients that cannot do SSE-C | Envelope, accepting no dedup/replication/content search for encrypted objects |
| Protection from Telegram reading payloads | SSE-C or envelope; none does not provide it |
| Protection from a compromised server | None of these; isolate the host and protect the master key |

For the exact headers, bucket documents, error codes and per-operation support, see [S3 API](s3-api.md) and [S3 compatibility](../reference/s3-specs.md).
