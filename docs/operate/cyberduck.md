# Cyberduck (desktop GUI and `duck` CLI)

Cyberduck is a desktop S3 browser for macOS and Windows. Its command-line
front end, `duck`, is built from the same Java code base and the same S3
protocol module, so the wire behaviour described here applies to both.

| Item | Value |
| --- | --- |
| Client tested automatically | Cyberduck / `duck` **9.6.0 (build 46406)** |
| Artefact | `duck_9.6.0.46406_amd64.deb` from the [release-9-6-0 archive](https://github.com/iterate-ch/cyberduck/releases/tag/release-9-6-0) |
| Test | [`tests/s3/test_s3_client_cyberduck.py`](https://github.com/babico/TeleDrive/blob/main/tests/s3/test_s3_client_cyberduck.py) |
| Desktop GUI | Not automated; verify with the [owner checklist](#owner-run-checklist) below |

The automatic test runs the real Java client, not a replica of its requests.
The GUI itself has no automation surface, so the checklist in this page is the
manual counterpart.

## Gateway settings

| Setting | Value |
| --- | --- |
| Server | Your S3 endpoint host, for example `s3.example.com` or `127.0.0.1` |
| Port | `9000` for plain HTTP behind no proxy, or `443` for the TLS listener |
| Protocol | `S3` (`s3://`, HTTPS by default) |
| Access Key ID | The `access_key` of an S3 credential |
| Secret Access Key | The `secret_key` shown once when the credential was created |
| Region | `us-east-1` |
| Addressing | **Path-style** (`http://host:9000/<bucket>/<key>`) |
| Signature | **AWS Signature Version 4** (`AWS4HMACSHA256`) |

The credential needs, at minimum, `s3:ListAllMyBuckets`, `s3:ListBucket`,
`s3:GetBucketLocation`, `s3:GetObject`, `s3:PutObject` and
`s3:DeleteObject`. Add `s3:GetBucketVersioning` if you want Cyberduck's own
version-aware listing; without that scope the version probe is refused like
any other operation the credential cannot perform.

## Required connection profile

Cyberduck cannot connect to this gateway correctly out of the box. Two shipped
defaults get in the way:

- `s3://` is hard-coded to HTTPS/443 ([`S3Protocol.getScheme`](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/S3Protocol.java#L67-L70)), so a plain-HTTP endpoint cannot be reached through the built-in S3 protocol.
- Uploads are **unsigned by default**: `queue.upload.checksum.calculate=false` ([`default.properties` L180](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/defaults/src/main/resources/default.properties#L180)) makes the client send `x-amz-content-sha256: UNSIGNED-PAYLOAD` with no `Content-MD5` ([`S3WriteFeature` L113-L131](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/S3WriteFeature.java#L113-L131)). TeleDrive refuses unsigned mutable uploads by design.

Install a connection profile that fixes the scheme, forces path-style
addressing on hostname endpoints, and turns checksum calculation on. Save it as
`TeleDrive S3.cyberduckprofile`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Protocol</key>
        <string>s3</string>
        <key>Vendor</key>
        <string>TeleDrive</string>
        <key>Name</key>
        <string>TeleDrive S3</string>
        <key>Default Nickname</key>
        <string>TeleDrive S3</string>
        <key>Default Hostname</key>
        <string>s3.example.com</string>
        <key>Default Port</key>
        <integer>80</integer>
        <key>Hostname Configurable</key>
        <true/>
        <key>Port Configurable</key>
        <true/>
        <key>Scheme</key>
        <string>http</string>
        <key>Schemes</key>
        <array><string>s3http</string></array>
        <key>Regions</key>
        <array><string>us-east-1</string></array>
        <key>Properties</key>
        <array>
            <string>queue.upload.checksum.calculate=true</string>
            <string>s3.bucket.virtualhost.disable=true</string>
        </array>
    </dict>
</plist>
```

Install it in the client's profile directory, then restart Cyberduck:

| Platform | Directory |
| --- | --- |
| macOS | `~/Library/Application Support/Cyberduck/Profiles/` |
| Windows | `%APPDATA%\Cyberduck\Profiles\` |
| `duck` on Linux | `~/.duck/profiles/` (or pass `--profile /path/to/file`) |

On macOS and Windows you can also double-click the `.cyberduckprofile` file.

For a **TLS** endpoint, change `Scheme` to `https` and `Default Port` to `443`
(the URL scheme in `Schemes` is only used to select the profile; any distinct
name works). Keep both `Properties` entries in every case.

Why these two properties work:

- `s3.bucket.virtualhost.disable=true` becomes a jets3t property
  ([`RequestEntityRestStorageService` L72-L84](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/RequestEntityRestStorageService.java#L72-L84));
  IP-address endpoints are path-style automatically, but hostnames are not.
- Profile `Properties` are copied both into the jets3t client and into the
  host's preference lookup ([L93-L95](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/RequestEntityRestStorageService.java#L93-L95)),
  so `queue.upload.checksum.calculate=true` reaches the upload filter.
- With checksums on, Cyberduck hashes the body, sends `Content-MD5`, and keeps
  `UNSIGNED-PAYLOAD` — the exact pair the gateway's unsigned-upload rule
  accepts. The MD5 is computed by
  [`S3SingleUploadService.checksum`](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/S3SingleUploadService.java#L44-L46).

## GUI connection

1. Install the profile and restart Cyberduck.
2. Choose **Open Connection** (⌘O / Ctrl+O), then the **TeleDrive S3** profile.
3. Enter the server and port. Leave the path empty to list buckets.
4. Enter the Access Key ID as **Username** and the Secret Access Key as
   **Password**. Do not select anonymous access.
5. Connect. The bucket list appears in the browser pane.

## Owner-run checklist

Run this against a non-production bucket. Tick each line; a failure is a real
finding, not a cosmetic difference.

| # | Action | Expected result |
| --- | --- | --- |
| 1 | Open the TeleDrive profile, enter credentials, connect | Bucket list loads; no `SignatureDoesNotMatch`, `AccessDenied`, or TLS error |
| 2 | **File → New Folder** named `cyberduck-check` | Folder appears; gateway stores a zero-byte key ending in `/` |
| 3 | Upload a binary file larger than 1 MiB into the folder | Transfer completes at 100%; **no** `Unsigned upload requires a signed Content-MD5 or SHA-256 checksum` error |
| 4 | **View → Show Hidden Files** (if off), then refresh | Uploaded file is listed with the correct size |
| 5 | **File → Get Info** on the file | Size matches the local file; modification date is plausible |
| 6 | Download the file to a different directory | File opens; compare hashes locally, for example `sha256sum` / `shasum -a 256` on both copies |
| 7 | Refresh and rename the file with **File → Rename** | New name appears (Cyberduck copies then deletes on S3) |
| 8 | Delete the file | It disappears from the listing; the bucket is versioned, so a delete marker is recorded |
| 9 | Delete the folder | It disappears |
| 10 | Try to delete the bucket while it still has object history | Expected: a `409` with `Bucket has object history; safe physical GC required`. This is TeleDrive policy, not a client fault; see [Garbage collection](garbage-collection.md) |
| 11 | Disconnect, quit Cyberduck, reopen and connect again | Bookmark still works; listing is consistent |
| 12 | Check the server log for the session | No `5xx` responses and no unhandled exceptions |
| 13 | Upload a file **larger than 100 MiB** | Expected: the transfer completes through multipart (initiate, parts, complete). If it fails, capture the failing request; the automatic suite proves the zero-length initiation is accepted |

If step 3 fails with the unsigned-upload error, the profile is not active or
`queue.upload.checksum.calculate=true` is missing from its `Properties`.

### Multipart uploads

Uploads at or above Cyberduck's **100 MiB** multipart threshold
([`s3.upload.multipart.threshold` L345](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/defaults/src/main/resources/default.properties#L345))
are supported. Cyberduck starts the upload with
`POST /<bucket>/<key>?uploads=`, a zero-length body and (on the shipped
unsigned profile) `x-amz-content-sha256: UNSIGNED-PAYLOAD`. The gateway
exempts exactly that zero-length initiation (declared `Content-Length: 0`,
never a chunked body) because it carries no object bytes, and every part is
separately checksummed by Cyberduck
([`S3MultipartWriteFeature` L131](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/S3MultipartWriteFeature.java#L131)).
Every request that can carry bytes still needs a signed digest, so the
checksum profile remains required — with it, Cyberduck signs the empty-body
digest on initiation and each part's checksum thereafter.

The automatic test `test_cyberduck_multipart_upload_completes` forces the
multipart path and asserts the initiation is accepted, a part is uploaded,
and the stored bytes read back identically. If Cyberduck's wire shape or a
gateway rule changes, that test fails and this page must be updated.

## What the automatic test exercises

The `duck` flow in CI, one process per operation (matching how a desktop user
connects and disconnects):

1. `GET /` — ListBuckets.
2. `PUT /<bucket>` — CreateBucket with an empty `text/xml` body for `us-east-1`.
3. `GET /<bucket>?encoding-type=url&max-keys=1000&prefix=&delimiter=%2F` —
   ListObjectsV2, plus `GET /<bucket>?delimiter=%2F&uploads=` for in-progress
   multipart uploads ([`S3ListService` L95-L107](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/S3ListService.java#L95-L107)).
4. `HEAD /<bucket>/<key>` probes, then `GET /<bucket>?object-lock=` before
   upload ([`S3ObjectLockService` L82-L86](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/S3ObjectLockService.java#L82-L86)).
5. `PUT /<bucket>/<folder>/` — CreateDirectory as a zero-byte key with `Content-MD5`.
6. `PUT /<bucket>/<folder>/<file>` — UploadPart-free single PUT with
   `Content-MD5`, `UNSIGNED-PAYLOAD`, `Expect: 100-continue`, and
   `User-Agent: Cyberduck/9.6.0.46406`.
7. `GET /<bucket>?encoding-type=url&max-keys=1000&prefix=<folder>%2F&delimiter=%2F` — long listing.
8. `HEAD` then `GET /<bucket>/<folder>/<file>` — download, compared byte for byte.
9. `GET /<bucket>?versioning`, then `DELETE /<bucket>/<folder>/<file>` — version
   probe ([`S3VersioningFeature` L130-L140](https://github.com/iterate-ch/cyberduck/blob/release-9-6-0/s3/src/main/java/ch/cyberduck/core/s3/S3VersioningFeature.java#L130-L140)) and delete with a versioned delete marker.
10. `DELETE /<bucket>/<folder>/` and `DELETE /<bucket>` — the bucket delete is
    asserted to be refused with the documented object-history message.
11. `POST /<bucket>/<key>?uploads=` — a forced multipart upload (threshold
    lowered to 1 KiB) initiates, uploads a part, completes, and reads back the
    same 6 MiB bytes.

Two more tests pin the boundaries. A profile **without**
`queue.upload.checksum.calculate=true` uploads `UNSIGNED-PAYLOAD` with no
`Content-MD5` and is refused with `400`, and no bytes reach the transport. A
profile that forces the multipart path proves the zero-length initiation is
accepted and the parts complete. If either Cyberduck's defaults or a gateway
rule changes, those tests fail and this page must be updated.

## Not covered

- The **GUI** itself is not automated. The checklist above is the only GUI
  verification.
- **Multipart upload** is exercised end to end through `duck` (see
  [Multipart uploads](#multipart-uploads)); the parts are small enough to run
  quickly, not a throughput or large-object test.
- **Server-side rename** (`--move`), synchronize, ACL editing, and version
  browsing are not exercised by the CLI test.
- **TLS certificate handling** is not exercised; the test uses plain HTTP with
  a loopback endpoint.
