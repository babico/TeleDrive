# Website hosting

A TeleDrive bucket can serve a static site at `/site/{bucket}/...` on the WebUI/REST origin. Website hosting has two independent switches: the stored index/error configuration and the per-bucket `public_read` gate. Both are required. This page covers enabling a site, exactly what the route serves, the security consequences and the effect on access-based tiering.

## How a site is enabled

| Operation | Endpoint | Permission | Effect |
| --- | --- | --- | --- |
| Store index/error documents | `PUT /{bucket}?website` | `s3:PutBucketWebsite` | Writes `storage_website_configs`; leaves `public_read` unchanged (default false) |
| Read the configuration | `GET /{bucket}?website` | `s3:GetBucketWebsite` | Returns XML, or `404 NoSuchWebsiteConfiguration` |
| Remove the configuration | `DELETE /{bucket}?website` | `s3:DeleteBucketWebsite` | Deletes the row and clears `public_read`; returns `204` |
| Read config plus gate | `GET /api/v1/admin/storage/buckets/{bucket}/website` | Admin session | JSON with `configured`, `index_document`, `error_document`, `public_read` |
| Configure and publish | `PUT /api/v1/admin/storage/buckets/{bucket}/website` | Admin session only | Writes the config and sets `public_read` in one logged owner step |

The S3 API never turns public access on by itself. The admin API requires the `admin` role; an API key holding the route permission is still refused because anonymous publishing must be a human owner decision. The WebUI's **S3 -> bucket -> Website** panel calls the admin API and asks the operator to type `PUBLISH` before enabling anonymous reads.

Store the documents with the standard website XML:

```bash
aws --endpoint-url https://s3.example.com s3api put-bucket-website \
  --bucket my-site \
  --website-configuration '{
    "IndexDocument": {"Suffix": "index.html"},
    "ErrorDocument": {"Key": "404.html"}
  }'
```

The equivalent XML body is:

```xml
<WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IndexDocument><Suffix>index.html</Suffix></IndexDocument>
  <ErrorDocument><Key>404.html</Key></ErrorDocument>
</WebsiteConfiguration>
```

Then enable anonymous read explicitly:

```bash
curl -X PUT https://teledrive.example.com/api/v1/admin/storage/buckets/my-site/website \
  -H 'Content-Type: application/json' \
  -H 'X-TeleDrive-CSRF: 1' \
  --cookie 'teledrive_session=...' \
  -d '{"index_document":"index.html","error_document":"404.html","public_read":true}'
```

The response includes a `notice` when `public_read` is true. The action is logged with the bucket, documents and gate value; it is not written to the durable security audit table by this route.

`PUT ?website` rejects a document name that is absolute, contains `..`, `.`, backslashes, control characters or URL delimiters, or ends with `/`. The XML body is capped at 16 KiB and parsed with `defusedxml`. `RedirectAllRequestsTo` and `RoutingRules` are valid AWS features with no honest implementation here; they return `501` rather than being silently ignored.

## What gets served

| Request | Resolution |
| --- | --- |
| `GET /site/my-site/` or `GET /site/my-site` | `index.html` at the bucket root |
| `GET /site/my-site/docs/` | `docs/index.html` |
| `GET /site/my-site/docs` | The exact object `docs` if it exists; otherwise `docs/index.html` |
| Missing key with an error document | The configured error object with status `404` |
| Missing key without an error document | A uniform `404` plain-text body |

Only the **current ready object** is addressable. Staging manifests, delete markers, removed versions and historical versions are never served. A deleted object returns `404` even though its Telegram messages remain retained for gated GC.

The route returns a uniform `404` for all of these cases, deliberately indistinguishable:

- the bucket does not exist;
- `public_read` is false;
- no website configuration exists, or it is disabled;
- the path contains traversal, backslashes, NUL/control characters, an absolute path or an encoded traversal variant;
- an archived object returns `InvalidObjectState` at the REST gate;
- an SSE-C object cannot be decrypted without the customer key.

Directory listings are never generated. A missing error document falls back to the plain uniform 404.

`Content-Type` comes from the object's stored metadata only when it is a plain media type; otherwise the response is `application/octet-stream`. A `text/*` type gets `; charset=utf-8`.

## Public access and bucket policy

`public_read` is a column on `storage_buckets`, not a bucket policy and not an ACL. It is the only gate the `/site/` route consults, together with the website configuration.

| Configuration | `/site/` result |
| --- | --- |
| Website config, `public_read=false` | Uniform 404 |
| No website config, `public_read=true` | Uniform 404 |
| Website config, `public_read=true`, object missing | Error document with 404, or uniform 404 |
| Public bucket policy or ACL, `public_read=false` | Uniform 404; `/site/` does not evaluate the S3 policy engine |
| `public_read=true`, restrictive bucket policy | `/site/` still serves; the path does not consult the policy |
| Public access block all true, `public_read=true` | `/site/` still serves; public access block governs S3 API policy/ACL, not this route |

!!! danger
    `public_read=true` publishes **every current ready object in the bucket**, not only `index.html` and `404.html`. Anyone who can reach the app origin can read all of them without a login or S3 credential. Keep secrets, backups, drafts and private exports in a different bucket.

Deleting the website configuration clears `public_read` in the same transaction. Deleting or recreating a bucket also removes the configuration and leaves the bucket private and unconfigured.

## Serving through the app, a proxy or a CDN

The site is served on the WebUI origin by the app itself. There is no separate website listener and no per-bucket hostname.

- **Reverse proxy:** forward `/site/...` to the web listener and include the public hostname in `web.allowed_hosts`. Do not strip the `/site/{bucket}` prefix; the bucket is part of the path. See [Reverse proxy](reverse-proxy.md).
- **CDN or caching proxy:** you may put one in front, but the origin sends `Cache-Control: no-store` and a strict CSP. A CDN that ignores the header can cache the page, which stops the origin from recording the read (see tiering below) and can serve an old version after an overwrite. If you enable caching, define a purge or short-TTL policy per bucket and do not cache across a version change.
- **Separate hostname:** a website hostname is still the same app origin unless you build a separate deployment. A new hostname must be added to `web.allowed_hosts`, and the `/site/{bucket}/` path must remain intact.

The app does not serve a bucket root at `/`; `/site/{bucket}/` is the only public path. A custom domain is a proxy/CDN concern, not an S3 website-hostname feature.

## Headers, caching and conditional requests

Every successful site response carries:

| Header | Value |
| --- | --- |
| `Content-Type` | Stored plain media type, or `application/octet-stream`; `text/*` gets `charset=utf-8` |
| `Content-Length` | Object size |
| `ETag` | Quoted object SHA-256 |
| `Last-Modified` | Object creation time in GMT |
| `Cache-Control` | `no-store` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'` |

`HEAD` returns the same headers with no body. The route does not implement `Range`, `If-None-Match` or `If-Modified-Since`; `ETag` and `Last-Modified` are informational. A client that needs conditional or ranged reads should use the S3 API, not the website path.

## Security warnings

- **Public means public.** `public_read` exposes all current objects in the bucket to anyone who can reach the app origin. There is no per-object allowlist on this path.
- **The CSP deliberately breaks normal websites.** `sandbox` without `allow-same-origin` puts the document in an opaque origin, and `default-src 'none'` blocks scripts, styles, images, fonts, frames and every other subresource. The stored HTML body is returned, but a conventional site with linked CSS, JavaScript or images will render as unstyled text. This is intentional: the site shares the app origin, so allowing same-origin access would let a hosted page read cookies and authenticated API responses.
- **No directory listing.** A directory without an index is a 404, not a file list.
- **Traversal is rejected before lookup.** Repeated percent-encoding, backslashes, control characters and absolute paths cannot escape the bucket key space.
- **No error detail.** The public route never explains why an object is unavailable; a missing key, a disabled gate and an archived object look the same.
- **Deleting the site revokes the gate.** `DELETE ?website` and bucket deletion clear `public_read`; a recreated bucket starts private.

## Tiering and access counts

A served page is an object read. `_serve_site` calls `record_object_access(item.id)` before streaming, so an active public site keeps resetting the Intelligent-Tiering idle clock. Without that record, a frequently viewed site could be demoted to archive and the next request would return `403 InvalidObjectState` at the REST gate, which the public route renders as a uniform 404.

Consequences:

- Public traffic counts toward tiering access statistics just like authenticated reads.
- A CDN that serves from cache prevents origin reads, so the origin sees an idle site and may archive it. The CDN then serves stale content until it expires, and a cache miss returns the 404 form of `InvalidObjectState`.
- Restoring an archived object through `RestoreObject` opens the bounded restore window; the public route does not do that automatically.
- The access counter update is a write on the read path by design. Expect it in database load and in storage-tier metrics.

See [Monitoring](monitoring.md) for access and capacity signals, and [Garbage collection](garbage-collection.md) for why a deleted object's media still exists after the site returns 404.

## Operating checklist

| Done | Item |
| --- | --- |
| [ ] | Index document exists as a current ready object |
| [ ] | Error document exists, or the uniform 404 is acceptable |
| [ ] | The bucket contains no private objects that must not be public |
| [ ] | `public_read` was enabled deliberately by an admin session |
| [ ] | The public hostname is in `web.allowed_hosts` |
| [ ] | The proxy forwards `/site/{bucket}/...` without rewriting the bucket path |
| [ ] | Any CDN cache policy accounts for `no-store`, overwrites and tiering |
| [ ] | The site was checked with `curl -I` for the expected status and CSP |
| [ ] | Removing the site with `DELETE ?website` also cleared `public_read` |
