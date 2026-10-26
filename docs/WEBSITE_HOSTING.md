# Website hosting (Phase I)

TeleDrive supports the S3 website configuration API and serves the result on
the WebUI origin at `/site/{bucket}/...`.

## Configuration

The index and error documents are real SQL state in
`storage_website_configs`. Writing them does **not** expose anything:

| API | Role / permission | Effect |
| --- | --- | --- |
| `PUT /{bucket}?website` | `s3:PutBucketWebsite` | Stores the index/error document. Leaves `public_read` unchanged (default FALSE). |
| `GET /{bucket}?website` | `s3:GetBucketWebsite` | Returns the stored configuration, or `404 NoSuchWebsiteConfiguration`. |
| `DELETE /{bucket}?website` | `s3:DeleteBucketWebsite` | Removes the configuration **and** clears `public_read`. Answers `204`. |
| `PUT /api/v1/admin/storage/buckets/{bucket}/website` | `admin` role | Stores the configuration and sets `public_read` in one audited step. |

The admin body is:

```json
{"index_document": "index.html", "error_document": "404.html",
 "public_read": true}
```

`public_read=true` **publishes every current ready object in the bucket
anonymously** to anyone who can reach the app origin. It is an explicit
owner/admin decision, audit-logged, and defaults to FALSE for new and
existing buckets. Operators, viewers and API keys cannot flip it.

`RedirectAllRequestsTo` and `RoutingRules` have no honest backing here (no
extra hostnames or rewrite engine) and are rejected with `501` rather than
accepted and ignored. `PutBucketWebsite` payloads are capped at 16 KiB and
parsed with `defusedxml`.

## Serving semantics

`GET /site/{bucket}/...` and `GET /site/{bucket}`:

* Uniform `404` when the bucket does not exist, `public_read` is FALSE, or no
  enabled website configuration exists. These cases are indistinguishable.
* Serve only the **current** published (`ready`) object. Staging manifests,
  delete markers and historical versions are never addressable. A deleted
  object 404s even though its immutable media remains for GC.
* `/site/b/` and `/site/b/dir/` resolve to `dir/index.html`; `/site/b/dir`
  also resolves the directory index when no exact object named `dir` exists.
* Missing keys/directories serve the configured error document with status
  `404`; without one the uniform 404 body is returned. Directory listings are
  never generated.
* Path traversal (`..`, `.`, repeated percent-encoded variants), backslashes,
  NUL/control characters and absolute filesystem paths are rejected before any
  key lookup.
* `Content-Type` comes from the object's stored metadata only when it is a
  plain media type; otherwise `application/octet-stream`. `text/*` gets
  `; charset=utf-8`.
* Every response carries `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store` and a strict CSP.

### Why the CSP is `sandbox; default-src 'none'`

The site is served on the **app origin**, so a hosted page could otherwise
read same-origin API responses, cookies or other private content. `sandbox`
without `allow-same-origin` puts the document in an opaque origin, severing
cookies and same-origin access. `default-src 'none'` additionally forbids
scripts, styles, images, frames and every other subresource. Together they make
a hosted page inert as an attack surface: the stored HTML body is returned, but
CSS, scripts and subresources are intentionally not allowed.

## Cleanup

`DeleteBucketWebsite` and bucket deletion clear both the configuration row and
`public_read`. A deleted or recreated bucket therefore starts private and
unconfigured.
