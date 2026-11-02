# TeleDrive documentation

TeleDrive is a personal object store that keeps payloads in Telegram and
metadata in SQL, and exposes them three ways: a web UI, a REST API and an
S3-compatible gateway. This site is the operator manual and the reference.

## Start here

<div class="grid cards" markdown>

- :material-rocket-launch: **[Install](start/install.md)** — one Docker
  container, Compose file, first boot.
- :material-tune: **[Configure](start/configure.md)** — environment, config
  file, the SQL settings document, ports and TLS.
- :material-cloud-upload: **[First upload](start/first-upload.md)** — log in,
  connect Telegram, put an object, read it back.

</div>

## Find what you need

| If you want to… | Read |
| --- | --- |
| Use the dashboard | [Web UI](guide/web-ui.md) |
| Call the HTTP API | [REST API](guide/rest-api.md) |
| Point `aws`, `boto3` or `rclone` at it | [S3 API](guide/s3-api.md) |
| Add Telegram accounts or rotate them | [Telegram accounts](guide/telegram-accounts.md) |
| Import a folder from disk | [Local file jobs](guide/local-jobs.md) |
| Run it from a shell | [Command line](guide/cli.md) |
| Keep the database healthy | [Databases](guide/databases.md) |
| Encrypt objects at rest | [Encryption](guide/encryption.md) |
| Back up and restore | [Backup and restore](operate/backup-restore.md) |
| Understand physical GC and why it is gated | [Garbage collection](operate/garbage-collection.md) |
| Scrape metrics or read the audit trail | [Monitoring](operate/monitoring.md) |
| Put it behind nginx/Caddy/Traefik | [Reverse proxy](operate/reverse-proxy.md) |
| Publish a static site from a bucket | [Website hosting](operate/website-hosting.md) |
| Upgrade an existing install | [Upgrade](operate/upgrade.md) |
| Fix something that is broken | [Troubleshooting](operate/troubleshooting.md) |
| Know exactly which S3 operations exist | [S3 compatibility](reference/s3-specs.md) |
| Look up a config key | [Configuration](reference/configuration.md) |
| Understand the code layout | [Module map](reference/module-map.md) |
| See how the test matrix works | [CI and tests](reference/ci.md) |

## What this is, precisely

- **One service, one container, one Python process.** The web UI, the REST
  API and the S3 gateway share one SQL catalog and one Telegram object
  engine. There is no second S3 container and no `--profile s3`.
- **Telegram is the blob store, not a sync client.** Chunks are uploaded to
  one dedicated private channel through an authorised Telethon USER session;
  the SQL database holds the object graph. Losing the database loses the
  index even though the bytes still exist in Telegram.
- **S3 is implemented, not proxied.** 114 of 116 AWS S3 operations are
  supported by this code, with signed SigV4 requests, real XML bodies and
  real error codes. The two that are not (`GetObjectTorrent`,
  `WriteGetObjectResponse`) have no possible backend here and refuse by name.
- **Ordinary Telegram chats are not end-to-end encrypted.** Encrypt before
  upload if Telegram itself must not read the content, or turn on the
  opt-in envelope encryption described in [Encryption](guide/encryption.md).

!!! warning "Release boundary"
    [v1.0.9](https://github.com/babico/TeleDrive/releases/tag/v1.0.9) is the
    last tagged release. `main` may be ahead of those binaries. Read
    [Project status](project/status.md) before treating any of this as
    production-ready for data you cannot lose.

!!! danger "Physical deletion is owner-gated"
    The collector that erases Telegram media is deliberately disabled until
    an independent backup host, an authorised soak and a restore rehearsal
    exist. `deletion_permitted` stays `False`. See
    [Garbage collection](operate/garbage-collection.md).

## The documentation itself

- Every page is Markdown under `docs/` in the repository; the site is built
  by MkDocs Material and published on GitHub Pages by the `Docs` workflow.
- Each page has an **Edit this page** link in the top-right corner that
  opens the source on GitHub.
- The documentation is part of the test suite: a meta-test fails when a page
  is missing from the navigation, when a relative link points at nothing, or
  when a public page is not English and locally linked. A stale claim is a
  test failure, not a documentation debt.
