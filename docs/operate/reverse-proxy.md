# Running behind a reverse proxy

TeleDrive has two independent listeners behind one container: the WebUI/REST API on `TELEDRIVE_WEB_PORT` (default `8080`) and the S3 gateway on `TELEDRIVE_S3_PORT` (default `9000`). This page covers TLS termination, the exact Host and path rules SigV4 requires, upload timeouts, the live log websocket and the symptoms produced by each misconfiguration.

## Deployment shapes

| Deployment | WebUI | S3 | Required environment |
| --- | --- | --- | --- |
| Direct, no TLS | HTTP | HTTP | None |
| Direct TLS, S3 only | HTTP | HTTPS | `TELEDRIVE_S3_SSL_CERTFILE` and optional `TELEDRIVE_S3_SSL_KEYFILE` |
| Direct TLS, both | HTTPS | HTTPS | Both listener certificate pairs |
| Proxy TLS, both | proxy HTTPS | proxy HTTPS | `TELEDRIVE_TRUSTED_PROXY=1` |
| Proxy TLS, S3 direct TLS | proxy HTTPS | HTTPS | `TELEDRIVE_TRUSTED_PROXY=1` plus the S3 certificate pair |
| TLS at proxy and at the app | HTTPS | HTTPS | Both proxy and app TLS, plus `TELEDRIVE_TRUSTED_PROXY=1` |

Ports, bind address and TLS paths are environment-only. They are not read from `config/config.yaml`, because the same variable must drive the host mapping, the in-container listener and the healthcheck.

```env
# .env or the Compose environment block
TELEDRIVE_BIND_ADDRESS=127.0.0.1
TELEDRIVE_WEB_PORT=8080
TELEDRIVE_S3_PORT=9000

# Direct TLS (omit when the proxy terminates TLS)
TELEDRIVE_SSL_CERTFILE=/config/ssl/server.crt
TELEDRIVE_SSL_KEYFILE=/config/ssl/server.key
TELEDRIVE_S3_SSL_CERTFILE=/config/ssl/server.crt
TELEDRIVE_S3_SSL_KEYFILE=/config/ssl/server.key

# Only when a trusted proxy is in front
TELEDRIVE_TRUSTED_PROXY=1
```

Keep the host-side ports on loopback when a proxy fronts them. The container binds `0.0.0.0` internally, but `TELEDRIVE_BIND_ADDRESS=127.0.0.1` limits the published Docker port to the host loopback.

## TLS material

Generate a self-signed pair with the shipped script:

```bash
python scripts/ops/generate_ssl.py \
  --out ./config/ssl \
  --hostname teledrive.example.com \
  --days 365
```

The script writes `server.crt` and `server.key`, refuses to overwrite existing files and prints the exact environment lines. It stores material under the `./config` mount in this example, so `/config/ssl/server.crt` is visible in the container. A combined PEM containing the chain and private key needs only the `_CERTFILE` variable.

The management interface publishes its public certificate without authentication at `/server.cer` (DER, for Windows trust stores) and `/server.crt` (PEM chain). A combined PEM's private key is stripped from the download. The Settings page also links both downloads.

Verify a generated pair against a running listener:

```bash
python scripts/ops/generate_ssl.py \
  --out ./config/ssl \
  --test https://127.0.0.1:8080 \
  --insecure
```

## `TRUSTED_PROXY` and `allowed_hosts`

`TELEDRIVE_TRUSTED_PROXY=1` does four separate things. Enable it only when a proxy you control is the direct peer; otherwise a client can forge the headers.

| Effect | Behaviour with `TRUSTED_PROXY=1` | Behaviour without it |
| --- | --- | --- |
| Cookie `Secure` | Set when `X-Forwarded-Proto: https` is received | Set only when the app itself terminates TLS |
| Generated S3 presigned URLs | Use `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-Port` | Use the listener's own scheme, Host and port |
| Client identity for throttles | Leftmost public IP in `X-Forwarded-For` | `request.client.host`, which is the proxy address behind a proxy |
| Uvicorn proxy headers | Enables proxy-header handling with trusted forwarded addresses | Ignored |

The audit trail is the exception: its `client_ip` is always `request.client.host`. A proxy deployment must correlate the real client through the proxy's access log.

`web.allowed_hosts` is a comma-separated list in `config/config.yaml` (or `TELEDRIVE_ALLOWED_HOSTS`). The web listener compares the Host header with the port stripped and rejects any other name with `400 {"detail": "Invalid host header"}` before the request is logged. Include every name clients use:

```yaml
web:
  allowed_hosts: "teledrive.example.com,localhost,127.0.0.1"
```

The S3 listener does not apply `allowed_hosts`, but its SigV4 verification still signs the exact Host header.

!!! warning
    Do not set `TELEDRIVE_TRUSTED_PROXY=1` on a listener reachable directly by clients. Any client could then choose its own throttle identity and generate presigned URLs for a host it controls.

## S3 addressing and SigV4 Host rules

Path-style is the default and needs no extra configuration:

```text
https://s3.example.com/my-bucket/my-key
```

Virtual-hosted style is opt-in. Set the public suffix so the gateway knows which part of the Host is the bucket:

```env
TELEDRIVE_S3_VHOST_SUFFIX=s3.example.com
```

Then a request to `https://my-bucket.s3.example.com/my-key` resolves the bucket from the Host. Without that variable the request is treated as path-style; `my-bucket.s3.example.com` becomes an invalid bucket name or a missing key, not a virtual-host request.

SigV4 signs the canonical request, which includes the HTTP method, the exact path, the canonical query string, the signed headers and the payload hash. `Host` is mandatory in `SignedHeaders`. Three rules follow:

1. **Forward the original Host unchanged.** Do not set `Host $upstream` or `Host 127.0.0.1:9000`. When the public port is not the default, preserve the port too: nginx `$host` drops it, so use `$http_host` for S3.
2. **Do not rewrite or normalize the path.** No trailing-slash rewrite, no `merge_slashes`, no percent-decoding and no `try_files`. Object keys are opaque byte strings.
3. **Do not let the proxy terminate and re-originate the request with a different scheme, host or port without the forwarded headers.** The signature itself covers Host, not `X-Forwarded-*`; the forwarded values are for cookie security and generated URLs.

For virtual-hosted style, route both the apex and the wildcard to the same S3 upstream:

```text
s3.example.com       -> S3 listener
*.s3.example.com     -> S3 listener
```

## nginx

```nginx
# http context
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

# --- WebUI + REST API ---
server {
    listen 443 ssl;
    server_name teledrive.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # Browser and REST uploads can be large; enforce the limit in TeleDrive.
    client_max_body_size 0;
    client_body_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host  $http_host;
        proxy_set_header X-Forwarded-Port  $server_port;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP         $remote_addr;

        # Live log websocket and long object transfers.
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}

# --- S3 gateway: path-style and virtual-hosted on one server ---
server {
    listen 443 ssl;
    server_name s3.example.com *.s3.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    client_max_body_size 0;
    client_body_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_http_version 1.1;
        # SigV4 signs the exact Host, including a non-default port.
        proxy_set_header Host              $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host  $http_host;
        proxy_set_header X-Forwarded-Port  $server_port;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        # Do not rewrite the URI: no merge_slashes, no trailing-slash rule.
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
```

`proxy_request_buffering off` matters for large multipart parts and streaming uploads. Buffering the whole part to proxy disk doubles the write cost and can turn part 2 into a timeout.

## Caddy

Caddy preserves the incoming Host by default and manages ACME certificates automatically. If you override the header, use the full request host, not a host-only placeholder.

```caddyfile
teledrive.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up Host {http.request.hostport}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host {http.request.hostport}
        header_up X-Forwarded-Port {server_port}
        flush_interval -1
        transport http {
            read_timeout 1h
            write_timeout 1h
        }
    }
}

s3.example.com, *.s3.example.com {
    reverse_proxy 127.0.0.1:9000 {
        header_up Host {http.request.hostport}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host {http.request.hostport}
        header_up X-Forwarded-Port {server_port}
        flush_interval -1
        transport http {
            read_timeout 1h
            write_timeout 1h
        }
    }
}
```

Caddy has no default request-body limit. Do not add a `request_body max_size` rule smaller than `rest_max_upload_bytes`.

## Traefik

```yaml
http:
  routers:
    teledrive-web:
      rule: "Host(`teledrive.example.com`)"
      service: teledrive-web
      tls:
        certResolver: le
    teledrive-s3:
      rule: "Host(`s3.example.com`) || HostRegexp(`^[a-z0-9-]+\\.s3\\.example\\.com$`)"
      service: teledrive-s3
      tls:
        certResolver: le
  services:
    teledrive-web:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://127.0.0.1:8080"
    teledrive-s3:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://127.0.0.1:9000"
```

Traefik forwards `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-Port` by default. Do not add a middleware that rewrites Host or strips the forwarded headers. For large uploads, raise the entrypoint's read/write timeouts; Traefik has no default body-size limit.

## Upload size and timeouts

| Limit | Where it is enforced | Default |
| --- | --- | --- |
| Single object or multipart part | `web.rest_max_upload_bytes` / `TELEDRIVE_REST_MAX_UPLOAD_BYTES` | 2 GiB |
| REST raw upload | Same `rest_max_upload_bytes`; disabled when set below 1 | 2 GiB |
| JSON/form request body | `web.max_request_bytes`; binary `/content` uploads are exempt | 32 MiB |
| Protocol timeout | Your proxy | nginx 60s read, Caddy no fixed default, Traefik entrypoint defaults |

Set the proxy body limit to `0` or above the TeleDrive limit. Set read and send timeouts long enough for the largest object and for a slow Telegram read. Because the app streams from Telegram, the first byte may take longer than the proxy's default idle timeout.

## WebSocket for the live log

The endpoint is `/api/v1/logs/stream`. It authenticates on the handshake with the `teledrive_session` cookie; a Bearer token in the query string is deliberately not accepted. It is admin-only. An unauthenticated socket closes with `4401`; a non-admin socket closes with `4403`.

The proxy must forward the `Upgrade` and `Connection` headers and allow a long idle connection. The nginx example above does both. Caddy supports WebSocket upgrades without extra configuration when `flush_interval -1` is set. Traefik supports them natively.

The socket replays the last 200 buffer entries, then streams new lines. It is not a durable audit trail; see [Monitoring](monitoring.md).

## Exact failure symptoms

| Symptom | Cause | Fix |
| --- | --- | --- |
| `403 SignatureDoesNotMatch` on every S3 request | Proxy rewrote Host, dropped a non-default port, normalized the path, or re-encoded the query | Preserve the exact Host (`$http_host`), disable path rewrites and `merge_slashes`, and do not decode the URI |
| `403 SignatureDoesNotMatch` only on a non-default HTTPS port | nginx `$host` dropped the port that the client signed | Use `proxy_set_header Host $http_host` on the S3 server |
| `403 RequestTimeTooSkewed` | Client clock is more than 15 minutes from the server, or the signed date does not match the credential scope | Enable NTP on the client; re-sign with the current time |
| `403 AccessDenied` with `Unknown, expired, revoked or unauthorized access key` | The key is unknown, expired, revoked or lacks the operation's permission | Check `GET /api/v1/admin/s3-credentials` and the credential's permission list |
| `400 {"detail": "Invalid host header"}` on the WebUI | The public Host is not in `web.allowed_hosts` | Add the proxy hostname to the list and restart or reload the settings |
| Login throttle is shared by every user, or one attacker locks everyone out | `TELEDRIVE_TRUSTED_PROXY` is off, so the throttle keys on the proxy address | Enable the flag and send `X-Forwarded-For` |
| Presigned URLs use `http://` or the upstream host/port | `TELEDRIVE_TRUSTED_PROXY` is off, or the proxy does not send `X-Forwarded-Proto` / `-Host` / `-Port` | Enable the flag and forward all three values |
| Session cookie lacks `Secure` behind HTTPS | Same cause: the app does not see `X-Forwarded-Proto: https` | Enable the flag and forward the header |
| `413` with an HTML proxy error page | The proxy body limit is too low | `client_max_body_size 0` in nginx; no Caddy/Traefik limit |
| `413 EntityTooLarge` with an S3 XML body | TeleDrive's `rest_max_upload_bytes` or a bucket quota rejected the upload | Raise the configured limit or quota; this is not a proxy failure |
| Multipart upload fails at part 2 or later | Proxy buffering, a short timeout, or a per-part limit | `proxy_request_buffering off`, longer read/send timeouts, body limit above the part size |
| `404` or `InvalidArgument` for `bucket.s3.example.com` | `TELEDRIVE_S3_VHOST_SUFFIX` is unset or does not match the Host suffix, or wildcard DNS is missing | Set the suffix, add `*.s3.example.com` DNS and route it to the S3 listener |
| WebSocket returns `400`, `426` or `502` | The proxy did not forward the upgrade or the connection was cut | Forward `Upgrade`/`Connection`, raise the read timeout |
| WebSocket closes with `4401` or `4403` | No session cookie, or the user is not an admin | Log in as an admin; do not put tokens in the URL |
| `502 Bad Gateway` on every request | The proxy points at the wrong port, or uses HTTPS against a plain listener | Match the proxy upstream scheme to the listener TLS variables |
| CORS preflight returns `403` | The bucket has no matching CORS rule; the proxy is not the cause | Configure bucket CORS with `PUT /{bucket}?cors` |

## Client examples

rclone, path-style behind a proxy:

```ini
[type = s3]
type = s3
provider = Other
endpoint = https://s3.example.com
force_path_style = true
```

AWS CLI:

```bash
aws --endpoint-url https://s3.example.com s3 ls s3://my-bucket/
```

boto3, path-style:

```python
import boto3
from botocore.client import Config

s3 = boto3.client(
    "s3",
    endpoint_url="https://s3.example.com",
    aws_access_key_id="...",
    aws_secret_access_key="...",
    config=Config(s3={"addressing_style": "path"}),
)
```

For virtual-hosted style, remove `force_path_style` / set `addressing_style: "virtual"` and configure `TELEDRIVE_S3_VHOST_SUFFIX`.

A self-signed certificate must be trusted by the client first. Download `/server.crt` from the management interface or use the Settings page link, then:

```bash
# curl
curl --cacert /path/to/server.crt https://s3.example.com/

# AWS CLI, boto3, rclone
export AWS_CA_BUNDLE=/path/to/server.crt
```

On Windows, import `/server.cer` into **Local Machine -> Trusted Root Certification Authorities** and restart the client. Per-application "ignore certificate" switches are unreliable for bucket listing.

See [Website hosting](website-hosting.md) for the public `/site/` path and [Troubleshooting](troubleshooting.md) for the error-code matrix.
