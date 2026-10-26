# Running TeleDrive behind a reverse proxy

TeleDrive is a single container with two listeners: the WebUI/REST API
(`:8080`) and the S3 gateway (`:9000`). This guide covers TLS
termination, **bucket path management** and the SigV4 pitfalls for
nginx, Caddy and Traefik.

## When you need this

Every combination is supported; the two listeners are independent.

| Deployment | WebUI | S3 | Environment |
|---|---|---|---|
| Direct, LAN, no TLS | HTTP | HTTP | — (default) |
| Direct TLS on S3 only | HTTP | **HTTPS** | `TELEDRIVE_S3_SSL_CERTFILE` (+ `_KEYFILE`) |
| Direct TLS on both | **HTTPS** | **HTTPS** | `TELEDRIVE_SSL_*` and `TELEDRIVE_S3_SSL_*` |
| Everything behind a proxy | proxy TLS | proxy TLS | `TELEDRIVE_TRUSTED_PROXY=1` |
| Mixed | proxy TLS | direct TLS | `TELEDRIVE_TRUSTED_PROXY=1` + `TELEDRIVE_S3_SSL_*` |
| Proxy TLS in front of app TLS | **HTTPS** | **HTTPS** | both sets of variables |

**Ports and TLS are ENV-ONLY.** They are deployment plumbing, not
application settings: the same variable drives the host port mapping,
the in-container listener and the container healthcheck. A certificate
may be a combined `.pem` (chain + private key in one file — only the
CERTFILE variable is needed) or a split `.crt` + `.key` pair. Mount
them under `./config` and reference them as `/config/ssl/...`:

```yaml
# docker-compose environment: (or .env)
TELEDRIVE_WEB_PORT: 8088
TELEDRIVE_S3_PORT: 9088
TELEDRIVE_SSL_CERTFILE: /config/ssl/server.crt
TELEDRIVE_SSL_KEYFILE: /config/ssl/server.key
TELEDRIVE_S3_SSL_CERTFILE: /config/ssl/server.crt
TELEDRIVE_S3_SSL_KEYFILE: /config/ssl/server.key
TELEDRIVE_TRUSTED_PROXY: "1"     # only behind a proxy
```

`./deploy/tls/generate.sh` creates the material under `./config/ssl` and
prints these exact lines.

**Client bootstrap:** the management interface serves its own public
certificate at `/server.cer` (DER — what Windows imports) and
`/server.crt` (PEM chain), unauthenticated, so clients can install it
into their trust store. Only certificate blocks are emitted; a combined
`.pem`'s private key is stripped. There is also a **TLS certificate**
card on the Settings page with both download links.

`TELEDRIVE_TRUSTED_PROXY=1` makes the app honor `X-Forwarded-Proto`
(Secure cookies are set when the client connection is https) and
`X-Forwarded-Host`/`X-Forwarded-Port` for generated presigned URLs.
Without it, everything still works — only the cookie `Secure` flag and
generated URLs may be wrong.

## The two S3 addressing styles

S3 clients address buckets either **path-style** or **virtual-hosted
style**:

```
path-style:          https://s3.example.com/my-bucket/my-key
virtual-hosted:      https://my-bucket.s3.example.com/my-key
```

TeleDrive's S3 gateway is **path-style first**, but it also accepts
virtual-hosted requests: it extracts the bucket from the `Host` header
(`my-bucket.s3.example.com`). Both work behind a proxy as long as you
follow the rules below.

## The three proxy rules for S3 (SigV4)

AWS SigV4 signatures cover the **exact** `Host` header and the path.
Breaking any of these gives `403 SignatureDoesNotMatch`:

1. **Never rewrite the Host.** Do not `proxy_set_header Host $upstream;`
   and do not let the proxy strip a subdomain. Forward
   `Host $host` (nginx) / default (Caddy).
2. **Do not touch the path.** No trailing-slash rewrites, no
   `merge_slashes`, no percent-decoding. S3 object keys are opaque.
3. **Forward the original scheme** via `X-Forwarded-Proto` and set
   `web.trusted_proxy: true` in TeleDrive.

For virtual-hosted style, map `*.s3.example.com` **and**
`s3.example.com` to the same upstream.

## nginx

```nginx
# --- WebUI + REST API ---
server {
    listen 443 ssl;
    server_name teledrive.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # Browser uploads go through this listener (drag & drop, REST).
    client_max_body_size 0;          # no proxy-side upload cap

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;                 # rule 1
        proxy_set_header X-Forwarded-Proto https;    # rule 3
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        # The web UI uses cookie auth; keep the session stable.
        proxy_cookie_path / "/; HttpOnly; SameSite=Lax";
    }
}

# --- S3 gateway: path-style AND virtual-hosted on one server ---
server {
    listen 443 ssl;
    server_name s3.example.com *.s3.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # rclone/boto3 multipart parts can be large.
    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;                 # rule 1: keep bucket subdomain
        proxy_set_header X-Forwarded-Proto https;    # rule 3
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # rule 2: do NOT modify the URI. No rewrite, no merge_slashes.
        proxy_pass_request_headers on;
    }
}
```

DNS: `s3.example.com` and `*.s3.example.com` → the proxy host. If you
only use path-style, the wildcard record is unnecessary.

## Caddy

Caddy manages certificates automatically (ACME):

```caddyfile
teledrive.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up Host {host}                    # rule 1
        header_up X-Forwarded-Proto https        # rule 3
    }
    # Browser uploads: no body limit
    request_body {
        max_size 0
    }
}

s3.example.com, *.s3.example.com {
    reverse_proxy 127.0.0.1:9000 {
        header_up Host {host}                    # rule 1: keep the bucket subdomain
        header_up X-Forwarded-Proto https        # rule 3
    }
    request_body {
        max_size 0                               # multipart parts
    }
}
```

## Traefik (Docker labels)

```yaml
http:
  routers:
    teledrive-web:
      rule: "Host(`teledrive.example.com`)"
      service: teledrive-web
      tls: {certResolver: le}
    teledrive-s3:
      rule: "Host(`s3.example.com`) || HostRegexp(`{bucket:[^.]+}.s3.example.com`)"
      service: teledrive-s3
      tls: {certResolver: le}
  services:
    teledrive-web:
      loadBalancer:
        servers: [{url: "http://127.0.0.1:8080"}]
        # SigV4: pass the original Host through unchanged
        passHostHeader: true
    teledrive-s3:
      loadBalancer:
        servers: [{url: "http://127.0.0.1:9000"}]
        passHostHeader: true
```

## Client configuration examples

rclone (path-style behind a proxy):

```ini
[type = s3]
type = s3
provider = Other
endpoint = https://s3.example.com
force_path_style = true
```

A self-signed certificate must be trusted by the client first — download
`https://<host>:<port>/server.cer` from the management interface (or use
the Settings page link) and import it, or point the client at the PEM:

```bash
# curl / AWS CLI / rclone
--cacert /path/to/server.crt        # curl
AWS_CA_BUNDLE=/path/to/server.crt   # AWS CLI / boto3 / rclone
```

AWS CLI:

```bash
aws --endpoint-url https://s3.example.com s3 ls s3://my-bucket/
```

Windows (S3 Browser, WinSCP): download `/server.cer`, double-click it,
choose **Install Certificate → Local Machine → Trusted Root
Certification Authorities**, restart the client. Bypassing validation
per-application is unreliable (some clients ignore that setting for
bucket listing), so importing the certificate is the dependable path.

boto3:

```python
import boto3
s3 = boto3.client(
    "s3",
    endpoint_url="https://s3.example.com",
    aws_access_key_id=..., aws_secret_access_key=...,
    # path-style:
    # config=botocore.client.Config(s3={"addressing_style": "path"}),
)
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `SignatureDoesNotMatch` on every request | Host was rewritten or path modified | rules 1–2 above |
| Works with `--insecure` only | self-signed cert not trusted by the client | install the CA or use ACME (Caddy/Traefik) |
| `413 Request Entity Too Large` | proxy body limit | `client_max_body_size 0` / `max_size 0` |
| Login loop over HTTPS | `trusted_proxy` not set | `web.trusted_proxy: true` + `X-Forwarded-Proto` |
| Virtual-hosted style 404s | wildcard DNS/route missing | `*.s3.example.com` must hit the S3 upstream |
| Multipart upload fails at part 2+ | proxy buffering a streaming body | nginx: `proxy_request_buffering off;` |

## Ports and bind addresses

Keep the host side of both TeleDrive ports on loopback when a proxy
fronts them, so only the proxy can reach the service:

```env
# .env
TELEDRIVE_BIND_ADDRESS=127.0.0.1
TELEDRIVE_WEB_PORT=8080
TELEDRIVE_S3_PORT=9000
```
