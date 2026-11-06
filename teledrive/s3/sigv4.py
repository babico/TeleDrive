"""AWS Signature V4 authorization for path-style S3 requests.

Supports signed headers and short-lived query presigns. A presigned PUT must
bind a SHA-256 checksum in its signed headers; anonymous mutable payload
presigns, AWS chunked streaming and SigV2 are deliberately refused.

Canonical query string
----------------------
The AWS SigV4 specification describes the client's job: URI-encode each
query parameter name and value (unreserved set ``-_.~``), then sort. What
a verifier must reconstruct from the wire is subtler, because AWS's own
SDK signs a request URL that already carries its query with the RAW
as-sent tokens (botocore ``_canonical_query_string_url``: split on ``&``
and the first ``=``, sort, join verbatim — no re-encoding), while other
clients decode the wire parameters and re-encode them per the spec. A
client that sends an unencoded ``/`` in ``response-content-type=text/plain``
therefore signs the literal ``text/plain``, and a verifier that
decode-and-re-encodes it to ``text%2Fplain`` rejects a request AWS
accepts (and would additionally authenticate the percent-encoded wire
form under a signature made for the raw form — a normalized substitute
of what was signed).

This module verifies against BOTH candidates (see
:func:`_query_candidates`): the raw wire tokens and the spec-literal
UriEncode form. Every candidate is a deterministic function of the exact
wire bytes, so the signature still binds the request as sent; fully
percent-encoded queries — the overwhelmingly common case, and every
presigned URL TeleDrive mints — produce a single candidate.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlsplit

from starlette.requests import Request


class SigV4Error(ValueError):
    def __init__(self, code: str, message: str):
        self.code, self.message = code, message
        super().__init__(message)


# aws-chunked streaming payload modes: the literal header VALUE is what
# gets signed, so header-mode verification accepts it as the payload hash.
SIGNED_STREAMING = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
SIGNED_STREAMING_TRAILER = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
UNSIGNED_STREAMING_TRAILER = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
STREAMING_MODES = frozenset({
    SIGNED_STREAMING, SIGNED_STREAMING_TRAILER, UNSIGNED_STREAMING_TRAILER})


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    """The SigV4 key-derivation chain (AWS4+secret -> date -> region ->
    service -> aws4_request)."""
    key = _hmac(b"AWS4" + secret.encode(), date)
    for word in (region, service, "aws4_request"):
        key = _hmac(key, word)
    return key


def _signature(key: bytes, string_to_sign: str) -> str:
    return hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()


MAX_QUERY_BYTES = 16 * 1024
MAX_QUERY_FIELDS = 100


def _query_pairs(raw: bytes) -> list[tuple[str, str]]:
    """Reject malformed or oversized wire queries before canonicalizing them.

    urllib.parse defaults to replacement characters on invalid UTF-8; a
    signature verifier must not authenticate normalized substitute bytes.
    """
    if len(raw) > MAX_QUERY_BYTES:
        raise SigV4Error("InvalidArgument", "S3 query string exceeds 16 KiB")
    try:
        return parse_qsl(
            raw.decode("ascii"), keep_blank_values=True,
            encoding="utf-8", errors="strict", max_num_fields=MAX_QUERY_FIELDS,
        )
    except (UnicodeError, ValueError) as exc:
        raise SigV4Error("InvalidArgument", "Invalid S3 query string") from exc


def _raw_query_pairs(raw: bytes) -> list[tuple[str, str]]:
    """The wire query's name/value tokens EXACTLY as sent, undecoded.

    Tokenization mirrors :func:`_query_pairs` (split on ``&``, partition
    at the first ``=``, blank tokens dropped) so the two views stay index
    aligned; the difference is that percent escapes and raw reserved
    characters are preserved byte-for-byte instead of being decoded.
    """
    text = raw.decode("ascii")
    if not text:
        return []
    return [tuple(token.partition("=")[::2])
            for token in text.split("&") if token != ""]


def _encoded_join(pairs) -> str:
    """Spec-literal canonical form: UriEncode every name and value, sort.

    This is the canonical query string the AWS SigV4 documentation
    describes ("URI-encode each name and value individually ... the
    sorting occurs after encoding"): the DECODED parameter values are
    re-encoded with the unreserved set ``-_.~``.
    """
    return "&".join(
        f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}"
        for key, value in sorted(pairs, key=lambda x: (quote(x[0], safe='-_.~'), quote(x[1], safe='-_.~')))
    )


def _wire_join(pairs) -> str:
    """Wire-bytes canonical form: the raw as-sent tokens, sorted.

    botocore (AWS's own SDK) signs a request URL that already carries
    its query exactly this way — ``_canonical_query_string_url`` splits
    the raw query on ``&`` and the first ``=``, sorts the pairs and
    joins them verbatim, with NO re-encoding. A client therefore signs
    an unencoded ``/``, ``=`` or ``+`` inside a query value as the raw
    character, and a verifier must compare against precisely those wire
    bytes rather than a re-encoded normalization of them.
    """
    return "&".join(f"{key}={value}" for key, value in sorted(pairs))


def _canonical_query(raw: bytes) -> str:
    """The spec-literal (UriEncode of the decoded values) candidate."""
    return _encoded_join(_query_pairs(raw))


def _wire_query(raw: bytes) -> str:
    """The raw as-sent wire candidate, behind the same validation gate.

    The query is still strictly validated (size, field count, decodable
    percent escapes) before it is authenticated; only the canonical
    FORM differs from :func:`_canonical_query`.
    """
    _query_pairs(raw)
    return _wire_join(_raw_query_pairs(raw))


def _query_candidates(raw: bytes, *, drop: str | None = None) -> set[str]:
    """Both canonical query strings a compliant client may have signed.

    AWS accepts both spellings of the same wire request:

    * the raw as-sent tokens (botocore's URL-embedded-query mode, and
      every client that signs the URL string it already built), and
    * the spec-literal UriEncode form (clients that decode the wire
      parameters and re-encode each name and value per the SigV4
      documentation).

    Every candidate is a deterministic function of the exact wire bytes,
    so accepting either still authenticates the request as sent. When
    the wire is already fully percent-encoded the two coincide (one
    candidate). ``drop`` removes one parameter (by decoded AND raw
    name) for presigned-URL verification, which must exclude
    ``X-Amz-Signature``.
    """
    decoded = [pair for pair in _query_pairs(raw) if pair[0] != drop]
    wired = [pair for pair in _raw_query_pairs(raw) if pair[0] != drop]
    return {_encoded_join(decoded), _wire_join(wired)}


def _canonical_path(request: Request) -> str:
    # S3SigV4Auth (unlike generic SigV4Auth) deliberately does NOT re-encode
    # or normalize the already URL-encoded request path. Preserve percent
    # escapes, double slashes and dot segments byte-for-byte.
    raw = request.scope.get("raw_path") or request.url.path.encode("utf-8")
    try:
        path = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SigV4Error("SignatureDoesNotMatch", "Invalid encoded URL path") from exc
    if not path.startswith("/"):
        raise SigV4Error("SignatureDoesNotMatch", "Invalid absolute URL path")
    return path


# S3 Express One Zone operations are signed with the ``s3express`` service
# name. Two groups may authenticate with that scope: the control-plane
# operations (ListDirectoryBuckets, CreateSession) and — only when the
# request targets an EXISTING directory bucket's zonal data plane — the
# object actions listed in teledrive.s3.directory_buckets.ZONAL_ACTIONS.
# The gateway passes ``zonal=True`` for exactly those requests; every
# other s3express-signed request fails closed here.
from teledrive.s3.directory_buckets import ZONAL_ACTIONS as _EXPRESS_ZONAL_PERMISSIONS

_EXPRESS_PERMISSIONS = frozenset({"s3:ListDirectoryBuckets", "s3:CreateSession"})
_SIGNING_SERVICES = frozenset({"s3", "s3express"})


def _express_signing_region() -> str:
    """The single region this deployment presents (``us-east-1`` default).

    S3 Express scopes must be signed for the deployment's own region; a
    scope minted for another region is a wrong-zone request and fails
    closed. Read at call time so configuration and tests apply without a
    re-import.
    """
    region = os.environ.get("TELEDRIVE_S3_REGION", "").strip()
    return region or "us-east-1"


_AUTH_SERVICE_RE = re.compile(
    r"AWS4-HMAC-SHA256 Credential=[^\s,/]{1,64}/\d{8}/[a-z0-9-]{1,32}/"
    r"([a-z0-9]{1,16})/aws4_request")
_PRESIGN_SERVICE_RE = re.compile(
    r"[^/\s]{1,64}/(\d{8})/[a-z0-9-]{1,32}/([a-z0-9]{1,16})/aws4_request")


def signing_service_hint(request: Request) -> str:
    """The declared credential-scope service, for ROUTING only.

    ``ListBuckets`` and ``ListDirectoryBuckets`` share ``GET /`` and botocore
    sends no distinguishing query field, so the scope name is the only wire
    signal. This value is unverified here: it is part of the canonical request
    that ``verify_header_signature`` recomputes, so a forged value simply
    fails signature verification. Anything unrecognized is reported as
    ``s3`` so the normal (stricter) path applies.
    """
    auth = request.headers.get("authorization", "")
    match = _AUTH_SERVICE_RE.match(auth)
    if match is not None:
        return match.group(1)
    credential = request.query_params.get("X-Amz-Credential", "")
    match = _PRESIGN_SERVICE_RE.fullmatch(credential)
    return match.group(2).lower() if match is not None else "s3"


def _signing_service(permission: str, service: str, *,
                     zonal: bool = False) -> str:
    if service not in _SIGNING_SERVICES:
        raise SigV4Error("AccessDenied", "Unsupported SigV4 service")
    if service == "s3express":
        allowed = _EXPRESS_PERMISSIONS
        if zonal:
            allowed = allowed | _EXPRESS_ZONAL_PERMISSIONS
        if permission not in allowed:
            raise SigV4Error(
                "AccessDenied", "S3 Express signing is only valid for directory-bucket operations")
    return service


def _presigned_signature(request: Request, lookup_secret, permission: str,
                         now: datetime | None) -> str:
    if request.method not in {"GET", "HEAD", "PUT", "DELETE", "POST"}:
        raise SigV4Error("NotImplemented", "Presigned S3 method unsupported")
    if request.headers.get("authorization"):
        raise SigV4Error("AccessDenied", "Ambiguous Authorization and query signature")
    pairs = _query_pairs(request.scope.get("query_string", b""))
    required = {
        "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date",
        "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature",
    }
    values = {}
    for key, value in pairs:
        if key in values:
            raise SigV4Error("SignatureDoesNotMatch", "Repeated presigned query parameter")
        values[key] = value
    if not required.issubset(values):
        raise SigV4Error("AccessDenied", "Incomplete presigned S3 URL")
    if values["X-Amz-Algorithm"] != "AWS4-HMAC-SHA256":
        raise SigV4Error("AccessDenied", "Only AWS Signature V4 is supported")
    if "X-Amz-Security-Token" in values:
        raise SigV4Error("InvalidToken", "Temporary AWS session tokens are unsupported")
    credential = re.fullmatch(
        r"([^/\s]{1,64})/(\d{8})/([a-z0-9-]{1,32})/([a-z0-9]{1,16})/aws4_request",
        values["X-Amz-Credential"],
    )
    if credential is None:
        raise SigV4Error("AccessDenied", "Invalid presigned credential scope")
    access_key, date, region, service = credential.groups()
    service = _signing_service(permission, service)
    if service == "s3express" and region != _express_signing_region():
        raise SigV4Error(
            "AccessDenied",
            "S3 Express signing region does not match this deployment")
    signed_string = values["X-Amz-SignedHeaders"]
    signed = signed_string.split(";")
    if (not signed or signed != sorted(set(signed)) or "host" not in signed
            or any(not re.fullmatch(r"[a-z0-9-]+", x) for x in signed)):
        raise SigV4Error("SignatureDoesNotMatch", "Invalid presigned SignedHeaders")
    headers = {}
    for name in signed:
        matching = [v.decode("latin-1") for k, v in request.scope["headers"]
                    if k.decode("ascii").lower() == name]
        if len(matching) != 1:
            raise SigV4Error("SignatureDoesNotMatch", "Ambiguous or missing signed header")
        headers[name] = " ".join(matching[0].strip().split())
    if request.method == "POST":
        # Permit only checksum-bound Complete or empty-body Initiate.
        # Both selectors are authenticated in the canonical query, and
        # arbitrary POSTs (including browser form uploads) remain refused.
        completing = (
            bool(values.get("uploadId"))
            and len(values["uploadId"]) <= 80
            and all(name in required | {"uploadId"} for name in values)
        )
        initiating = (
            "uploads" in values and values["uploads"] == ""
            and all(name in required | {"uploads"} for name in values)
        )
        if not (completing or initiating):
            raise SigV4Error("NotImplemented", "Only bound multipart POST supported")
        if ("x-amz-content-sha256" not in signed or not re.fullmatch(
            r"[0-9a-f]{64}", headers.get("x-amz-content-sha256", "")
        )):
            raise SigV4Error("AccessDenied", "Multipart POST requires signed SHA-256")
        if initiating and headers["x-amz-content-sha256"] != _sha(b""):
            raise SigV4Error(
                "XAmzContentSHA256Mismatch",
                "Presigned multipart initiation must bind an empty request body",
            )
    if request.method == "PUT":
        if "x-amz-copy-source" in signed:
            # Presigned CopyObject: the request has no body, so the
            # signature must bind the EMPTY-body digest — and the
            # source header being signed (checked here and again in the
            # copy handler) is what stops the URL being replayed
            # against a different private source object.
            if ("x-amz-content-sha256" not in signed
                    or headers["x-amz-content-sha256"] != _sha(b"")):
                raise SigV4Error(
                    "AccessDenied",
                    "Presigned copy requires the signed empty-body digest")
        elif not {"x-amz-checksum-sha256", "x-amz-content-sha256"}.intersection(signed):
            # Never expose an S3 write URL which permits arbitrary replacement
            # with a different payload by anyone who obtains the link.
            raise SigV4Error("AccessDenied", "Presigned PUT requires signed SHA-256 checksum")
        if "x-amz-content-sha256" in signed and not re.fullmatch(
            r"[0-9a-f]{64}", headers["x-amz-content-sha256"]
        ):
            raise SigV4Error("XAmzContentSHA256Mismatch", "Invalid signed upload checksum")
        if "x-amz-checksum-sha256" in signed:
            import base64
            import binascii
            try:
                checksum = base64.b64decode(headers["x-amz-checksum-sha256"], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise SigV4Error("XAmzContentSHA256Mismatch", "Invalid signed upload checksum") from exc
            if len(checksum) != 32:
                raise SigV4Error("XAmzContentSHA256Mismatch", "Invalid signed upload checksum")
    stamp = values["X-Amz-Date"]
    if not re.fullmatch(r"\d{8}T\d{6}Z", stamp) or stamp[:8] != date:
        raise SigV4Error("AccessDenied", "Invalid presigned date")
    try:
        instant = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        expires = int(values["X-Amz-Expires"])
    except ValueError as exc:
        raise SigV4Error("AccessDenied", "Invalid presigned expiration") from exc
    if not (1 <= expires <= 604800):
        raise SigV4Error("AccessDenied", "Presigned URL expiry must be 1..604800 seconds")
    clock = now or datetime.now(timezone.utc)
    if (clock - instant).total_seconds() > expires:
        raise SigV4Error("AccessDenied", "Presigned URL expired")
    if (instant - clock).total_seconds() > 900:
        raise SigV4Error("RequestTimeTooSkewed", "Presigned timestamp too far in future")
    signature = values["X-Amz-Signature"]
    if not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise SigV4Error("SignatureDoesNotMatch", "Invalid signature format")
    # botocore's SigV4 canonical request uses the declared payload hash
    # when x-amz-content-sha256 is present, including presigned POST.
    # The signed header above pins the digest, and the multipart handler
    # independently rehashes the received XML before committing it.
    canonical_payload = (
        headers["x-amz-content-sha256"]
        if "x-amz-content-sha256" in signed else "UNSIGNED-PAYLOAD"
    )
    scope = f"{date}/{region}/{service}/aws4_request"

    def _to_sign(query: str) -> str:
        canonical = (
            f"{request.method}\n{_canonical_path(request)}\n{query}\n"
            + "".join(f"{name}:{headers[name]}\n" for name in signed)
            + f"\n{signed_string}\n{canonical_payload}"
        )
        return (f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n"
                f"{_sha(canonical.encode())}")

    # Built before the credential lookup (fail-closed wire validation),
    # with the presign signature parameter excluded from every candidate.
    candidates = _query_candidates(
        request.scope.get("query_string", b""), drop="X-Amz-Signature")
    secret = lookup_secret(access_key, permission)
    if secret is None:
        raise SigV4Error("AccessDenied", "Unknown, expired, revoked or unauthorized access key")
    key = _signing_key(secret, date, region, service)
    if not any(hmac.compare_digest(
            _signature(key, _to_sign(query)), signature)
            for query in candidates):
        raise SigV4Error("SignatureDoesNotMatch", "Presigned signature mismatch")
    return access_key


def presign_get_url(endpoint: str, bucket: str, key: str, access_key: str,
                    secret: str, expires: int = 3600, *,
                    region: str = "us-east-1",
                    now: datetime | None = None) -> str:
    """Create a presigned GET URL for one object.

    Mirrors _presigned_signature's canonical recipe exactly (host-only
    signed headers, UNSIGNED-PAYLOAD, sorted encoded query) so the
    gateway verifies its own URLs. The secret never leaves the caller.
    """
    if not (1 <= int(expires) <= 604800):
        raise ValueError("Expiry must be 1..604800 seconds")
    clock = now or datetime.now(timezone.utc)
    stamp = clock.strftime("%Y%m%dT%H%M%SZ")
    date = stamp[:8]
    host = endpoint.split("://", 1)[-1].rstrip("/")
    # Preserve EVERY segment byte-for-byte, including empty ones: the
    # verifier canonicalises the request path as received, so dropping empty
    # segments signed a DIFFERENT object than the one requested -- "a//b"
    # produced a URL for "a/b", and a trailing "dir/" dropped its slash.
    path = "/" + "/".join(
        quote(segment, safe="-_.~") for segment in (bucket, *key.split("/")))
    scope = f"{date}/{region}/s3/aws4_request"
    pairs = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Credential", f"{access_key}/{scope}"),
        ("X-Amz-Date", stamp),
        ("X-Amz-Expires", str(int(expires))),
        ("X-Amz-SignedHeaders", "host"),
    ]
    canonical_query = "&".join(
        f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
        for k, v in sorted(pairs, key=lambda p:
                           (quote(p[0], safe='-_.~'), quote(p[1], safe='-_.~')))
    )
    canonical = (
        f"GET\n{path}\n{canonical_query}\n"
        f"host:{host}\n\nhost\nUNSIGNED-PAYLOAD"
    )
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{_sha(canonical.encode())}"
    )
    auth_key = _hmac(b"AWS4" + secret.encode(), date)
    for word in (region, "s3", "aws4_request"):
        auth_key = _hmac(auth_key, word)
    signature = hmac.new(auth_key, string_to_sign.encode(),
                         hashlib.sha256).hexdigest()
    return (f"{endpoint.rstrip('/')}{path}?{canonical_query}"
            f"&X-Amz-Signature={signature}")


def verify_header_signature(request: Request, lookup_secret, permission: str, *,
                            now: datetime | None = None,
                            allow_s3express_zonal: bool = False) -> str:
    """Return authenticated access-key ID; never reveal the secret on failure.

    lookup_secret(access_key, permission) must atomically honor revocation and
    scope. The body digest is separately checked by the upload handler.
    ``allow_s3express_zonal`` admits the directory-bucket zonal actions under
    the ``s3express`` scope; the gateway sets it only for requests that
    target an existing directory bucket's object data plane, where the
    lookup_secret closure is an S3 Express session resolver.
    """
    if "X-Amz-Algorithm" in request.query_params or "X-Amz-Signature" in request.query_params:
        return _presigned_signature(request, lookup_secret, permission, now)
    auth = request.headers.get("authorization", "")
    match = re.fullmatch(
        r"AWS4-HMAC-SHA256 Credential=([^\s,/]{1,64})/(\d{8})/([a-z0-9-]{1,32})/"
        r"([a-z0-9]{1,16})/aws4_request,"
        r"\s*SignedHeaders=([a-z0-9;\-]+),\s*Signature=([0-9a-f]{64})",
        auth,
    )
    if match is None:
        raise SigV4Error("AccessDenied", "AWS Signature V4 Authorization required")
    access_key, date, region, service, headers_part, actual_signature = match.groups()
    service = _signing_service(permission, service,
                               zonal=allow_s3express_zonal)
    if service == "s3express" and region != _express_signing_region():
        raise SigV4Error(
            "AccessDenied",
            "S3 Express signing region does not match this deployment")
    signed = headers_part.split(";")
    if signed != sorted(set(signed)) or "host" not in signed or "x-amz-date" not in signed:
        raise SigV4Error("SignatureDoesNotMatch", "Invalid SignedHeaders")
    headers: dict[str, str] = {}
    for name in signed:
        # Ambiguous repeated signed headers are rejected rather than combined.
        values = [v.decode("latin-1") for k, v in request.scope["headers"]
                  if k.decode("ascii").lower() == name]
        if len(values) != 1:
            raise SigV4Error("SignatureDoesNotMatch", "Missing or ambiguous signed header")
        headers[name] = " ".join(values[0].strip().split())
    request_date = request.headers.get("x-amz-date", "")
    if not re.fullmatch(r"\d{8}T\d{6}Z", request_date) or request_date[:8] != date:
        raise SigV4Error("RequestTimeTooSkewed", "Invalid signed timestamp")
    try:
        instant = datetime.strptime(request_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SigV4Error("RequestTimeTooSkewed", "Invalid request timestamp") from exc
    clock = now or datetime.now(timezone.utc)
    if abs((clock - instant).total_seconds()) > 900:
        raise SigV4Error("RequestTimeTooSkewed", "Request timestamp outside 15-minute window")
    payload = request.headers.get("x-amz-content-sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", payload):
        if payload in STREAMING_MODES:
            # aws-chunked: chunk signatures (or a signed trailer
            # declaration) authenticate the payload; the body decoder
            # enforces them. Unsigned streaming additionally requires
            # the trailer declaration to be signed.
            if (payload == UNSIGNED_STREAMING_TRAILER
                    and "x-amz-trailer" not in signed):
                raise SigV4Error(
                    "InvalidRequest",
                    "Unsigned streaming requires a signed x-amz-trailer declaration")
        elif payload != "UNSIGNED-PAYLOAD":
            raise SigV4Error("XAmzContentSHA256Mismatch", "Signed SHA-256 payload required")
        elif request.method in {"PUT", "POST"} and not (
            "content-md5" in signed or "x-amz-checksum-sha256" in signed
        ):
            # A CreateMultipartUpload initiation carries NO body: the parts
            # are uploaded (and checksummed) individually afterwards, so
            # there is nothing for a payload digest to protect. Real clients
            # (Cyberduck 9.6.0 among them) send ?uploads= with
            # UNSIGNED-PAYLOAD and no checksum; refusing it broke every
            # upload above their multipart threshold. Exempt only the
            # zero-length initiation, matched by query selector AND an empty
            # declared body — anything that can carry bytes still needs a
            # digest.
            initiation = (
                "uploads" in request.query_params
                # Exactly zero bytes must be DECLARED: a missing length can
                # mean a chunked body, which would smuggle unverified bytes
                # past the digest rule. Never admit that shape.
                and request.headers.get("content-length", "").strip() == "0"
                and "transfer-encoding" not in request.headers
            )
            if not initiation:
                raise SigV4Error(
                    "XAmzContentSHA256Mismatch",
                    "Unsigned upload requires a signed Content-MD5 or "
                    "SHA-256 checksum",
                )
    scope = f"{date}/{region}/{service}/aws4_request"

    def _to_sign(query: str) -> str:
        canonical = (
            f"{request.method}\n{_canonical_path(request)}\n{query}\n"
            + "".join(f"{key}:{headers[key]}\n" for key in signed)
            + f"\n{headers_part}\n{payload}"
        )
        return (f"AWS4-HMAC-SHA256\n{request_date}\n{scope}\n"
                f"{_sha(canonical.encode())}")

    # A compliant client may have canonicalized the query either as the
    # raw as-sent tokens (botocore URL mode) or as the spec-literal
    # UriEncode form; both are deterministic functions of the wire
    # request, so either signature authenticates exactly what was sent.
    # The candidates (and their strict wire validation) are built BEFORE
    # the credential lookup: an untrusted query never reaches secrets.
    candidates = _query_candidates(
        request.scope.get("query_string", b""))
    secret = lookup_secret(access_key, permission)
    if secret is None:
        raise SigV4Error("AccessDenied", "Unknown, expired, revoked or unauthorized access key")
    key = _signing_key(secret, date, region, service)
    if not any(hmac.compare_digest(
            _signature(key, _to_sign(query)), actual_signature)
            for query in candidates):
        raise SigV4Error("SignatureDoesNotMatch", "Request signature mismatch")
    return access_key
