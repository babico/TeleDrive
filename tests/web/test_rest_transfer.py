"""HTTP binary transfer contract: actual SQLite metadata and fake USER MTProto bytes."""
from __future__ import annotations

import hashlib
import os

import pytest
from fastapi.testclient import TestClient

import web.app as webapp
PRODUCTION_TRANSPORT = webapp.storage_transport
from teledrive.db import connect_database


class FakeUserTransport:
    """Disk-backed USER MTProto stand-in: same upload/download contract."""

    def __init__(self):
        self.parts = {}
        self.counter = 0
        self.deletions = 0

    async def upload(self, path, *, object_id, ordinal, checksum):
        self.counter += 1
        identifier = f"test-part-{self.counter}"
        self.parts[identifier] = path.read_bytes()
        return "mtproto-user", -1001234567890, self.counter

    async def verify_target(self):
        pass

    async def download(self, reference, destination):
        destination.write_bytes(self.parts[f"test-part-{reference.message_id}"])


@pytest.fixture
def service(tmp_path, monkeypatch):
    path = tmp_path / "state.db"
    bot = FakeUserTransport()
    monkeypatch.setattr(webapp, "db_connect", lambda: connect_database(str(path)))
    monkeypatch.setattr(
        webapp, "storage_transport", lambda db: bot,
    )
    monkeypatch.setattr(webapp, "STORAGE_SCRATCH_DIR", str(tmp_path / "scratch"))
    monkeypatch.setattr(webapp, "REST_MAX_UPLOAD_BYTES", 4 * 1024**2)
    from tests import seed_local_user
    seed_local_user(lambda: connect_database(str(path)),
                    "admin-test", "some-long-password", "admin")
    webapp.AUTH_FAILURES.clear()
    client = TestClient(webapp.app, headers={"host": "localhost"})
    try:
        from tests import login_headers
        response = client.post("/api/v1/admin/keys",
            headers={**login_headers(client, "admin-test", "some-long-password"),
                     "x-teledrive-csrf": "1"}, json={
                "name": "storage-integration", "scopes": [
                    "buckets:read", "buckets:manage", "objects:read",
                    "objects:write", "objects:delete",
                ],
            })
        assert response.status_code == 201, response.text
        token = response.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        res = client.post("/api/v1/buckets", headers=headers, json={"name": "backup-bucket"})
        assert res.status_code == 201, res.text
        yield client, headers, bot, tmp_path
    finally:
        client.close()


def put(client, headers, payload, key="data.bin"):
    return client.put("/api/v1/buckets/backup-bucket/content",
                      params={"key": key}, headers={
                          **headers, "Content-Type": "application/octet-stream"
                      }, content=payload)


# Deterministic payloads: os.urandom inside parametrize prints the whole
# repr into the test id, so every pytest-xdist worker collects a different
# id and collection fails. These still cross the chunk and multi-MiB paths.
_CHUNK_CROSSING = bytes((i * 31 + 7) % 256 for i in range(4097))
_MULTI_MIB = bytes((i * 17 + 3) % 256 for i in range(1_049_600))


@pytest.mark.parametrize("data", [b"", b"x", _CHUNK_CROSSING, _MULTI_MIB])
def test_binary_round_trip_persists_bytes_not_in_sql(service, data):
    client, headers, bot, root = service
    uploaded = put(client, headers, data)
    assert uploaded.status_code == 201, uploaded.text
    identifier = uploaded.json()["id"]
    assert uploaded.json()["sha256"] == hashlib.sha256(data).hexdigest()
    assert uploaded.json()["size"] == len(data)
    result = client.get("/api/v1/buckets/backup-bucket/content",
                        params={"key": "data.bin"}, headers=headers)
    assert result.status_code == 200, result.text
    assert result.content == data
    assert result.headers["etag"] == '"' + hashlib.sha256(data).hexdigest() + '"'
    assert result.headers["x-teledrive-object-id"] == identifier
    assert not list((root / "scratch").glob("api-upload-*"))
    # SQLite stores manifests/file_ids, never the file bytes.
    if len(data) > 100:
        assert data[:100] not in (root / "state.db").read_bytes()


def test_http_range_suffix_and_unsatisfiable_ranges(service):
    client, headers, _, _ = service
    data = b"0123456789abcdef"
    assert put(client, headers, data).status_code == 201
    for range_header, expected in [
        ("bytes=3-8", b"345678"),
        ("bytes=7-", b"789abcdef"),
        ("bytes=-4", b"cdef"),
    ]:
        result = client.get("/api/v1/buckets/backup-bucket/content",
            params={"key": "data.bin"}, headers={**headers, "Range": range_header})
        assert result.status_code == 206
        assert result.content == expected
        assert result.headers["content-length"] == str(len(expected))
    for invalid in ["bytes=50-60", "bytes=8-3", "bytes=0-1,4-6", "units=0-1"]:
        result = client.get("/api/v1/buckets/backup-bucket/content",
            params={"key": "data.bin"}, headers={**headers, "Range": invalid})
        assert result.status_code == 416


def test_auth_and_upload_policy_enforced_before_telegram_send(service):
    client, headers, bot, _ = service
    args = {"key": "denied"}
    url = "/api/v1/buckets/backup-bucket/content"
    assert client.put(url, params=args, headers={"Content-Type": "application/octet-stream"},
                      content=b"secret").status_code == 401
    assert client.put(url, params=args, headers=headers, content=b"secret").status_code == 415
    assert client.put(url, params=args, headers={
        **headers, "Content-Type": "application/octet-stream",
    }, content=b"z" * (4 * 1024**2 + 1)).status_code == 413
    assert bot.counter == 0


def test_missing_key_is_404_and_overwrite_is_versioned(service):
    client, headers, bot, _ = service
    assert client.get("/api/v1/buckets/backup-bucket/content",
                      params={"key": "absent"}, headers=headers).status_code == 404
    one = put(client, headers, b"one")
    two = put(client, headers, b"two")
    assert one.status_code == 201 and two.status_code == 201
    assert one.json()["id"] != two.json()["id"]
    assert two.json()["generation"] == 2
    result = client.get("/api/v1/buckets/backup-bucket/content",
                        params={"key": "data.bin"}, headers=headers)
    assert result.content == b"two"
    uploads_before_conflict = bot.counter
    conflicting = client.put("/api/v1/buckets/backup-bucket/content",
        params={"key": "data.bin", "generation": 1},
        headers={**headers, "Content-Type": "application/octet-stream"}, content=b"three")
    assert conflicting.status_code == 409
    assert bot.counter == uploads_before_conflict  # zero Telegram writes for a stale generation


def test_missing_user_session_returns_503_before_upload(service, monkeypatch):
    client, headers, bot, _ = service
    # The service fixture temporarily patches the transport. Restore the
    # production factory and remove its required Telegram configuration.
    monkeypatch.setattr(webapp, "storage_transport", PRODUCTION_TRANSPORT)
    monkeypatch.delenv("TELEDRIVE_STORAGE_MTPROTO_API_ID", raising=False)
    monkeypatch.delenv("TELEDRIVE_STORAGE_MTPROTO_API_HASH", raising=False)
    monkeypatch.delenv("TELEDRIVE_STORAGE_MTPROTO_CHANNEL", raising=False)
    monkeypatch.delenv("TELEDRIVE_STORAGE_MTPROTO_SESSION_FILE", raising=False)
    result = put(client, headers, b"secret", key="unconfigured")
    assert result.status_code == 503
    assert bot.counter == 0


def test_head_returns_actual_object_metadata_without_telegram_download(service):
    client, headers, bot, _ = service
    body = os.urandom(257)
    uploaded = put(client, headers, body, key="head-check.bin")
    assert uploaded.status_code == 201
    calls_before = bot.counter
    result = client.head(
        "/api/v1/buckets/backup-bucket/content",
        params={"key": "head-check.bin"}, headers=headers,
    )
    assert result.status_code == 200
    assert result.content == b""
    assert result.headers["content-length"] == str(len(body))
    assert result.headers["etag"] == '"' + hashlib.sha256(body).hexdigest() + '"'
    assert result.headers["x-teledrive-object-id"] == uploaded.json()["id"]
    assert bot.counter == calls_before

    absent = client.head(
        "/api/v1/buckets/backup-bucket/content",
        params={"key": "does-not-exist"}, headers=headers,
    )
    assert absent.status_code == 404

    forbidden = client.head(
        "/api/v1/buckets/backup-bucket/content",
        params={"key": "head-check.bin"},
    )
    assert forbidden.status_code == 401


# --- Signed public share links -------------------------------------------

ADMIN = ("admin-test", "some-long-password")


def _admin_headers(client):
    from tests import login_headers
    return login_headers(client, *ADMIN)


def _admin_post(client, path, **kw):
    kw["headers"] = {**_admin_headers(client), **kw.get("headers", {}),
                     "x-teledrive-csrf": "1"}
    return client.post(path, **kw)


def _share(client, payload, bucket="backup-bucket"):
    webapp._share_rate.clear()
    return _admin_post(
        client, f"/api/v1/admin/storage/buckets/{bucket}/shares",
        json=payload)


def test_share_link_streams_object_without_auth(service):
    client, headers, _, _ = service
    payload = os.urandom(8192)
    assert put(client, headers, payload).status_code in (200, 201)

    r = _share(client, {"key": "data.bin", "expires_in": 3600})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert r.json()["path"] == f"/share/{token}"

    # Unauthenticated GET streams the exact bytes.
    res = client.get(f"/share/{token}")
    assert res.status_code == 200
    assert res.content == payload
    assert res.headers["content-type"].startswith("application/octet-stream")
    assert "attachment" in res.headers.get("content-disposition", "")

    # The download is counted and reported by the admin listing.
    listing = client.get("/api/v1/admin/storage/shares", headers=_admin_headers(client))
    assert listing.status_code == 200
    entry = next(s for s in listing.json()["shares"] if s["token"] == token)
    assert entry["download_count"] == 1
    assert entry["status"] == "active"


def test_share_link_password_gate(service):
    client, headers, _, _ = service
    payload = b"secret-shared-bytes"
    assert put(client, headers, payload).status_code in (200, 201)
    webapp._share_rate.clear()
    r = _admin_post(client, "/api/v1/admin/storage/buckets/backup-bucket/shares",
                    json={"key": "data.bin", "password": "hunter2"})
    token = r.json()["token"]

    # GET shows an HTML password form, never the bytes.
    page = client.get(f"/share/{token}")
    assert page.status_code == 200
    assert "password" in page.text and b"secret-shared-bytes" not in page.content

    # Wrong password is rejected without consuming a download slot.
    bad = client.post(f"/share/{token}", data={"password": "nope"})
    assert bad.status_code == 401

    # Correct password streams the object.
    good = client.post(f"/share/{token}", data={"password": "hunter2"})
    assert good.status_code == 200 and good.content == payload


def test_share_link_expiry_count_and_revocation(service):
    client, headers, _, tmp = service
    assert put(client, headers, b"bounded").status_code in (200, 201)
    webapp._share_rate.clear()
    r = _admin_post(client, "/api/v1/admin/storage/buckets/backup-bucket/shares",
                    json={"key": "data.bin", "max_downloads": 1})
    token = r.json()["token"]
    assert client.get(f"/share/{token}").status_code == 200
    # Exhausted: uniform 404.
    assert client.get(f"/share/{token}").status_code == 404

    # A second link, expired by force via the DB: uniform 404.
    webapp._share_rate.clear()
    r = _admin_post(client, "/api/v1/admin/storage/buckets/backup-bucket/shares",
                    json={"key": "data.bin", "expires_in": 3600})
    token2 = r.json()["token"]
    db = webapp.db_connect()
    try:
        from sqlalchemy import text
        db.connection.execute(text(
            "UPDATE share_links SET expires_at = 1 WHERE token = :t"),
            {"t": token2})
        db.commit()
    finally:
        db.close()
    assert client.get(f"/share/{token2}").status_code == 404

    # Revocation removes the link.
    webapp._share_rate.clear()
    r = _admin_post(client, "/api/v1/admin/storage/buckets/backup-bucket/shares",
                    json={"key": "data.bin"})
    token3 = r.json()["token"]
    revoked = client.delete(f"/api/v1/admin/storage/shares/{token3}",
                            headers={**_admin_headers(client),
                                     "x-teledrive-csrf": "1"})
    assert revoked.status_code == 200
    assert client.get(f"/share/{token3}").status_code == 404

    # Unknown and malformed tokens answer 404 without leaking anything.
    assert client.get("/share/does-not-exist-token").status_code == 404
    assert client.get("/share/../../etc/passwd").status_code in (404, 403, 422)


def test_share_creation_validation(service):
    client, headers, _, _ = service
    assert put(client, headers, b"x").status_code in (200, 201)
    webapp._share_rate.clear()
    base = "/api/v1/admin/storage/buckets/backup-bucket/shares"
    assert _admin_post(client, base, json={"key": ""}).status_code == 422
    assert _admin_post(client, base, json={}).status_code == 422
    assert _admin_post(client, base, json={
        "key": "data.bin", "expires_in": 1}).status_code == 422
    assert _admin_post(client, base, json={
        "key": "data.bin", "max_downloads": 0}).status_code == 422
    assert _admin_post(client, base, json={
        "key": "data.bin", "password": ""}).status_code == 422
    # Missing object and missing bucket are 404.
    assert _admin_post(client, base, json={"key": "ghost.bin"}).status_code == 404
    assert _admin_post(client, "/api/v1/admin/storage/buckets/nope/shares",
                       json={"key": "x"}).status_code == 404


def test_share_public_route_rate_limit(service):
    client, headers, _, _ = service
    assert put(client, headers, b"limited").status_code in (200, 201)
    webapp._share_rate.clear()
    r = _admin_post(client, "/api/v1/admin/storage/buckets/backup-bucket/shares",
                    json={"key": "data.bin"})
    token = r.json()["token"]
    codes = [client.get(f"/share/{token}").status_code for _ in range(70)]
    assert 429 in codes, codes[:5]


# --- Content search ---------------------------------------------------------

def test_content_search_and_reindex(service):
    client, headers, _, _ = service
    # A text upload is indexed automatically at upload time.
    body = b"quarterly report with unique-zeta-marker figures"
    assert put(client, headers, body, key="report-2026.txt").status_code in (200, 201)
    # A binary upload is never indexed.
    assert put(client, headers, b"\x00\x01\x02\x03",
               key="blob.bin").status_code in (200, 201)

    r = client.get("/api/v1/admin/storage/search",
                   headers=_admin_headers(client), params={"q": "unique-zeta-marker",
                                       "mode": "content"})
    assert r.status_code == 200
    results = r.json()["objects"]
    assert len(results) == 1
    assert results[0]["key"] == "report-2026.txt"
    assert "unique-zeta-marker" in results[0]["snippet"]

    # Key mode is unchanged and does not match content.
    r = client.get("/api/v1/admin/storage/search",
                   headers=_admin_headers(client), params={"q": "unique-zeta-marker"})
    assert [o["key"] for o in r.json()["objects"]] == []

    # Invalid mode is rejected.
    assert client.get("/api/v1/admin/storage/search",
                      headers=_admin_headers(client),
                      params={"q": "x", "mode": "wild"}).status_code == 422

    # Reindex backfill: wiping the index makes the object searchable again.
    db = webapp.db_connect()
    try:
        from sqlalchemy import text
        db.connection.execute(text("DELETE FROM object_content_index"))
        db.connection.execute(
            text("DELETE FROM object_content_fts"))
        db.commit()
    finally:
        db.close()
    r = client.get("/api/v1/admin/storage/search",
                   headers=_admin_headers(client), params={"q": "unique-zeta-marker",
                                       "mode": "content"})
    assert r.json()["objects"] == []

    r = client.post("/api/v1/admin/storage/search/reindex",
                    headers={**_admin_headers(client),
                             "x-teledrive-csrf": "1"},
                    json={"limit": 10})
    assert r.status_code == 200, r.text
    assert r.json()["indexed"] >= 1

    r = client.get("/api/v1/admin/storage/search",
                   headers=_admin_headers(client), params={"q": "unique-zeta-marker",
                                       "mode": "content"})
    assert len(r.json()["objects"]) == 1


def test_share_token_is_a_credential_not_public_metadata(service):
    """A share token must not leak to a read-only principal.

    Found by the API review: a ``viewer`` could call
    ``GET /api/v1/admin/storage/shares`` and read every live token, then
    use ``/share/<token>`` anonymously -- turning a read-only account into
    a publisher whose access outlives its own revocation. Worse, the audit
    middleware logged ``request.url.path`` verbatim, so the same token was
    readable through ``/api/logs``.
    """
    client, headers, _, _ = service
    assert put(client, headers, b"share-token-exposure").status_code in (200, 201)
    created = _share(client, {"key": "data.bin", "expires_in": 3600})
    assert created.status_code == 200, created.text
    token = created.json()["token"]

    # A viewer may not enumerate credentials.
    db_path = webapp.db_connect().engine.url.database
    from tests import seed_local_user
    seed_local_user(lambda: connect_database(db_path),
                    "peeker", "peeker-password-1", "viewer")
    from tests import login_headers
    viewer = login_headers(client, "peeker", "peeker-password-1")
    assert client.get("/api/v1/admin/storage/shares",
                      headers=viewer).status_code == 403

    # A viewer cannot read the log stream at all, and no log line may contain
    # the token, including the one the middleware writes for the anonymous
    # download -- checked as admin, who CAN read it.
    assert client.get(f"/share/{token}").status_code == 200
    assert client.get("/api/v1/logs", headers=viewer).status_code == 403
    from tests import login_headers as _login
    admin_logs = client.get("/api/v1/logs",
                            headers=_login(client, "admin-test",
                                           "some-long-password"))
    assert admin_logs.status_code == 200
    assert token not in admin_logs.text, "share token leaked into the log stream"


def test_multibyte_key_is_rejected_before_any_upload(service):
    """A publish-time key rejection used to orphan uploaded bytes.

    The query parameter bounds the key to 1024 CHARACTERS but the catalog
    bounds it to 1024 UTF-8 BYTES. A 600-character multibyte key passed the
    request layer, uploaded the whole payload to Telegram, and only then
    failed at publish -- leaving a ready manifest with no published version,
    which physical GC never collects. The key is now validated first.
    """
    client, headers, bot, _ = service
    before = bot.counter
    reply = put(client, headers, b"x" * 4096, key="é" * 600)
    assert reply.status_code == 422, reply.text
    assert bot.counter == before, "bytes reached Telegram for a doomed key"


def test_rest_reads_refuse_an_archived_object_until_restored(service):
    """Tiering is an access gate; the REST read path must apply it too.

    The S3 data plane answers 403 InvalidObjectState for an archived object,
    but this handler never called object_read_state, so archived bytes
    streamed with 200/206 -- the access control was simply absent on one of
    the two read surfaces.
    """
    from sqlalchemy import text
    client, headers, bot, _ = service
    body = os.urandom(300)
    uploaded = put(client, headers, body, key="cold.bin")
    assert uploaded.status_code == 201
    oid = uploaded.json()["id"]

    db = connect_database(webapp.db_connect().engine.url.database)
    try:
        db.connection.execute(text(
            "UPDATE storage_objects SET storage_class = 'ARCHIVE_ACCESS', "
            "restore_until_ns = NULL WHERE id = :o"), {"o": oid})
        db.connection.commit()
    finally:
        db.close()

    before = bot.counter
    denied = client.get("/api/v1/buckets/backup-bucket/content",
                        params={"key": "cold.bin"}, headers=headers)
    assert denied.status_code == 403, denied.text
    assert "InvalidObjectState" in denied.text
    assert client.head("/api/v1/buckets/backup-bucket/content",
                       params={"key": "cold.bin"}, headers=headers
                       ).status_code == 403
    assert bot.counter == before, "archived bytes were streamed anyway"

    # An open restore window makes it readable again.
    db = connect_database(webapp.db_connect().engine.url.database)
    try:
        from sqlalchemy import text as _text
        db.connection.execute(_text(
            "UPDATE storage_objects SET restore_until_ns = :until WHERE id = :o"),
            {"until": (2 ** 63) - 1, "o": oid})
        db.connection.commit()
    finally:
        db.close()
    restored = client.get("/api/v1/buckets/backup-bucket/content",
                          params={"key": "cold.bin"}, headers=headers)
    assert restored.status_code == 200
    assert restored.content == body


def test_rest_get_refuses_an_sse_c_object_instead_of_empty_200(service):
    """A 200 with Content-Length and zero bytes is a silent data-loss shape."""
    from sqlalchemy import text
    client, headers, bot, _ = service
    uploaded = put(client, headers, b"secret-bytes", key="enc.bin")
    assert uploaded.status_code == 201
    oid = uploaded.json()["id"]

    db = connect_database(webapp.db_connect().engine.url.database)
    try:
        db.connection.execute(text(
            "INSERT INTO storage_object_encryption "
            "(object_id, mode, key_md5, created_at) "
            "VALUES (:o, 'SSE-C', :md5, 1)"),
            {"o": oid, "md5": "a" * 24})
        db.connection.commit()
    finally:
        db.close()

    resp = client.get("/api/v1/buckets/backup-bucket/content",
                      params={"key": "enc.bin"}, headers=headers)
    assert resp.status_code == 400, resp.text
    assert "SSE-C" in resp.text
    assert resp.content != b""
    assert client.head("/api/v1/buckets/backup-bucket/content",
                       params={"key": "enc.bin"}, headers=headers
                       ).status_code == 400


def test_share_link_is_bound_to_the_object_it_shared(service):
    """An unauthenticated link must not re-target replaced content.

    The row stored only (bucket, key) and resolution followed the live head,
    so a shared URL served NEW bytes after an overwrite, and came back to
    life after an unlink plus a re-upload. Verified before the fix: the same
    token returned ``200 NEW-CONTENT``.
    """
    client, headers, _, _ = service
    assert put(client, headers, b"ORIGINAL", key="shared.bin").status_code == 201
    created = _share(client, {"key": "shared.bin", "expires_in": 3600})
    assert created.status_code == 200, created.text
    token = created.json()["token"]

    first = client.get(f"/share/{token}")
    assert first.status_code == 200 and first.content == b"ORIGINAL"

    # Overwrite the key with different bytes.
    assert put(client, headers, b"REPLACED", key="shared.bin").status_code == 201
    after_overwrite = client.get(f"/share/{token}")
    # The slot budget is the link's, not the key's: serving the NEW bytes
    # would be the bug, so a 404 (link exhausted of meaning) is expected
    # only if the object is unreachable -- otherwise it must still be ORIGINAL.
    if after_overwrite.status_code == 200:
        assert after_overwrite.content == b"ORIGINAL", "link re-targeted"

    # Unlink and re-upload: the link must never serve the new object.
    assert client.delete("/api/v1/buckets/backup-bucket/objects",
                         params={"key": "shared.bin"},
                         headers=headers).status_code in (200, 409)
    assert put(client, headers, b"THIRD", key="shared.bin").status_code == 201
    revived = client.get(f"/share/{token}")
    if revived.status_code == 200:
        assert revived.content != b"THIRD", "link revived for a new upload"


def test_share_404_does_not_consume_a_download_slot(service):
    """A failed request must not spend the link's budget.

    The counter was incremented before the object was resolved, so any link
    preview bot, retry loop or stale bookmark silently exhausted the quota
    without anyone downloading anything.
    """
    from sqlalchemy import text
    client, headers, _, _ = service
    assert put(client, headers, b"slot-budget", key="slot.bin").status_code == 201
    created = _share(client, {"key": "slot.bin", "max_downloads": 5})
    assert created.status_code == 200, created.text
    token = created.json()["token"]

    db = connect_database(webapp.db_connect().engine.url.database)
    try:
        db.connection.execute(text(
            "UPDATE share_links SET object_id = 'gone-object-id' "
            "WHERE token = :t"), {"t": token})
        db.connection.commit()
    finally:
        db.close()

    for _ in range(4):
        assert client.get(f"/share/{token}").status_code == 404

    db = connect_database(webapp.db_connect().engine.url.database)
    try:
        count = db.connection.execute(text(
            "SELECT download_count FROM share_links WHERE token = :t"),
            {"t": token}).scalar_one()
    finally:
        db.close()
    assert count == 0, "a 404 consumed download slots"
