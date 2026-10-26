"""Phase I website hosting: S3 config contract, public route and public_read.

The public route is exercised through the real web app (same origin as the
WebUI), against the same SQLite database and deterministic Telegram transport
used by the signed S3 gateway.
"""
from __future__ import annotations

import time
from xml.etree import ElementTree as ET

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import web.app as webapp
from tests.s3.test_s3_gateway import service, signed
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.website import parse_website_xml, website_xml, WebsiteError
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
ADMIN_AUTH = ("testadmin", "secure-auth-password")
CSRF = {"x-teledrive-csrf": "1"}


def website_xml_body(index="index.html", error=None):
    root = ET.Element("WebsiteConfiguration")
    index_node = ET.SubElement(root, "IndexDocument")
    ET.SubElement(index_node, "Suffix").text = index
    if error is not None:
        error_node = ET.SubElement(root, "ErrorDocument")
        ET.SubElement(error_node, "Key").text = error
    return ET.tostring(root)


def create_bucket(service, name="site-bucket"):
    assert signed(service, "PUT", "/" + name).status_code == 200


def put_object(service, bucket, key, body, content_type=None):
    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    response = signed(service, "PUT", f"/{bucket}/{key}", body,
                      extra_headers=headers or None)
    assert response.status_code == 200, response.text
    return response


def admin_config(web, bucket, *, index="index.html", error=None,
                 public_read=True):
    return web.put(
        f"/api/v1/admin/storage/buckets/{bucket}/website",
        auth=ADMIN_AUTH, headers=CSRF,
        json={"index_document": index, "error_document": error,
              "public_read": public_read},
    )


def seed_user(connection, username: str, password: str, role: str) -> None:
    db = connection()
    try:
        db.connection.execute(text(
            "INSERT INTO users (username, password_hash, role, enabled, "
            "created_at, updated_at) VALUES (:u, :p, :r, 1, :now, :now)"
        ), {"u": username, "p": webapp._hash_password(password),
            "r": role, "now": int(time.time())})
        db.connection.commit()
    finally:
        db.close()


@pytest.fixture
def site(service, monkeypatch, tmp_path):
    _, _, telegram, connection, _ = service
    monkeypatch.setattr(webapp, "db_connect", connection)
    monkeypatch.setattr(webapp, "storage_transport", lambda db: telegram)
    monkeypatch.setattr(webapp, "STORAGE_SCRATCH_DIR",
                        str(tmp_path / "website-staging"))
    monkeypatch.setattr(webapp, "WEB_USER", ADMIN_AUTH[0])
    monkeypatch.setattr(webapp, "WEB_PASSWORD", ADMIN_AUTH[1])
    webapp.AUTH_FAILURES.clear()
    web = TestClient(webapp.app, base_url="http://localhost:8080")
    try:
        yield web, connection
    finally:
        web.close()


def test_enabled_flag_off_by_default_and_uniform_404(service, site):
    web, connection = site
    create_bucket(service)
    put_object(service, "site-bucket", "index.html", b"<h1>private</h1>")

    # No config at all, a nonexistent bucket and a config-only bucket all
    # answer the same 404 before public_read is turned on.
    for path in ("/site/site-bucket/", "/site/site-bucket/index.html",
                 "/site/no-such-bucket/", "/site/site-bucket/missing"):
        reply = web.get(path)
        assert reply.status_code == 404, path
        assert reply.content == b"Not Found\n"

    # S3 PutBucketWebsite writes the config but never publishes the bucket.
    assert signed(service, "PUT", "/site-bucket?website",
                  website_xml_body()).status_code == 200
    assert web.get("/site/site-bucket/").status_code == 404
    assert web.get("/site/site-bucket/index.html").status_code == 404

    # The admin API can store the config with the gate still closed.
    assert admin_config(web, "site-bucket", public_read=False).status_code == 200
    assert web.get("/site/site-bucket/").status_code == 404

    db = connection()
    try:
        assert BucketCatalog(ManifestStore(db)).public_read("site-bucket") is False
    finally:
        db.close()


def test_index_and_error_document_semantics(service, site):
    web, _ = site
    create_bucket(service)
    put_object(service, "site-bucket", "index.html", b"ROOT",
               content_type="text/html")
    put_object(service, "site-bucket", "dir/index.html", b"DIR",
               content_type="text/html")
    put_object(service, "site-bucket", "error.html", b"<h1>ERR</h1>",
               content_type="text/html")
    put_object(service, "site-bucket", "page.html", b"PAGE",
               content_type="text/html")
    assert admin_config(web, "site-bucket", index="index.html",
                        error="error.html").status_code == 200

    root = web.get("/site/site-bucket/")
    assert root.status_code == 200 and root.content == b"ROOT"
    assert root.headers["content-type"].startswith("text/html")

    # Trailing slash and directory-name forms both serve dir/index.html.
    for path in ("/site/site-bucket/dir/", "/site/site-bucket/dir"):
        reply = web.get(path)
        assert reply.status_code == 200 and reply.content == b"DIR", path

    page = web.get("/site/site-bucket/page.html")
    assert page.status_code == 200 and page.content == b"PAGE"

    missing = web.get("/site/site-bucket/missing.html")
    assert missing.status_code == 404
    assert missing.content == b"<h1>ERR</h1>"

    # A directory without an index document is a 404 error document, never
    # a generated directory listing.
    no_index = web.get("/site/site-bucket/empty-dir/")
    assert no_index.status_code == 404
    assert no_index.content == b"<h1>ERR</h1>"
    assert b"empty-dir" not in no_index.content


def test_only_current_ready_objects_are_served(service, site):
    web, _ = site
    create_bucket(service)
    assert admin_config(web, "site-bucket", error=None).status_code == 200
    put_object(service, "site-bucket", "page.html", b"version-one")
    assert web.get("/site/site-bucket/page.html").content == b"version-one"

    # A second PUT moves the current head; the old version is not public.
    put_object(service, "site-bucket", "page.html", b"version-two")
    assert web.get("/site/site-bucket/page.html").content == b"version-two"

    # DELETE writes a logical tombstone. The deleted object must 404 even
    # though its immutable manifest/media still exist for GC.
    assert signed(service, "DELETE", "/site-bucket/page.html").status_code == 204
    gone = web.get("/site/site-bucket/page.html")
    assert gone.status_code == 404
    assert gone.content == b"Not Found\n"


def test_traversal_absolute_paths_and_directory_listing_rejected(service, site):
    web, _ = site
    create_bucket(service)
    put_object(service, "site-bucket", "index.html", b"ROOT")
    put_object(service, "site-bucket", "secret.txt", b"SECRET")
    assert admin_config(web, "site-bucket").status_code == 200

    # Unit-level truth for the decoder: each of these is refused.
    for bad in ("../secret.txt", "a/../../secret.txt", "%2e%2e/secret.txt",
                "%252e%252e/secret.txt", "/etc/passwd", "C:/windows/win.ini",
                "a\\b.txt", "a\x00b.txt", "a//b.txt", "~/secret.txt"):
        assert webapp._site_path(bad) is None, bad
    assert webapp._site_path("dir/index.html") == "dir/index.html"
    assert webapp._site_path("") == ""

    # HTTP-level: encoded traversal never reaches an object.
    for path in ("/site/site-bucket/%2e%2e/secret.txt",
                 "/site/site-bucket/%252e%252e/secret.txt",
                 "/site/site-bucket/%2fetc%2fpasswd"):
        reply = web.get(path)
        assert reply.status_code == 404, path
        assert b"SECRET" not in reply.content


def test_csp_nosniff_and_safe_content_type(service, site):
    web, _ = site
    create_bucket(service)
    put_object(service, "site-bucket", "index.html", b"<h1>ok</h1>",
               content_type="text/html")
    put_object(service, "site-bucket", "blob.bin", b"\x00\x01\x02")
    assert admin_config(web, "site-bucket").status_code == 200

    for path in ("/site/site-bucket/", "/site/site-bucket/blob.bin"):
        reply = web.get(path)
        assert reply.status_code == 200
        csp = reply.headers["content-security-policy"]
        assert "sandbox" in csp and "default-src 'none'" in csp
        assert reply.headers["x-content-type-options"] == "nosniff"
        assert reply.headers["cache-control"] == "no-store"
    assert web.get("/site/site-bucket/").headers["content-type"].startswith(
        "text/html")
    assert web.get("/site/site-bucket/blob.bin").headers[
        "content-type"] == "application/octet-stream"


def test_delete_clears_config_and_public_read(service, site):
    web, connection = site
    create_bucket(service)
    put_object(service, "site-bucket", "index.html", b"ROOT")
    assert admin_config(web, "site-bucket").status_code == 200
    assert web.get("/site/site-bucket/").status_code == 200

    assert signed(service, "DELETE", "/site-bucket?website").status_code == 204
    assert web.get("/site/site-bucket/").status_code == 404
    assert signed(service, "GET", "/site-bucket?website").status_code == 404

    from teledrive.storage.manifest import ManifestStore
    db = connection()
    try:
        assert BucketCatalog(ManifestStore(db)).public_read("site-bucket") is False
    finally:
        db.close()

    # Deleting an absent website is idempotent.
    assert signed(service, "DELETE", "/site-bucket?website").status_code == 204


def test_strict_xml_rejections_and_unsupported_redirects(service, site):
    web, _ = site
    create_bucket(service)
    path = "/site-bucket?website"
    assert signed(service, "PUT", path, website_xml_body()).status_code == 200
    before = signed(service, "GET", path).content

    redirect = (b"<WebsiteConfiguration><RedirectAllRequestsTo>"
                b"<HostName>example.com</HostName>"
                b"</RedirectAllRequestsTo></WebsiteConfiguration>")
    routing = (b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix>"
               b"</IndexDocument><RoutingRules><RoutingRule/></RoutingRules>"
               b"</WebsiteConfiguration>")
    assert signed(service, "PUT", path, redirect).status_code == 501
    assert signed(service, "PUT", path, routing).status_code == 501
    for malformed in (
        b"<not-website/>",
        b"<WebsiteConfiguration><IndexDocument/></WebsiteConfiguration>",
        b"<WebsiteConfiguration><IndexDocument><Suffix>../x</Suffix>"
        b"</IndexDocument></WebsiteConfiguration>",
        b"<WebsiteConfiguration><IndexDocument><Suffix>/abs</Suffix>"
        b"</IndexDocument></WebsiteConfiguration>",
        b"<WebsiteConfiguration><Unexpected/></WebsiteConfiguration>",
        b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix>"
        b"</IndexDocument><IndexDocument><Suffix>x</Suffix></IndexDocument>"
        b"</WebsiteConfiguration>",
        b"x" * (16 * 1024 + 1),
    ):
        reply = signed(service, "PUT", path, malformed)
        assert reply.status_code == 400, (malformed[:80], reply.text)
    # Failed writes never replace the stored configuration.
    assert signed(service, "GET", path).content == before

    assert parse_website_xml(website_xml_body())[
        "index_document"] == "index.html"
    with pytest.raises(WebsiteError):
        parse_website_xml(b"<WebsiteConfiguration/>")
    rendered = ET.fromstring(website_xml(
        {"index_document": "index.html", "error_document": "404.html",
         "enabled": True}))
    assert rendered.findtext(NS + "IndexDocument/" + NS + "Suffix") == "index.html"
    assert rendered.findtext(NS + "ErrorDocument/" + NS + "Key") == "404.html"


def test_operator_cannot_enable_public_read(service, site):
    web, connection = site
    create_bucket(service)
    seed_user(connection, "opuser", "operator-password-1", "operator")
    login = web.post("/api/auth/login", headers=CSRF,
                     json={"username": "opuser",
                           "password": "operator-password-1"})
    assert login.status_code == 200, login.text
    bearer = {"Authorization": "Bearer " + login.json()["token"], **CSRF}
    denied = web.put(
        "/api/v1/admin/storage/buckets/site-bucket/website",
        headers=bearer,
        json={"index_document": "index.html", "error_document": None,
              "public_read": True},
    )
    assert denied.status_code == 403, denied.text
    assert web.get("/site/site-bucket/").status_code == 404

    # Admin (Basic auth) can make the same decision. Drop the operator
    # session cookie so Basic auth is evaluated on its own.
    web.cookies.clear()
    assert admin_config(web, "site-bucket").status_code == 200
    assert web.get("/site/site-bucket/").status_code == 404  # no index object


def test_permission_separation_for_website_controls(service):
    create_bucket(service)
    db = service[3]()
    try:
        keys = S3CredentialStore(db, service[4])
        reader = keys.create("website-reader", ["s3:GetBucketWebsite"])
        writer = keys.create("website-writer", ["s3:PutBucketWebsite"])
        deleter = keys.create("website-deleter", ["s3:DeleteBucketWebsite"])
        object_only = keys.create("object-only", ["s3:GetObject"])
    finally:
        db.close()
    path = "/site-bucket?website"
    body = website_xml_body()
    assert signed(service, "GET", path, access=object_only.access_key,
                  secret=object_only.secret_key).status_code == 403
    assert signed(service, "PUT", path, body, access=object_only.access_key,
                  secret=object_only.secret_key).status_code == 403

    assert signed(service, "PUT", path, body, access=reader.access_key,
                  secret=reader.secret_key).status_code == 403
    assert signed(service, "PUT", path, body, access=writer.access_key,
                  secret=writer.secret_key).status_code == 200
    assert signed(service, "GET", path, access=writer.access_key,
                  secret=writer.secret_key).status_code == 403
    assert signed(service, "GET", path, access=reader.access_key,
                  secret=reader.secret_key).status_code == 200
    assert signed(service, "DELETE", path, access=reader.access_key,
                  secret=reader.secret_key).status_code == 403
    assert signed(service, "DELETE", path, access=deleter.access_key,
                  secret=deleter.secret_key).status_code == 204


def test_bucket_deletion_removes_website_state(service, site):
    web, connection = site
    create_bucket(service, "empty-site")
    assert admin_config(web, "empty-site", public_read=True).status_code == 200
    db = connection()
    try:
        assert db.connection.execute(text(
            "SELECT COUNT(*) FROM storage_website_configs "
            "WHERE bucket = 'empty-site'")).scalar_one() == 1
    finally:
        db.close()

    assert signed(service, "DELETE", "/empty-site").status_code == 204
    db = connection()
    try:
        assert db.connection.execute(text(
            "SELECT COUNT(*) FROM storage_website_configs "
            "WHERE bucket = 'empty-site'")).scalar_one() == 0
    finally:
        db.close()

    # A recreated bucket starts private and unconfigured.
    create_bucket(service, "empty-site")
    assert web.get("/site/empty-site/").status_code == 404
    assert signed(service, "GET", "/empty-site?website").status_code == 404
