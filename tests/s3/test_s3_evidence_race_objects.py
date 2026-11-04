"""Race-column evidence for the object data plane of the S3 matrix.

Fills the ``race`` cells of ``docs/reference/s3-evidence.md`` for the
object operations whose contention is not a bucket configuration row:
the reads (GetObject, HeadObject, GetObjectAttributes,
SelectObjectContent), the object mutations (CopyObject, RenameObject,
DeleteObjects, UpdateObjectEncryption), the multipart data plane
(CreateMultipartUpload, UploadPart, UploadPartCopy,
AbortMultipartUpload) and RestoreObject.

The contract pinned per family is the honest one for a SQL catalog that
publishes immutable object versions by one head-pointer transaction:

* **read-vs-publish / read-vs-delete** — a reader that resolves the head
  while a writer publishes or unlinks observes *one complete version*:
  the old body/headers or the new body/headers, or a clean 404 after the
  unlink. Never a half-written body, never headers from one version with
  a body from another, never a 5xx. This holds because ``catalog.get``
  names one immutable object id and the body is streamed from that id,
  while the head swap is a single committed CAS.
* **write-vs-write on one key/slot** — two independent ``Database``
  connections (two processes) contending for one destination, one part
  slot or one version leave *exactly one* row/head; the loser either
  converges by last-write-wins or receives a designed conflict
  (409 ``OperationAborted`` / ``CopyConflict`` / ``MultipartError``).
  Never two heads, never two rows for one part number, never a merged
  object.
* **rotation** — two concurrent SSE-C rotations leave the object
  readable under exactly one of the new keys; the chunk journal and the
  encryption marker always describe the same complete rotation.
* **queue** — two concurrent RestoreObject requests for one archived
  version queue exactly once; the loser gets the designed
  ``RestoreAlreadyInProgress``/``conflict`` answer, never a second
  transition.

Every case forces the interleaving with a ``threading.Barrier``: each
worker opens a fresh ``Database`` (or issues a fresh signed request,
which opens one) and only then touches the store.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import threading
import time
from urllib.parse import quote

from sqlalchemy import func, select

from teledrive.s3.multipart import MultipartError, MultipartStore, parts, uploads
from teledrive.storage.catalog import BucketCatalog, heads, published_versions
from teledrive.storage.copy import CopyConflict
from teledrive.storage.manifest import ChunkReference, ManifestStore, objects
from tests.s3.test_s3_gateway import service, signed
from tests.s3.test_s3_multipart import begin, complete, setup, xml_text
from tests.s3.test_s3_select import _csv_request, _decode_messages, _records
from tests.s3.test_s3_sse_c import (
    COPY_PREFIX, KEY_A, KEY_B, raw_key, ssec_headers,
)

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
KEY_C = raw_key(3)
BUCKET = "race-objects"


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

def _fresh(service):
    """A new Database + catalog, as a second process would open it."""
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _barrier(count: int) -> threading.Barrier:
    return threading.Barrier(count, timeout=30)


def _run(bodies, *, timeout: float = 120.0):
    """Run every body on its own thread; all meet one barrier first.

    The body itself opens its connection, exactly like a separate
    process would. Returns one ``(status, value)`` pair per body.
    """
    barrier = _barrier(len(bodies))
    results: list[tuple[str, object] | None] = [None] * len(bodies)

    def worker(index, body):
        try:
            barrier.wait()
            results[index] = ("ok", body())
        except BaseException as exc:  # classified by the caller
            results[index] = ("error", exc)

    threads = [threading.Thread(target=worker, args=(index, body))
               for index, body in enumerate(bodies)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=timeout)
    assert not any(thread.is_alive() for thread in threads), (
        "an object race worker never finished")
    return results


def _bucket(service, name: str = BUCKET) -> str:
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return name


def _publish_version(service, bucket: str, key: str, payload: bytes,
                     *, message_id: int) -> str:
    """Stage and publish one immutable version through TWO connections."""
    service[2].parts[f"file-{message_id}"] = payload
    db, catalog = _fresh(service)
    try:
        now = int(time.time())
        digest = hashlib.sha256(payload).hexdigest()
        oid = catalog.manifests.begin(bucket, key, len(payload), now)
        catalog.manifests.append(oid, ChunkReference(
            ordinal=0, offset=0, size=len(payload), sha256=digest,
            account="mtproto-user", chat_id=-1001234567890,
            message_id=message_id), now)
        catalog.manifests.finish(oid, digest, now)
        catalog.publish(oid, now=now)
        return oid
    finally:
        db.close()


def _head_count(service, bucket: str, key: str) -> int:
    db, catalog = _fresh(service)
    try:
        return int(db.connection.execute(
            select(func.count()).select_from(heads).where(
                heads.c.bucket == bucket,
                heads.c.key_hash == catalog._keyhash(key))).scalar_one())
    finally:
        db.close()


def _head(service, bucket: str, key: str):
    db, catalog = _fresh(service)
    try:
        return db.connection.execute(
            select(heads.c.object_id, heads.c.generation).where(
                heads.c.bucket == bucket,
                heads.c.key_hash == catalog._keyhash(key))).first()
    finally:
        db.close()


def _published_count(service, bucket: str, key: str) -> int:
    db = service[3]()
    try:
        return int(db.connection.execute(
            select(func.count()).select_from(published_versions.join(
                objects, published_versions.c.object_id == objects.c.id,
            )).where(objects.c.bucket == bucket,
                     objects.c.object_key == key)).scalar_one())
    finally:
        db.close()


def _designed(exc: BaseException, *names: str) -> bool:
    text = f"{type(exc).__name__}: {exc}"
    return any(name in text for name in names)


# ---------------------------------------------------------------------------
# reads: GetObject / HeadObject / GetObjectAttributes
# ---------------------------------------------------------------------------

def test_get_head_attributes_each_read_one_complete_version(service):
    """GET/HEAD/attributes racing publish: old or new, never a mixture."""
    _bucket(service)
    key = "read.bin"
    # version id -> the complete body that version publishes.
    versions: dict[str, bytes] = {}
    first = _publish_version(service, BUCKET, key, b"old-payload-" + b"o" * 64,
                             message_id=76001)
    versions[first] = b"old-payload-" + b"o" * 64

    for round_number in range(8):
        payload = b"round-%02d-" % round_number + bytes([65 + round_number]) * 80
        published: dict[str, bytes] = {}
        barrier = threading.Barrier(2, timeout=30)

        def reader():
            barrier.wait()
            got = signed(service, "GET", f"/{BUCKET}/{key}")
            head = signed(service, "HEAD", f"/{BUCKET}/{key}")
            attrs = signed(
                service, "GET", f"/{BUCKET}/{key}?attributes",
                extra_headers={"x-amz-object-attributes":
                               "ETag,ObjectSize"})
            return got, head, attrs

        def writer():
            barrier.wait()
            identifier = _publish_version(service, BUCKET, key, payload,
                                          message_id=76010 + round_number)
            published[identifier] = payload
            return identifier

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            read_future = pool.submit(reader)
            write_future = pool.submit(writer)
            got, head, attrs = read_future.result(timeout=60)
            version = write_future.result(timeout=60)
        versions.update(published)

        assert got.status_code == 200, got.text
        # Negative: the body is exactly one complete version, never a
        # prefix of the old version followed by bytes of the new one.
        assert got.content in versions.values(), (
            f"a concurrent publish produced a torn body: {got.content!r}")
        body = got.content
        # Each response names the immutable version it served, so its
        # headers can be checked against THAT version, not against a
        # later independent GET (which may legitimately see the newer one).
        assert head.status_code == 200, head.text
        head_body = versions[head.headers["x-amz-version-id"]]
        assert int(head.headers["content-length"]) == len(head_body), (
            "HEAD served a version with a mismatched length")
        assert head.headers["etag"] == (
            '"' + hashlib.sha256(head_body).hexdigest() + '"')
        assert attrs.status_code == 200, attrs.text
        attrs_body = versions[attrs.headers["x-amz-version-id"]]
        assert str(len(attrs_body)).encode() in attrs.content
        assert hashlib.sha256(attrs_body).hexdigest().encode() in attrs.content
        assert version in versions


def test_get_and_head_across_delete_never_torn_or_error(service):
    """GET/HEAD racing unlink: the complete old object or a clean 404."""
    _bucket(service)
    key = "delete.bin"
    payload = b"read-while-unlinked-" * 32
    _publish_version(service, BUCKET, key, payload, message_id=76101)
    barrier = threading.Barrier(2, timeout=30)

    def reader():
        barrier.wait()
        return (signed(service, "GET", f"/{BUCKET}/{key}"),
                signed(service, "HEAD", f"/{BUCKET}/{key}"))

    def deleter():
        barrier.wait()
        db, catalog = _fresh(service)
        try:
            return catalog.remove_current(BUCKET, key)
        finally:
            db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(reader)
        delete_future = pool.submit(deleter)
        got, head = read_future.result(timeout=60)
        assert delete_future.result(timeout=60) is True

    assert got.status_code in (200, 404), got.text
    assert head.status_code in (200, 404), head.text
    if got.status_code == 200:
        assert got.content == payload, "a concurrent unlink tore the body"
        assert int(head.headers["content-length"]) == len(payload)
    else:
        assert head.status_code == 404, (
            "GET saw the object deleted while HEAD still served it")
    assert _head(service, BUCKET, key) is None


# ---------------------------------------------------------------------------
# reads: SelectObjectContent
# ---------------------------------------------------------------------------

def test_select_reads_exactly_one_complete_version(service):
    """Select races publish: complete old rows or complete new rows."""
    _bucket(service)
    key = "rows.csv"
    old = b"name,age\nalice,30\nbob,25\n"
    new = b"name,age\ncarol,41\ndave,19\neve,52\n"
    _publish_version(service, BUCKET, key, old, message_id=76201)
    old_records = b"alice,30\nbob,25\n"
    new_records = b"carol,41\ndave,19\neve,52\n"
    barrier = threading.Barrier(2, timeout=30)

    def reader():
        barrier.wait()
        return signed(service, "POST",
                      f"/{BUCKET}/{key}?select&select-type=2",
                      _csv_request("SELECT * FROM S3Object"))

    def writer():
        barrier.wait()
        _publish_version(service, BUCKET, key, new, message_id=76202)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(reader)
        write_future = pool.submit(writer)
        response = read_future.result(timeout=60)
        write_future.result(timeout=60)

    assert response.status_code == 200, response.text
    records = _records(_decode_messages(response.content))
    assert records in (old_records, new_records), (
        f"Select mixed two object versions: {records!r}")


# ---------------------------------------------------------------------------
# CopyObject / RenameObject
# ---------------------------------------------------------------------------

def _copy(service, source_key: str, destination_key: str):
    return signed(service, "PUT", f"/{BUCKET}/{destination_key}",
                  extra_headers={"x-amz-copy-source":
                                 f"/{BUCKET}/{source_key}"})


def test_two_concurrent_copies_leave_one_destination_object(service):
    """Copy-vs-copy to one destination: one head, one clean loser."""
    _bucket(service)
    _publish_version(service, BUCKET, "copy-a.bin", b"copy-source-a",
                     message_id=76301)
    _publish_version(service, BUCKET, "copy-b.bin", b"copy-source-b",
                     message_id=76302)
    outcomes = _run([
        lambda: _copy(service, "copy-a.bin", "destination.bin"),
        lambda: _copy(service, "copy-b.bin", "destination.bin"),
    ])
    responses = []
    for status, value in outcomes:
        assert status == "ok", value
        responses.append(value)
    codes = sorted(response.status_code for response in responses)
    assert codes[0] in (200, 409) and 200 in codes, codes
    # Exactly one head; the loser's clean conflict is 409 OperationAborted.
    assert _head_count(service, BUCKET, "destination.bin") == 1
    body = signed(service, "GET", f"/{BUCKET}/destination.bin")
    assert body.status_code == 200
    assert body.content in (b"copy-source-a", b"copy-source-b"), (
        "a concurrent copy merged two source objects")


def test_two_concurrent_renames_leave_one_destination_object(service):
    """Rename-vs-rename to one destination: one head, one clean 409.

    Both renames can pass the destination-occupied check before either
    commits; the head key is primary-keyed, so the loser must surface the
    designed ``OperationAborted`` conflict, never a raw IntegrityError
    (500) and never a second head.
    """
    _bucket(service)
    for round_number in range(4):
        bucket = f"race-rename-{round_number}"
        _bucket(service, bucket)
        _publish_version(service, bucket, "rename-a.bin", b"rename-source-a",
                         message_id=76401 + round_number * 2)
        _publish_version(service, bucket, "rename-b.bin", b"rename-source-b",
                         message_id=76402 + round_number * 2)

        def rename(source: str):
            return signed(
                service, "PUT", f"/{bucket}/renamed.bin?renameObject",
                extra_headers={"x-amz-rename-source": f"/{bucket}/{source}"})

        outcomes = _run([
            lambda: rename("rename-a.bin"),
            lambda: rename("rename-b.bin"),
        ])
        responses = []
        for status, value in outcomes:
            assert status == "ok", value
            responses.append(value)
        codes = sorted(response.status_code for response in responses)
        assert codes == [200, 409], (
            f"a rename race must answer one 200 and one 409, got {codes}")
        assert _head_count(service, bucket, "renamed.bin") == 1
        body = signed(service, "GET", f"/{bucket}/renamed.bin")
        assert body.status_code == 200
        assert body.content in (b"rename-source-a", b"rename-source-b")
        # Negative: the losing source still exists untouched; a conflict may
        # never destroy an object.
        surviving = [
            key for key in ("rename-a.bin", "rename-b.bin")
            if signed(service, "GET", f"/{bucket}/{key}").status_code == 200]
        assert len(surviving) == 1, surviving
        assert (b"rename-source-a" if surviving[0] == "rename-a.bin"
                else b"rename-source-b") == signed(
            service, "GET", f"/{bucket}/{surviving[0]}").content


def test_two_concurrent_copies_into_a_lock_bucket_stay_protected(service):
    """CopyObject carrying lock: the winning copy has the complete default."""
    _bucket(service)
    assert signed(service, "PUT", f"/{BUCKET}?object-lock",
                  b'<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/'
                  b'doc/2006-03-01/"><ObjectLockEnabled>Enabled'
                  b"</ObjectLockEnabled><Rule><DefaultRetention>"
                  b"<Mode>GOVERNANCE</Mode><Days>2</Days>"
                  b"</DefaultRetention></Rule></ObjectLockConfiguration>"
                  ).status_code == 200
    _publish_version(service, BUCKET, "locked-a.bin", b"locked-source-a",
                     message_id=76411)
    _publish_version(service, BUCKET, "locked-b.bin", b"locked-source-b",
                     message_id=76412)
    outcomes = _run([
        lambda: _copy(service, "locked-a.bin", "locked-dest.bin"),
        lambda: _copy(service, "locked-b.bin", "locked-dest.bin"),
    ])
    for status, value in outcomes:
        assert status == "ok", value
        assert value.status_code in (200, 409), value.text
    head = _head(service, BUCKET, "locked-dest.bin")
    assert head is not None
    db, catalog = _fresh(service)
    try:
        state = catalog.object_lock_state(head[0])
    finally:
        db.close()
    # The winner was published inside the same transaction as its default
    # retention: one complete tuple, never a mode without a window.
    assert state["mode"] == "GOVERNANCE", state
    assert state["retain_until_ns"] is not None
    assert int(state["retain_until_ns"]) > time.time_ns()
    denied = signed(service, "DELETE",
                    f"/{BUCKET}/locked-dest.bin?versionId={head[0]}")
    assert denied.status_code == 403, denied.text


# ---------------------------------------------------------------------------
# UpdateObjectEncryption
# ---------------------------------------------------------------------------

def test_two_concurrent_rotations_leave_one_complete_key(service):
    """SSE-C rotation-vs-rotation: one key, chunk journal and marker agree."""
    assert signed(service, "PUT", "/race-sse").status_code == 200
    payload = b"rotation-race-payload-" * 40
    put = signed(service, "PUT", "/race-sse/rotate.bin", payload,
                 extra_headers=ssec_headers(KEY_A))
    assert put.status_code == 200, put.text

    def rotate(new_key):
        return signed(
            service, "PUT", "/race-sse/rotate.bin?encryption", b"",
            extra_headers={**ssec_headers(new_key),
                           **ssec_headers(KEY_A, prefix=COPY_PREFIX)})

    outcomes = _run([
        lambda: rotate(KEY_B),
        lambda: rotate(KEY_C),
    ])
    responses = []
    for status, value in outcomes:
        assert status == "ok", value
        responses.append(value)
    codes = sorted(response.status_code for response in responses)
    assert codes[0] in (200, 400), codes
    assert 200 in codes, codes

    winners = []
    for key in (KEY_B, KEY_C):
        got = signed(service, "GET", "/race-sse/rotate.bin",
                     extra_headers=ssec_headers(key))
        if got.status_code == 200:
            assert got.content == payload, (
                "a concurrent rotation left a torn object")
            winners.append(key)
    # Exactly one of the two new keys reads the object; the other is the
    # designed 400 (its old key is gone).
    assert len(winners) == 1, (
        f"concurrent rotations left {len(winners)} readable keys")
    assert signed(service, "GET", "/race-sse/rotate.bin",
                  extra_headers=ssec_headers(KEY_A)).status_code == 400


# ---------------------------------------------------------------------------
# DeleteObjects
# ---------------------------------------------------------------------------

def test_concurrent_batch_version_deletes_revoke_exactly_once(service):
    """DeleteObjects batch: one version revoked once, one clean loser."""
    _bucket(service)
    key = "batch.bin"
    first = _publish_version(service, BUCKET, key, b"batch-v1",
                            message_id=76501)
    _publish_version(service, BUCKET, key, b"batch-v2", message_id=76502)

    def delete():
        db, catalog = _fresh(service)
        try:
            return catalog.delete_version(BUCKET, key, first)
        finally:
            db.close()

    outcomes = _run([delete, delete])
    values = []
    for status, value in outcomes:
        assert status == "ok", value
        values.append(value)
    assert sorted(values) == [False, True], values

    db, catalog = _fresh(service)
    try:
        from teledrive.storage.catalog import removed_versions
        removed = db.connection.execute(select(func.count()).select_from(
            removed_versions).where(
            removed_versions.c.object_id == first)).scalar_one()
        assert removed == 1, "one version was revoked twice"
        assert catalog.current_marker(BUCKET, key) is None
        assert catalog.get(BUCKET, key).item.id != first
        assert _head_count(service, BUCKET, key) == 1
    finally:
        db.close()
    assert signed(service, "GET", f"/{BUCKET}/{key}").content == b"batch-v2"


def test_concurrent_batch_deletes_create_one_current_marker(service):
    """Two concurrent key deletes append versions but leave one head."""
    _bucket(service)
    key = "marker.bin"
    _publish_version(service, BUCKET, key, b"marker-payload",
                     message_id=76511)

    def delete():
        db, catalog = _fresh(service)
        try:
            return catalog.delete_marker(BUCKET, key)
        finally:
            db.close()

    outcomes = _run([delete, delete])
    markers = []
    for status, value in outcomes:
        if status == "ok":
            markers.append(value)
        else:
            # A loser that read the old head before the winner committed
            # gets the designed CAS refusal, never a torn state.
            assert _designed(value, "Concurrent object deletion/write"), value
    assert markers, "both concurrent deletes were refused"
    assert len(set(markers)) == len(markers)
    assert _head_count(service, BUCKET, key) == 1
    head = _head(service, BUCKET, key)
    assert head[0] in markers
    assert _published_count(service, BUCKET, key) == 1 + len(markers)
    assert signed(service, "GET", f"/{BUCKET}/{key}").status_code == 404


# ---------------------------------------------------------------------------
# multipart: CreateMultipartUpload / UploadPart / UploadPartCopy /
# AbortMultipartUpload
# ---------------------------------------------------------------------------

def test_concurrent_creates_open_distinct_complete_sessions(service):
    """CreateMultipartUpload-vs-create: two rows, two usable sessions."""
    setup(service)

    def create():
        return signed(service, "POST", "/backup-bucket/asset.bin?uploads")

    outcomes = _run([create, create])
    ids = []
    for status, value in outcomes:
        assert status == "ok", value
        assert value.status_code == 200, value.text
        ids.append(xml_text(value, "UploadId"))
    assert len(set(ids)) == 2, "two creates shared one upload id"
    db, catalog = _fresh(service)
    try:
        rows = db.connection.execute(select(uploads.c.id).where(
            uploads.c.id.in_(ids))).scalars().all()
        assert sorted(rows) == sorted(ids)
        for identifier in ids:
            account = db.connection.execute(select(
                uploads.c.state).where(uploads.c.id == identifier)
            ).scalar_one()
            assert account == "active"
    finally:
        db.close()
    for identifier in ids:
        assert signed(
            service, "GET",
            f"/backup-bucket/asset.bin?uploadId={identifier}"
        ).status_code == 200


def test_two_concurrent_upload_parts_leave_one_slot(service):
    """UploadPart-vs-part: exactly one parts row for the part number."""
    setup(service)
    uid = begin(service)
    payloads = {b"part-writer-a" * 4, b"part-writer-b" * 5}

    def upload(payload):
        return signed(
            service, "PUT",
            f"/backup-bucket/asset.bin?partNumber=5&uploadId={uid}",
            payload)

    outcomes = _run([
        lambda: upload(b"part-writer-a" * 4),
        lambda: upload(b"part-writer-b" * 5),
    ])
    etags = []
    for status, value in outcomes:
        assert status == "ok", value
        assert value.status_code in (200, 409), value.text
        if value.status_code == 200:
            etags.append(value.headers["etag"])
    assert etags, outcomes

    db, catalog = _fresh(service)
    try:
        rows = db.connection.execute(select(
            parts.c.object_id, parts.c.etag).where(
            parts.c.upload_id == uid, parts.c.number == 5)).all()
    finally:
        db.close()
    assert len(rows) == 1, f"the part slot holds {len(rows)} rows"
    stored_etag = '"' + rows[0][1] + '"'
    assert stored_etag in etags, "the surviving row is not a writer's part"

    done = complete(service, uid, [(5, stored_etag)])
    assert done.status_code == 200, done.text
    body = signed(service, "GET", "/backup-bucket/asset.bin")
    assert body.status_code == 200
    # Negative: the published object is exactly one writer's part bytes.
    assert any(body.content == sha for sha in payloads), body.content


def test_two_concurrent_part_copies_leave_one_slot(service):
    """UploadPartCopy-vs-copy: exactly one parts row for the part number."""
    setup(service)
    sources = {"source-a.bin": b"copy-part-a" * 6,
               "source-b.bin": b"copy-part-b" * 7}
    for name, payload in sources.items():
        assert signed(service, "PUT", f"/backup-bucket/{name}",
                      payload).status_code == 200
    uid = begin(service)

    def copy_part(source):
        return signed(
            service, "PUT",
            f"/backup-bucket/asset.bin?partNumber=5&uploadId={uid}",
            extra_headers={"x-amz-copy-source": f"/backup-bucket/{source}"})

    outcomes = _run([
        lambda: copy_part("source-a.bin"),
        lambda: copy_part("source-b.bin"),
    ])
    for status, value in outcomes:
        assert status == "ok", value
        assert value.status_code in (200, 409), value.text

    db, catalog = _fresh(service)
    try:
        rows = db.connection.execute(select(
            parts.c.object_id, parts.c.etag).where(
            parts.c.upload_id == uid, parts.c.number == 5)).all()
    finally:
        db.close()
    assert len(rows) == 1, f"the part-copy slot holds {len(rows)} rows"
    etag = '"' + rows[0][1] + '"'
    done = complete(service, uid, [(5, etag)])
    assert done.status_code == 200, done.text
    body = signed(service, "GET", "/backup-bucket/asset.bin")
    assert body.content in sources.values(), (
        "a concurrent part copy published mixed source bytes")


def test_two_concurrent_aborts_leave_one_dead_session(service):
    """Abort-vs-abort: one state transition, one clean loser."""
    setup(service)
    uid = begin(service)

    def abort():
        return signed(
            service, "DELETE",
            f"/backup-bucket/asset.bin?uploadId={uid}")

    outcomes = _run([abort, abort])
    codes = []
    for status, value in outcomes:
        assert status == "ok", value
        codes.append(value.status_code)
    assert sorted(codes)[0] in (204, 404, 409), codes
    assert 204 in codes, codes

    db, catalog = _fresh(service)
    try:
        state = db.connection.execute(select(uploads.c.state).where(
            uploads.c.id == uid)).scalar_one()
        assert state == "aborted"
        assert db.connection.execute(select(func.count()).select_from(
            published_versions).where(
            published_versions.c.object_id == uid)).scalar_one() == 0
    finally:
        db.close()
    assert signed(
        service, "GET",
        f"/backup-bucket/asset.bin?uploadId={uid}").status_code == 404


# ---------------------------------------------------------------------------
# RestoreObject
# ---------------------------------------------------------------------------

def test_two_concurrent_restore_requests_queue_once(service, tmp_path,
                                                    monkeypatch):
    """Restore-vs-restore: exactly one ARCHIVED -> RESTORING transition."""
    monkeypatch.setenv("TELEDRIVE_COLD_ARCHIVE_DIR", str(tmp_path / "cold"))
    _bucket(service)
    key = "cold.bin"
    version = _publish_version(service, BUCKET, key, b"cold-payload",
                               message_id=76601)
    from teledrive.storage.cold_store import archive_versions
    db, _catalog = _fresh(service)
    try:
        now = time.time_ns()
        db.connection.execute(archive_versions.insert().values(
            object_id=version, bucket=BUCKET, object_key=key,
            state="ARCHIVED", generation=0, idempotency_key="race-" + version,
            whole_sha256=hashlib.sha256(b"cold-payload").hexdigest(),
            stored_bytes=len(b"cold-payload"), created_ns=now, updated_ns=now))
        db.commit()
    finally:
        db.close()

    def restore(days):
        from teledrive.storage.cold_store import ArchiveStore, ColdBlobStore
        db, catalog = _fresh(service)
        try:
            return ArchiveStore(
                catalog, ColdBlobStore(tmp_path / "cold")
            ).request_restore(version, days=days, now_ns=time.time_ns())
        finally:
            db.close()

    outcomes = _run([lambda: restore(1), lambda: restore(2)])
    values = []
    for status, value in outcomes:
        assert status == "ok", value
        values.append(value)
    assert sorted(values) == ["conflict", "queued"], values
    db, _catalog = _fresh(service)
    try:
        row = db.connection.execute(select(
            archive_versions.c.state, archive_versions.c.generation,
            archive_versions.c.restore_days).where(
            archive_versions.c.object_id == version)).one()
    finally:
        db.close()
    assert row[0] == "RESTORING"
    assert row[1] == 1, "two restore requests advanced the fence twice"
    assert row[2] in (1, 2)
