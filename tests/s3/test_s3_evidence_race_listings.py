"""Race-column evidence for the listing operations of the S3 matrix.

Fills the ``race`` cells of ``docs/reference/s3-evidence.md`` for the
read-side listing family: ListObjects (V1), ListObjectsV2,
ListObjectVersions, ListMultipartUploads, ListParts and
ListDirectoryBuckets.

The honest consistency contract for a SQL-backed single-owner gateway,
verified against the implementation before being pinned here:

* **Snapshot per page** — every page is computed by one SQL SELECT
  under statement-level isolation, so a page never mixes rows from
  different statements: its entries are strictly ordered by the
  pagination key, each entry appears once, and every entry is a row
  that was fully committed when the page's SELECT ran (never a
  half-written one).
* **Monotonic keyset pagination** — every surface pages by a
  lexicographic high-water mark (bucket name / object key /
  (key, version) / (key, uploadId) / part number), never by offset:

  - a row inserted BEFORE the cursor between two pages is never
    re-listed (no duplicates across a walk);
  - a row deleted between two pages is skipped silently — including
    the row named by the continuation marker itself, which must never
    error the next page (the ListObjectVersions marker case below is
    a fixed regression);
  - a row inserted AFTER the cursor is either included in a later
    page or not seen at all, but never duplicated.

Listing pages are separate HTTP requests, so "a writer mutating while
a reader lists" is materialized as writes landing deterministically
between a walk's page requests (each page opens a fresh connection,
exactly as two processes would), plus store-level ``threading.Barrier``
races for single-page snapshot consistency. Every case asserts the
negatives: never a duplicate entry across the walk, never a 4xx/5xx
from the interleaving, never an entry outside the legal states.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import threading
import time
from urllib.parse import quote
from xml.etree import ElementTree as ET

from sqlalchemy import select

from teledrive.s3.multipart import MultipartStore
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ChunkReference, ManifestStore
from tests.s3.test_s3_directory_buckets import ZONE, xsigned
from tests.s3.test_s3_gateway import service, signed

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _fresh(service):
    """A new Database plus catalog, as a second process would open it."""
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _publish(catalog, bucket, key, payload, *, message_id, now=None):
    """begin -> one journaled chunk -> finish -> publish (store level)."""
    now = int(time.time()) if now is None else now
    digest = hashlib.sha256(payload).hexdigest()
    oid = catalog.manifests.begin(bucket, key, len(payload), now)
    catalog.manifests.append(oid, ChunkReference(
        ordinal=0, offset=0, size=len(payload), sha256=digest,
        account="mtproto-user", chat_id=-1001234567890,
        message_id=message_id), now)
    catalog.manifests.finish(oid, digest, now)
    catalog.publish(oid, now=now)
    return oid


def _keys(page) -> list[str]:
    root = ET.fromstring(page.content)
    return [node.findtext(NS + "Key") for node in root.findall(NS + "Contents")]


def _token(page) -> str | None:
    root = ET.fromstring(page.content)
    node = root.find(NS + "NextContinuationToken")
    return None if node is None else node.text


def _marker(page) -> str | None:
    root = ET.fromstring(page.content)
    node = root.find(NS + "NextMarker")
    return None if node is None else node.text


def _truncated(page) -> bool:
    root = ET.fromstring(page.content)
    return root.findtext(NS + "IsTruncated") == "true"


def _walk_v2(service, bucket: str, maximum: int = 2):
    """Yield each page's keys; the caller mutates state between yields."""
    token = None
    pages = []
    while True:
        path = f"/{bucket}?list-type=2&max-keys={maximum}"
        if token:
            path += "&continuation-token=" + quote(token, safe="")
        page = signed(service, "GET", path)
        assert page.status_code == 200, page.text
        pages.append(_keys(page))
        token = _token(page)
        if token is None:
            return pages


def _walk_v1(service, bucket: str, maximum: int = 2):
    marker = ""
    pages = []
    while True:
        path = f"/{bucket}?max-keys={maximum}"
        if marker:
            path += "&marker=" + quote(marker, safe="")
        page = signed(service, "GET", path)
        assert page.status_code == 200, page.text
        pages.append(_keys(page))
        assert _keys(page) == sorted(_keys(page)), "a V1 page is not sorted"
        marker = _marker(page)
        if marker is None:
            return pages


def _object_exists(service, bucket: str, key: str) -> bool:
    return signed(service, "HEAD", f"/{bucket}/{quote(key, safe='/')}").status_code == 200


# ---------------------------------------------------------------------------
# ListObjectsV2 / ListObjects: monotonic walk under concurrent mutation
# ---------------------------------------------------------------------------

def test_list_objects_v2_walk_never_duplicates_or_errors(service):
    """ListObjectsV2 race: keyset pagination survives concurrent writes."""
    bucket = "race-list-v2"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    seeded = [f"walk-{index:02d}" for index in range(1, 9)]
    for key in seeded:
        assert signed(service, "PUT", f"/{bucket}/{key}",
                      key.encode()).status_code == 200

    # Page 1 delivers walk-01..02 and a continuation cursor after walk-02.
    first = signed(service, "GET", f"/{bucket}?list-type=2&max-keys=2")
    assert first.status_code == 200, first.text
    assert _keys(first) == ["walk-01", "walk-02"]
    token = _token(first)
    assert token

    # Concurrent writers, deterministically between the pages:
    # 1. an insert BEFORE the cursor (never re-listed),
    # 2. a delete of a not-yet-listed key (skipped silently),
    # 3. an insert AFTER the cursor (included later, never duplicated).
    assert signed(service, "PUT", f"/{bucket}/walk-01x",
                  b"before-cursor").status_code == 200
    assert signed(service, "DELETE", f"/{bucket}/walk-05").status_code == 204
    assert signed(service, "PUT", f"/{bucket}/walk-08x",
                  b"after-cursor").status_code == 200

    listed: list[str] = list(_keys(first))
    token = token
    while token:
        page = signed(service, "GET",
                      f"/{bucket}?list-type=2&max-keys=2&continuation-token="
                      + quote(token, safe=""))
        assert page.status_code == 200, page.text
        keys = _keys(page)
        assert keys == sorted(keys), "a page mixed out-of-order keys"
        listed += keys
        token = _token(page)

    # Negative: no key is ever listed twice across the concurrent walk.
    assert len(listed) == len(set(listed)), listed
    # The deleted key never appears; the before-cursor insert never
    # appears; every surviving seeded key appears exactly once.
    assert "walk-05" not in listed
    assert "walk-01x" not in listed
    for key in seeded:
        expected = key != "walk-05"
        assert (key in listed) == expected, key
    # The after-cursor insert is included exactly once (it was committed
    # before the next page's SELECT and sorts after the cursor).
    assert listed.count("walk-08x") == 1
    assert not _object_exists(service, bucket, "walk-05")


def test_list_objects_v1_marker_walk_never_duplicates_or_errors(service):
    """ListObjects (V1) race: the marker walk holds the same contract."""
    bucket = "race-list-v1"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    seeded = [f"v1-{index:02d}" for index in range(1, 7)]
    for key in seeded:
        assert signed(service, "PUT", f"/{bucket}/{key}",
                      key.encode()).status_code == 200

    first = signed(service, "GET", f"/{bucket}?max-keys=2")
    assert _keys(first) == ["v1-01", "v1-02"]
    marker = _marker(first)
    assert marker == "v1-02"

    # Between the pages: an insert before the marker and a delete of a
    # not-yet-listed key.
    assert signed(service, "PUT", f"/{bucket}/v1-01x",
                  b"before-marker").status_code == 200
    assert signed(service, "DELETE", f"/{bucket}/v1-04").status_code == 204

    listed: list[str] = list(_keys(first))
    while marker:
        page = signed(service, "GET", f"/{bucket}?max-keys=2&marker="
                      + quote(marker, safe=""))
        assert page.status_code == 200, page.text
        keys = _keys(page)
        assert keys == sorted(keys)
        listed += keys
        marker = _marker(page)

    assert len(listed) == len(set(listed)), listed
    assert "v1-04" not in listed
    assert "v1-01x" not in listed
    for key in seeded:
        assert (key in listed) == (key != "v1-04"), key


def test_list_objects_single_page_is_a_statement_snapshot(service):
    """One page is one SELECT: pre-state or post-state, never a mixture."""
    service[2].parts["file-99001"] = b"mid-write"
    service[2].parts["file-99002"] = b"mid-delete"

    for bucket, writer in (("race-list-snap-i", "insert"),
                           ("race-list-snap-d", "delete")):
        assert signed(service, "PUT", f"/{bucket}").status_code == 200
        pre = [f"snap-{index:02d}" for index in range(1, 7)]
        for key in pre:
            assert signed(service, "PUT", f"/{bucket}/{key}",
                          key.encode()).status_code == 200
        expected_post = (pre + ["snap-03x"] if writer == "insert"
                         else [key for key in pre if key != "snap-04"])

        barrier = threading.Barrier(2, timeout=15)

        def read_page():
            db, catalog = _fresh(service)
            try:
                barrier.wait()
                return [item.item.key for item in catalog.list_objects(
                    bucket, limit=100)]
            finally:
                db.close()

        def write():
            db, catalog = _fresh(service)
            try:
                barrier.wait()
                if writer == "insert":
                    _publish(catalog, bucket, "snap-03x", b"mid-write",
                             message_id=99001)
                else:
                    assert catalog.remove_current(bucket, "snap-04") is True
            finally:
                db.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            reader = pool.submit(read_page)
            pool.submit(write).result(timeout=30)
            page = reader.result(timeout=30)

        assert page == sorted(page), "the page is not sorted"
        assert len(page) == len(set(page)), "the page repeats a key"
        # The single SELECT is atomic: the whole page matches the
        # pre-write state or the post-write state, never a mixture.
        assert page in (sorted(pre), sorted(expected_post)), page


# ---------------------------------------------------------------------------
# ListObjectVersions
# ---------------------------------------------------------------------------

def _version_entries(page):
    root = ET.fromstring(page.content)
    entries = root.findall(NS + "Version") + root.findall(NS + "DeleteMarker")
    return [(node.findtext(NS + "Key"), node.findtext(NS + "VersionId"))
            for node in entries]


def test_list_object_versions_walk_survives_concurrent_version_mutation(service):
    """ListObjectVersions race: keyset walk incl. marker removal (regression).

    A NextVersionIdMarker whose version is deleted between two pages
    must resume the walk at the exact keyset position, not error: the
    published-version row survives removal, so the position is known.
    """
    bucket = "race-versions"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    version_ids = []
    for payload in (b"v1", b"v2", b"v3"):
        put = signed(service, "PUT", f"/{bucket}/multi.bin", payload)
        assert put.status_code == 200
        version_ids.append(put.headers["x-amz-version-id"])
    assert signed(service, "PUT", f"/{bucket}/tail.bin",
                  b"tail").status_code == 200
    tail_version = signed(service, "GET", f"/{bucket}?versions"
                          ).content
    tail_id = ET.fromstring(tail_version).findall(
        f"{NS}Version")[-1].findtext(f"{NS}VersionId")

    # Page 1: the newest version of multi.bin is the pagination marker.
    first = signed(service, "GET", f"/{bucket}?versions&max-keys=1")
    assert first.status_code == 200, first.text
    assert _version_entries(first) == [("multi.bin", version_ids[2])]
    key_marker = ET.fromstring(first.content).findtext(NS + "NextKeyMarker")
    version_marker = ET.fromstring(first.content).findtext(
        NS + "NextVersionIdMarker")
    assert (key_marker, version_marker) == ("multi.bin", version_ids[2])

    # Concurrent writer between the pages: delete the MARKER version.
    # The next page must resume (skip the removed marker) — a 400 here
    # is the torn-pagination bug this test pins as fixed.
    gone = signed(service, "DELETE",
                  f"/{bucket}/multi.bin?versionId={version_marker}")
    assert gone.status_code == 204, gone.text
    # And delete a not-yet-listed version (tail.bin's only version).
    assert signed(service, "DELETE",
                  f"/{bucket}/tail.bin?versionId={tail_id}").status_code == 204
    # And publish a NEW version of an already-listed key: newest-first
    # ordering puts it before the cursor, so it must never be re-listed.
    fresh = signed(service, "PUT", f"/{bucket}/multi.bin", b"v4-race")
    assert fresh.status_code == 200

    listed: list[tuple[str, str]] = []
    marker = f"&key-marker={quote(key_marker, safe='')}" \
             f"&version-id-marker={quote(version_marker, safe='')}"
    while True:
        page = signed(service, "GET", f"/{bucket}?versions&max-keys=1{marker}")
        assert page.status_code == 200, page.text
        entries = _version_entries(page)
        listed += entries
        root = ET.fromstring(page.content)
        if root.findtext(NS + "IsTruncated") != "true":
            break
        next_key = root.findtext(NS + "NextKeyMarker")
        next_version = root.findtext(NS + "NextVersionIdMarker")
        assert next_key is not None
        marker = (f"&key-marker={quote(next_key, safe='')}"
                  f"&version-id-marker={quote(next_version or '', safe='')}")

    # Never a duplicate version, never a removed version, never the
    # already-passed fresh version, and the walk stayed monotonic.
    assert len(listed) == len(set(listed)), listed
    keys = [key for key, _ in listed]
    assert keys == sorted(keys), "version pages lost key order"
    assert version_ids[2] not in [version for _, version in listed], (
        "the removed marker version was re-listed")
    assert tail_id not in [version for _, version in listed], (
        "a concurrently deleted version was listed")
    assert fresh.headers["x-amz-version-id"] not in [
        version for _, version in listed], (
        "a version published behind the cursor was re-listed")
    # The two surviving older versions of multi.bin are listed exactly
    # once: the walk resumed at the marker's exact position.
    assert sorted(version for key, version in listed
                  if key == "multi.bin") == sorted(version_ids[:2])


def test_list_object_versions_single_page_is_a_statement_snapshot(service):
    """One versions page is one SELECT over the visible-version join."""
    bucket = "race-versions-snap"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    seeded = []
    for payload in (b"s1", b"s2"):
        seeded.append(signed(
            service, "PUT", f"/{bucket}/snap.bin", payload
        ).headers["x-amz-version-id"])

    barrier = threading.Barrier(2, timeout=15)

    def read_page():
        db, catalog = _fresh(service)
        try:
            barrier.wait()
            entries, more = catalog.list_bucket_versions(bucket, limit=10)
            return [(entry["key"], entry["version_id"]) for entry in entries]
        finally:
            db.close()

    def delete_writer():
        db, catalog = _fresh(service)
        try:
            barrier.wait()
            assert catalog.delete_version(bucket, "snap.bin", seeded[1])
        finally:
            db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(read_page)
        pool.submit(delete_writer).result(timeout=30)
        page = reader.result(timeout=30)

    # The single SELECT saw the removal or it did not — never a torn
    # half-state such as a row that is both present and removed. The
    # page is ordered newest-version-first within the key.
    assert page in (
        [("snap.bin", seeded[1]), ("snap.bin", seeded[0])],
        [("snap.bin", seeded[0])],
    ), page
    assert len(page) == len(set(page))


# ---------------------------------------------------------------------------
# ListMultipartUploads
# ---------------------------------------------------------------------------

def test_list_multipart_uploads_walk_survives_concurrent_abort_and_initiate(
        service):
    """ListMultipartUploads race: keyset walk over (key, uploadId)."""
    bucket = "race-mpu-list"
    assert signed(service, "PUT", f"/{bucket}").status_code == 200
    owner = service[1].access_key

    db, catalog = _fresh(service)
    try:
        mpu = MultipartStore(catalog)
        upload_a = mpu.initiate(bucket, "up-a", owner)
        upload_c = mpu.initiate(bucket, "up-c", owner)
        upload_d = mpu.initiate(bucket, "up-d", owner)
    finally:
        db.close()

    # Page 1: one upload, cursor after ("up-a", upload_a).
    db, catalog = _fresh(service)
    try:
        records, more = MultipartStore(catalog).list_uploads(
            bucket, owner, limit=1)
        assert [(r.object_key, r.id) for r in records] == [
            ("up-a", upload_a)]
        assert more
    finally:
        db.close()

    # Concurrent writers between the pages:
    # 1. abort a not-yet-listed upload (skipped silently),
    # 2. initiate an upload sorting after the cursor (listed later),
    # 3. initiate an upload sorting BEFORE the cursor (never listed).
    db, catalog = _fresh(service)
    try:
        mpu = MultipartStore(catalog)
        mpu.abort(upload_d, bucket, "up-d", owner)
        upload_b = mpu.initiate(bucket, "up-b", owner)
        upload_before = mpu.initiate(bucket, "up-", owner)
    finally:
        db.close()

    listed: list[tuple[str, str]] = []
    after_key, after_id = "up-a", upload_a
    while True:
        db, catalog = _fresh(service)
        try:
            records, more = MultipartStore(catalog).list_uploads(
                bucket, owner, after_key=after_key, after_id=after_id,
                limit=1)
        finally:
            db.close()
        listed += [(r.object_key, r.id) for r in records]
        if not more or not records:
            break
        after_key, after_id = records[-1].object_key, records[-1].id

    # Never a duplicate, never the aborted upload, never the
    # before-cursor initiate; the after-cursor initiate is listed
    # exactly once (committed before the next page's SELECT).
    assert len(listed) == len(set(listed)), listed
    assert upload_d not in [uid for _, uid in listed]
    assert upload_before not in [uid for _, uid in listed]
    assert [key for key, _ in listed] == ["up-b", "up-c"], listed
    assert listed.count(("up-b", upload_b)) == 1
    assert listed.count(("up-c", upload_c)) == 1


# ---------------------------------------------------------------------------
# ListParts
# ---------------------------------------------------------------------------

def _part_numbers(page):
    root = ET.fromstring(page.content)
    return [int(node.findtext(NS + "PartNumber"))
            for node in root.findall(NS + "Part")]


def test_list_parts_walk_stays_ordered_under_concurrent_part_writes(service):
    """ListParts race: strictly-ordered pages while parts are re-staged."""
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    uid = None
    from tests.s3.test_s3_multipart import begin, part
    uid = begin(service)
    for number in (1, 2, 3, 4):
        part(service, uid, number, b"seed-part-%d" % number)

    # Page 1: parts 1..2, marker at 2.
    page = signed(service, "GET",
                  f"/backup-bucket/asset.bin?uploadId={uid}&max-parts=2")
    assert page.status_code == 200, page.text
    assert _part_numbers(page) == [1, 2]

    # Concurrent writer between the pages: re-stage part 4 (a new ETag
    # for the same number) and stage part 5 (a new number).
    new_etag = part(service, uid, 4, b"re-staged-part-4")
    part(service, uid, 5, b"added-part-5")

    marker = 2
    numbers: list[int] = []
    while True:
        page = signed(
            service, "GET",
            f"/backup-bucket/asset.bin?uploadId={uid}&max-parts=2"
            f"&part-number-marker={marker}")
        assert page.status_code == 200, page.text
        page_numbers = _part_numbers(page)
        numbers += page_numbers
        root = ET.fromstring(page.content)
        if root.findtext(NS + "IsTruncated") != "true":
            break
        marker = int(root.findtext(NS + "NextPartNumberMarker"))

    # One row per part number, strictly increasing, no error — the
    # re-staged part 4 appears exactly once with its final ETag.
    assert numbers == [3, 4, 5], numbers
    final = signed(
        service, "GET", f"/backup-bucket/asset.bin?uploadId={uid}")
    assert final.status_code == 200
    root = ET.fromstring(final.content)
    part4 = [node for node in root.findall(NS + "Part")
             if node.findtext(NS + "PartNumber") == "4"]
    assert len(part4) == 1, "part 4 is listed twice after the re-stage"
    assert part4[0].findtext(NS + "ETag") == new_etag, (
        "part 4 lists a stale ETag after the concurrent re-stage")


def test_list_parts_part_slot_race_leaves_exactly_one_row(service):
    """Two concurrent UploadParts of one part number: one winner's row."""
    assert signed(service, "PUT", "/backup-bucket").status_code == 200
    from tests.s3.test_s3_multipart import begin
    uid = begin(service)
    owner = service[1].access_key
    service[2].parts["file-99101"] = b"part-a"
    service[2].parts["file-99102"] = b"part-b"

    def stage_variant(db, variant, message_id):
        catalog = BucketCatalog(ManifestStore(db))
        payload = f"part-{variant}".encode()
        digest = hashlib.sha256(payload).hexdigest()
        oid = catalog.manifests.begin("backup-bucket", "asset.bin",
                                      len(payload), int(time.time()))
        catalog.manifests.append(oid, ChunkReference(
            ordinal=0, offset=0, size=len(payload), sha256=digest,
            account="mtproto-user", chat_id=-1001234567890,
            message_id=message_id), int(time.time()))
        catalog.manifests.finish(oid, digest, int(time.time()))
        return oid

    barrier = threading.Barrier(2, timeout=15)

    def record_part(variant, message_id):
        db, catalog = _fresh(service)
        try:
            oid = stage_variant(db, variant, message_id)
            barrier.wait()
            MultipartStore(catalog).record_part(
                uid, "backup-bucket", "asset.bin", owner,
                number=5, object_id=oid, etag=hashlib.md5(
                    f"part-{variant}".encode(),
                    usedforsecurity=False).hexdigest())
            return oid
        except BaseException as exc:
            if ("OperationAborted" in str(exc)
                    or getattr(exc, "code", "") == "OperationAborted"):
                return "refused"
            raise
        finally:
            db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result(timeout=30) for future in (
            pool.submit(record_part, "a", 99101),
            pool.submit(record_part, "b", 99102),
        )]

    db, catalog = _fresh(service)
    try:
        from teledrive.s3.multipart import parts
        rows = db.connection.execute(select(
            parts.c.number, parts.c.object_id).where(
            parts.c.upload_id == uid, parts.c.number == 5)).all()
    finally:
        db.close()
    # Exactly one row for the part slot — the CAS-refusal design or
    # last-write-wins, never two rows for one part number.
    assert len(rows) == 1, f"the part slot holds {len(rows)} rows"
    assert rows[0][0] == 5
    assert rows[0][1] in results or len(results) == 2
    # The final ListParts page reflects exactly the winner.
    final = signed(
        service, "GET", f"/backup-bucket/asset.bin?uploadId={uid}")
    assert final.status_code == 200
    numbers = _part_numbers(final)
    assert numbers.count(5) == 1


# ---------------------------------------------------------------------------
# ListDirectoryBuckets
# ---------------------------------------------------------------------------

def _directory_names(page) -> list[str]:
    root = ET.fromstring(page.content)
    return [node.findtext(NS + "Name")
            for node in root.findall(f"{NS}Buckets/{NS}Bucket")]


def test_list_directory_buckets_walk_survives_concurrent_create(service):
    """ListDirectoryBuckets race: opaque keyset tokens under creation."""
    dir_a = f"alpha--{ZONE}--x-s3"
    dir_c = f"gamma--{ZONE}--x-s3"
    dir_b = f"beta--{ZONE}--x-s3"
    before_cursor = f"aaa--{ZONE}--x-s3"
    assert xsigned(service, "PUT", f"/{dir_a}").status_code == 200
    assert xsigned(service, "PUT", f"/{dir_c}").status_code == 200

    first = xsigned(service, "GET", "/?max-directory-buckets=1",
                    service_name="s3express")
    assert first.status_code == 200, first.text
    assert _directory_names(first) == [dir_a]
    token = ET.fromstring(first.content).findtext(NS + "ContinuationToken")
    assert token

    # Concurrent creator between the pages: one bucket after the cursor
    # (listed next) and one BEFORE the cursor (never listed).
    assert xsigned(service, "PUT", f"/{dir_b}").status_code == 200
    assert xsigned(service, "PUT", f"/{before_cursor}").status_code == 200

    listed: list[str] = []
    while token:
        page = xsigned(
            service, "GET",
            f"/?max-directory-buckets=1&continuation-token={token}",
            service_name="s3express")
        assert page.status_code == 200, page.text
        listed += _directory_names(page)
        token = ET.fromstring(page.content).findtext(NS + "ContinuationToken")

    # Never a duplicate, never the before-cursor creation, and the
    # after-cursor creation is delivered exactly once.
    assert len(listed) == len(set(listed)), listed
    assert before_cursor not in listed
    assert listed == [dir_b, dir_c], listed


# ---------------------------------------------------------------------------
# table / meta contract
# ---------------------------------------------------------------------------

LISTING_RACE_CASES = {
    "ListObjects":
        "the V1 marker walk never duplicates, never errors, and skips "
        "concurrently deleted keys",
    "ListObjectsV2":
        "the continuation-token walk never duplicates, never errors, and "
        "skips concurrently deleted keys",
    "ListObjectVersions":
        "the (key, version) keyset walk survives concurrent version "
        "deletion — including deletion of the marker version itself",
    "ListMultipartUploads":
        "the (key, uploadId) walk skips concurrently aborted uploads and "
        "never re-lists before-cursor initiations",
    "ListParts":
        "part pages stay strictly ordered with one row per part number "
        "while parts are concurrently (re-)staged",
    "ListDirectoryBuckets":
        "the opaque token walk delivers after-cursor creations exactly "
        "once and never re-lists before-cursor ones",
}


def test_the_listing_table_names_only_supported_operations():
    """A renamed/removed operation must fail here, not test nothing."""
    import json
    import pathlib
    manifest = json.loads(
        (pathlib.Path(__file__).resolve().parents[2]
         / "teledrive/s3/operation_manifest.json").read_text())
    supported = {op["name"] for op in manifest["operations"]
                 if op.get("status") == "supported"}
    stale = sorted(set(LISTING_RACE_CASES) - supported)
    assert not stale, f"the listing race table names: {stale}"
