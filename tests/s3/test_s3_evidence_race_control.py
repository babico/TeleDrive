"""Race-column evidence for the service and bucket-control plane.

Fills the remaining ``race`` cells of
``docs/reference/s3-evidence.md``: the service lifecycle reads
(HeadBucket, GetBucketLocation), DeleteBucket, CreateSession, the
object-lock family (configuration, retention, legal hold), the one-state
bucket controls (request payment, accelerate), the metadata-configuration
family, the notification/logging reads, and the bucket policy surface
(PutBucketPolicy, GetBucketPolicyStatus).

The contracts pinned here, all forced with a ``threading.Barrier`` and
two independent ``Database`` connections (the two-process contract):

* **read-vs-mutate** — a read concurrent with a create/delete/replace
  sees the complete old state, the complete new state, or the clean
  404/absent state. Never a half-row, never a 5xx, never a response that
  mixes fields from two writers.
* **write-vs-write** — two writers replacing one row/column converge to
  exactly one complete value: last-write-wins, or a designed refusal
  (409 conflict / 403 WORM rule / 501 unsupported state). A tuple field
  pair (mode + window, enabled + role) always comes from ONE writer,
  never a merge.
* **delete-vs-write** — the deleted state and the written state are
  mutually exclusive; a pre-race value never survives both.
* **stateless controls** — RequestPayment and Accelerate have exactly
  one state and store nothing. Concurrent PUTs of the accepted state
  succeed without creating rows, and a concurrent GET always returns
  the one complete document; the rejected state never becomes visible.
* **CreateSession** — concurrent issuance mints distinct credentials,
  each with its own durable row, and every one resolves.
"""
from __future__ import annotations

import concurrent.futures
import json
import threading
import time
from xml.etree import ElementTree as ET

from sqlalchemy import func, select

from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.directory_buckets import S3ExpressSessionStore, s3_sessions
from teledrive.s3.metadata_journal import (
    MetadataConfigurationError, MetadataConfigurationStore, metadata_configs,
)
from teledrive.s3.notifications import (
    NotificationStore, logging_configs, notification_configs,
)
from teledrive.s3.policy import (
    BucketPolicyStore, bucket_policy, parse_policy,
)
from teledrive.storage.catalog import BucketCatalog, buckets
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_directory_buckets import (
    ZONE, create_directory, xsigned,
)
from tests.s3.test_s3_gateway import service, signed

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

def _fresh(service):
    """A new Database + catalog, as a second process would open it."""
    db = service[3]()
    return db, BucketCatalog(ManifestStore(db))


def _run(bodies, *, timeout: float = 120.0):
    barrier = threading.Barrier(len(bodies), timeout=30)
    results: list[tuple[str, object] | None] = [None] * len(bodies)

    def worker(index, body):
        try:
            barrier.wait()
            results[index] = ("ok", body())
        except BaseException as exc:
            results[index] = ("error", exc)

    threads = [threading.Thread(target=worker, args=(index, body))
               for index, body in enumerate(bodies)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=timeout)
    assert not any(thread.is_alive() for thread in threads), (
        "a control-plane race worker never finished")
    return results


def _bucket(service, name: str) -> str:
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return name


def _count(service, table, *where) -> int:
    db = service[3]()
    try:
        statement = select(func.count()).select_from(table)
        if where:
            statement = statement.where(*where)
        return int(db.connection.execute(statement).scalar_one())
    finally:
        db.close()


def _designed(exc: BaseException, *names: str) -> bool:
    text = f"{type(exc).__name__}: {exc}"
    return any(name in text for name in names)


# ---------------------------------------------------------------------------
# service lifecycle: HeadBucket / GetBucketLocation / DeleteBucket
# ---------------------------------------------------------------------------

def test_head_bucket_and_location_race_delete_to_complete_answers(service):
    """HeadBucket/GetBucketLocation: 200 with the full state or clean 404."""
    _bucket(service, "race-head")
    barrier = threading.Barrier(2, timeout=30)

    def reader():
        barrier.wait()
        return (signed(service, "HEAD", "/race-head"),
                signed(service, "GET", "/race-head?location"))

    def deleter():
        barrier.wait()
        db, catalog = _fresh(service)
        try:
            catalog.delete_bucket("race-head")
        finally:
            db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        read_future = pool.submit(reader)
        delete_future = pool.submit(deleter)
        head, location = read_future.result(timeout=60)
        delete_future.result(timeout=60)

    assert head.status_code in (200, 404), head.text
    assert location.status_code in (200, 404), location.text
    if location.status_code == 200:
        root = ET.fromstring(location.content)
        assert root.text is not None
        assert head.status_code == 200, (
            "GetBucketLocation served a bucket HeadBucket already lost")
    assert _count(service, buckets, buckets.c.name == "race-head") == 0


def test_two_concurrent_bucket_deletes_converge_to_absent(service):
    """DeleteBucket-vs-delete: one bucket row, no resurrected sub-state."""
    _bucket(service, "race-delete")
    # Attach state that must never survive the deletion.
    assert signed(service, "PUT", "/race-delete?cors",
                  b"<CORSConfiguration><CORSRule><AllowedOrigin>"
                  b"https://app.example.com</AllowedOrigin>"
                  b"<AllowedMethod>GET</AllowedMethod></CORSRule>"
                  b"</CORSConfiguration>").status_code == 200

    def delete():
        db, catalog = _fresh(service)
        try:
            return catalog.delete_bucket("race-delete")
        finally:
            db.close()

    outcomes = _run([delete, delete])
    successes = 0
    for status, value in outcomes:
        if status == "ok":
            successes += 1
        else:
            assert _designed(value, "Bucket does not exist"), value
    assert successes >= 1
    assert _count(service, buckets, buckets.c.name == "race-delete") == 0
    # Recreating the same name must not inherit the old bucket's CORS row.
    assert signed(service, "PUT", "/race-delete").status_code == 200
    assert signed(service, "GET", "/race-delete?cors").status_code in (
        200, 404)
    db = service[3]()
    try:
        from teledrive.s3.cors import cors_config
        assert db.connection.execute(select(func.count()).select_from(
            cors_config).where(
            cors_config.c.bucket == "race-delete")).scalar_one() == 0, (
            "a deleted bucket's configuration survived the delete race")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# CreateSession
# ---------------------------------------------------------------------------

def test_concurrent_create_sessions_are_distinct_and_resolvable(service):
    """CreateSession-vs-create: one row per credential, all usable."""
    directory = f"race-sessions--{ZONE}--x-s3"
    create_directory(service, directory)

    def issue():
        db = service[3]()
        try:
            return S3ExpressSessionStore(db, service[4]).issue(
                directory, "ReadWrite", service[1].access_key)
        finally:
            db.close()

    outcomes = _run([issue, issue, issue, issue])
    issued = []
    for status, value in outcomes:
        assert status == "ok", value
        issued.append(value)
    assert len({session.access_key for session in issued}) == 4
    assert len({session.session_token for session in issued}) == 4
    assert _count(service, s3_sessions, s3_sessions.c.bucket == directory) == 4
    for session in issued:
        db = service[3]()
        try:
            resolved = S3ExpressSessionStore(db, service[4]).resolve(
                session.access_key, directory, "s3:PutObject", session.session_token)
        finally:
            db.close()
        assert resolved == session.secret_key, (
            "a concurrently issued session did not resolve")


# ---------------------------------------------------------------------------
# object lock: configuration, retention, legal hold
# ---------------------------------------------------------------------------

def test_object_lock_configuration_read_and_two_writers(service):
    """Get/PutObjectLockConfiguration: one complete (mode, days) tuple."""
    _bucket(service, "race-lock-config")
    stop = threading.Event()

    def reader():
        db, catalog = _fresh(service)
        try:
            samples = []
            while not stop.is_set():
                samples.append(catalog.object_lock_config("race-lock-config"))
                db.connection.rollback()
                time.sleep(0.002)
            return samples
        finally:
            db.close()

    def write(mode, days):
        db, catalog = _fresh(service)
        try:
            catalog.set_object_lock_config(
                "race-lock-config", mode=mode, days=days)
        finally:
            db.close()

    results: dict[str, object] = {}

    def hold_reader():
        results["samples"] = reader()

    thread = threading.Thread(target=hold_reader)
    thread.start()
    try:
        outcomes = _run([
            lambda: write("COMPLIANCE", 10),
            lambda: write("GOVERNANCE", 20),
        ])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()

    for status, value in outcomes:
        if status == "error":
            # A serialized second writer may legitimately be refused by
            # the one-way/extend-only rule; that is the designed answer.
            assert _designed(value, "only be extended"), value
    assert any(status == "ok" for status, _ in outcomes), outcomes
    db, catalog = _fresh(service)
    try:
        final = catalog.object_lock_config("race-lock-config")
    finally:
        db.close()
    assert final in ({"default_mode": "COMPLIANCE", "default_days": 10},
                     {"default_mode": "GOVERNANCE", "default_days": 20}), final
    legal = (None,
             {"default_mode": "COMPLIANCE", "default_days": 10},
             {"default_mode": "GOVERNANCE", "default_days": 20})
    torn = [sample for sample in results["samples"] if sample not in legal]
    assert not torn, torn[:3]


def _seed_version(service, bucket, key, payload):
    put = signed(service, "PUT", f"/{bucket}/{key}", payload)
    assert put.status_code == 200, put.text
    return put.headers["x-amz-version-id"]


def test_object_retention_read_and_two_writers(service):
    """Get/PutObjectRetention: the final (mode, until) is one writer's."""
    _bucket(service, "race-retention")
    version = _seed_version(service, "race-retention", "held.bin",
                            b"retention-payload")
    now_ns = time.time_ns()
    pairs = [
        ("GOVERNANCE", now_ns + 100 * 1_000_000_000),
        ("COMPLIANCE", now_ns + 200 * 1_000_000_000),
    ]
    stop = threading.Event()

    def reader():
        db, catalog = _fresh(service)
        try:
            samples = []
            while not stop.is_set():
                state = catalog.object_lock_state(version)
                samples.append((state["mode"], state["retain_until_ns"]))
                db.connection.rollback()
                time.sleep(0.002)
            return samples
        finally:
            db.close()

    def write(mode, until_ns):
        db, catalog = _fresh(service)
        try:
            catalog.set_retention(version, mode=mode, until_ns=until_ns)
        finally:
            db.close()

    results: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: results.update(samples=reader()))
    thread.start()
    try:
        outcomes = _run([lambda: write(*pairs[0]),
                         lambda: write(*pairs[1])])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()

    for status, value in outcomes:
        if status == "error":
            # COMPLIANCE can never be downgraded; a serialized second
            # writer legitimately hits the designed WORM refusal.
            assert _designed(value, "COMPLIANCE", "retention"), value
    assert any(status == "ok" for status, _ in outcomes), outcomes
    db, catalog = _fresh(service)
    try:
        final = catalog.object_lock_state(version)
    finally:
        db.close()
    final_pair = (final["mode"], final["retain_until_ns"])
    assert final_pair in pairs, f"retention merged two writers: {final_pair}"
    legal = [(None, None), *pairs]
    torn = [sample for sample in results["samples"] if sample not in legal]
    assert not torn, torn[:3]


def test_legal_hold_read_and_two_writers(service):
    """Get/PutObjectLegalHold: one boolean, never a torn legal state."""
    _bucket(service, "race-hold")
    version = _seed_version(service, "race-hold", "hold.bin", b"held")
    stop = threading.Event()

    def reader():
        db, catalog = _fresh(service)
        try:
            samples = []
            while not stop.is_set():
                samples.append(catalog.object_lock_state(
                    version)["legal_hold"])
                db.connection.rollback()
                time.sleep(0.002)
            return samples
        finally:
            db.close()

    def write(held):
        db, catalog = _fresh(service)
        try:
            catalog.set_legal_hold(version, held)
        finally:
            db.close()

    results: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: results.update(samples=reader()))
    thread.start()
    try:
        outcomes = _run([lambda: write(True), lambda: write(False)])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()

    assert all(status == "ok" for status, _ in outcomes), outcomes
    db, catalog = _fresh(service)
    try:
        final = catalog.object_lock_state(version)["legal_hold"]
    finally:
        db.close()
    assert final in (True, False)
    assert set(results["samples"]) <= {True, False}


# ---------------------------------------------------------------------------
# one-state bucket controls: RequestPayment / Accelerate
# ---------------------------------------------------------------------------

REQUEST_PAYMENT = (b"<RequestPaymentConfiguration>"
                   b"<Payer>BucketOwner</Payer>"
                   b"</RequestPaymentConfiguration>")
REQUESTER = (b"<RequestPaymentConfiguration>"
             b"<Payer>Requester</Payer>"
             b"</RequestPaymentConfiguration>")
ACCELERATE = (b"<AccelerateConfiguration><Status>Suspended</Status>"
              b"</AccelerateConfiguration>")
ACCELERATE_ENABLED = (b"<AccelerateConfiguration><Status>Enabled</Status>"
                      b"</AccelerateConfiguration>")


def _flag_value(response) -> dict[str, str]:
    return {node.tag.rsplit("}", 1)[-1]: node.text
            for node in ET.fromstring(response.content)}


def test_request_payment_is_one_state_under_concurrent_writes(service):
    """Get/PutBucketRequestPayment: no stored row, no torn state."""
    _bucket(service, "race-payment")

    def put(body):
        return signed(service, "PUT", "/race-payment?requestPayment", body)

    def get():
        return signed(service, "GET", "/race-payment?requestPayment")

    def reader():
        values = []
        for _ in range(20):
            response = get()
            assert response.status_code == 200, response.text
            values.append(_flag_value(response))
        return values

    outcomes = _run([reader,
                     lambda: put(REQUEST_PAYMENT),
                     lambda: put(REQUEST_PAYMENT),
                     lambda: put(REQUESTER)])
    reads = outcomes[0][1]
    assert outcomes[1][1].status_code == 200
    assert outcomes[2][1].status_code == 200
    # The rejected state is a clean 501, never silently stored.
    assert outcomes[3][1].status_code == 501
    assert all(value == {"Payer": "BucketOwner"} for value in reads)
    assert _flag_value(signed(
        service, "GET", "/race-payment?requestPayment")) == {
        "Payer": "BucketOwner"}
    # Nothing is persisted: the bucket row count is unchanged.
    assert _count(service, buckets,
                  buckets.c.name == "race-payment") == 1


def test_accelerate_is_one_state_under_concurrent_writes(service):
    """Get/PutBucketAccelerateConfiguration: no stored row, no torn state."""
    _bucket(service, "race-accelerate")

    def put(body):
        return signed(service, "PUT", "/race-accelerate?accelerate", body)

    def reader():
        values = []
        for _ in range(20):
            response = signed(
                service, "GET", "/race-accelerate?accelerate")
            assert response.status_code == 200, response.text
            values.append(_flag_value(response))
        return values

    outcomes = _run([reader,
                     lambda: put(ACCELERATE),
                     lambda: put(ACCELERATE),
                     lambda: put(ACCELERATE_ENABLED)])
    reads = outcomes[0][1]
    assert outcomes[1][1].status_code == 200
    assert outcomes[2][1].status_code == 200
    assert outcomes[3][1].status_code == 501
    assert all(value == {"Status": "Suspended"} for value in reads)
    assert _flag_value(signed(
        service, "GET", "/race-accelerate?accelerate")) == {
        "Status": "Suspended"}
    assert _count(service, buckets,
                  buckets.c.name == "race-accelerate") == 1


# ---------------------------------------------------------------------------
# metadata configuration
# ---------------------------------------------------------------------------

def _v2_config(*, days=7, inventory=False, annotation=False):
    return {
        "api_version": 2, "retention_days": days,
        "inventory_enabled": inventory, "annotation_enabled": annotation,
        "role": "", "destination_label": "", "table_name": "",
    }


def _v1_config(*, table="race-table"):
    return {
        "api_version": 1, "retention_days": None,
        "inventory_enabled": False, "annotation_enabled": False,
        "role": "", "destination_label":
            "arn:aws:s3tables:us-east-1:123456789012:bucket/race",
        "table_name": table,
    }


def _create_config(service, bucket, config):
    db, catalog = _fresh(service)
    try:
        return MetadataConfigurationStore(catalog).create(bucket, config)
    finally:
        db.close()


def test_concurrent_metadata_configuration_creates_leave_one_row(service):
    """CreateBucketMetadataConfiguration/Table: one row, one clean 409."""
    _bucket(service, "race-metadata")
    for config in (_v2_config(days=3), _v1_config()):
        selector = ("metadataConfiguration" if config["api_version"] == 2
                    else "metadataTable")
        bucket = f"race-metadata-{selector.lower()}"
        _bucket(service, bucket)

        def create(config=config, bucket=bucket):
            return _create_config(service, bucket, config)

        outcomes = _run([create, create])
        errors = [value for status, value in outcomes if status == "error"]
        assert len(errors) == 1, outcomes
        assert _designed(errors[0], "already exists"), errors[0]
        assert _count(service, metadata_configs,
                      metadata_configs.c.bucket == bucket) == 1
        db, catalog = _fresh(service)
        try:
            stored = MetadataConfigurationStore(catalog).get(bucket)
        finally:
            db.close()
        assert stored is not None
        assert stored["api_version"] == config["api_version"]


def test_metadata_configuration_read_races_updates(service):
    """GetBucketMetadataConfiguration: a complete config, never a mix."""
    bucket = _bucket(service, "race-metadata-read")
    _create_config(service, bucket, _v2_config(days=7))
    stop = threading.Event()

    def reader():
        db, catalog = _fresh(service)
        try:
            samples = []
            while not stop.is_set():
                value = MetadataConfigurationStore(catalog).get_with_stats(
                    bucket)
                samples.append(value)
                db.connection.rollback()
                time.sleep(0.002)
            return samples
        finally:
            db.close()

    def update_days(days):
        db, catalog = _fresh(service)
        try:
            MetadataConfigurationStore(catalog).update_journal(bucket, days)
        finally:
            db.close()

    def update_inventory(enabled):
        db, catalog = _fresh(service)
        try:
            MetadataConfigurationStore(catalog).update_inventory(
                bucket, enabled)
        finally:
            db.close()

    results: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: results.update(samples=reader()))
    thread.start()
    try:
        outcomes = _run([
            lambda: update_days(30),
            lambda: update_inventory(True),
        ])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()
    assert all(status == "ok" for status, _ in outcomes), outcomes
    for sample in results["samples"]:
        assert sample is not None
        # Every sampled dict is one coherent committed row: the fixed V2
        # fields never change, and the mutable fields are legal values.
        assert sample["api_version"] == 2
        assert sample["journal_enabled"] is True
        assert sample["retention_days"] in (7, 30)
        assert sample["inventory_enabled"] in (False, True)
        assert set(sample) >= {
            "bucket", "api_version", "journal_enabled", "annotation_enabled",
            "inventory_enabled", "retention_days", "role",
            "destination_label", "table_name", "created_ns", "updated_ns",
            "journal_stats",
        }


def test_metadata_table_configuration_read_races_updates(service):
    """GetBucketMetadataTableConfiguration: complete V1 config or 404."""
    bucket = _bucket(service, "race-metadata-table-read")
    _create_config(service, bucket, _v1_config(table="race-table-one"))
    stop = threading.Event()

    def reader():
        db, catalog = _fresh(service)
        try:
            samples = []
            while not stop.is_set():
                samples.append(MetadataConfigurationStore(catalog).get(bucket))
                db.connection.rollback()
                time.sleep(0.002)
            return samples
        finally:
            db.close()

    def update_days(days):
        db, catalog = _fresh(service)
        try:
            MetadataConfigurationStore(catalog).update_journal(bucket, days)
        finally:
            db.close()

    results: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: results.update(samples=reader()))
    thread.start()
    try:
        outcomes = _run([lambda: update_days(14), lambda: update_days(21)])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()
    assert all(status == "ok" for status, _ in outcomes), outcomes
    legal_days = (None, 14, 21)
    for sample in results["samples"]:
        assert sample is not None
        assert sample["api_version"] == 1
        assert sample["table_name"] == "race-table-one"
        assert sample["retention_days"] in legal_days


def test_metadata_configuration_delete_versus_create(service):
    """DeleteBucketMetadataConfiguration/Table: absent or exactly one row."""
    for selector in ("metadataConfiguration", "metadataTable"):
        bucket = f"race-metadata-delete-{selector.lower()}"
        _bucket(service, bucket)
        config = (_v2_config(days=5) if selector == "metadataConfiguration"
                  else _v1_config(table="race-delete-table"))
        _create_config(service, bucket, config)

        def delete(bucket=bucket):
            db, catalog = _fresh(service)
            try:
                return MetadataConfigurationStore(catalog).delete(bucket)
            finally:
                db.close()

        def create(bucket=bucket, config=config):
            return _create_config(service, bucket, config)

        outcomes = _run([delete, create])
        for status, value in outcomes:
            if status == "error":
                # A create that observes the still-present config answers
                # the designed 409; a delete never errors.
                assert _designed(value, "already exists"), value
        rows = _count(service, metadata_configs,
                      metadata_configs.c.bucket == bucket)
        assert rows in (0, 1), f"the delete race left {rows} rows"
        db, catalog = _fresh(service)
        try:
            stored = MetadataConfigurationStore(catalog).get(bucket)
        finally:
            db.close()
        assert (rows == 0) == (stored is None)


def test_concurrent_metadata_inventory_updates_leave_one_value(service):
    """UpdateBucketMetadataInventoryTableConfiguration: one boolean."""
    bucket = _bucket(service, "race-metadata-inventory")
    _create_config(service, bucket, _v2_config())

    def update(enabled):
        db, catalog = _fresh(service)
        try:
            MetadataConfigurationStore(catalog).update_inventory(
                bucket, enabled)
        finally:
            db.close()

    outcomes = _run([lambda: update(True), lambda: update(False)])
    assert all(status == "ok" for status, _ in outcomes), outcomes
    db, catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(catalog).get(bucket)
    finally:
        db.close()
    assert stored is not None
    assert stored["inventory_enabled"] in (True, False)


def test_concurrent_metadata_annotation_updates_leave_one_pair(service):
    """UpdateBucketMetadataAnnotationTableConfiguration: one (enabled, role)."""
    bucket = _bucket(service, "race-metadata-annotation")
    _create_config(service, bucket,
                   _v2_config(annotation=True))
    pairs = [(True, "arn:aws:iam::123456789012:role/race-a"),
             (False, "arn:aws:iam::123456789012:role/race-b")]

    def update(enabled, role):
        db, catalog = _fresh(service)
        try:
            MetadataConfigurationStore(catalog).update_annotation(
                bucket, enabled, role)
        finally:
            db.close()

    outcomes = _run([lambda: update(*pairs[0]), lambda: update(*pairs[1])])
    assert all(status == "ok" for status, _ in outcomes), outcomes
    db, catalog = _fresh(service)
    try:
        stored = MetadataConfigurationStore(catalog).get(bucket)
    finally:
        db.close()
    assert stored is not None
    final = (stored["annotation_enabled"], stored["role"])
    assert final in pairs, f"annotation update merged two writers: {final}"


# ---------------------------------------------------------------------------
# notification / logging reads
# ---------------------------------------------------------------------------

NOTIFICATION_CONFIGS = [
    {"destination": "https://hooks.example.com/a",
     "events": ["s3:ObjectCreated:*"], "filter_prefix": "a/",
     "filter_suffix": "", "enabled": True},
    {"destination": "https://hooks.example.com/b",
     "events": ["s3:ObjectRemoved:*"], "filter_prefix": "b/",
     "filter_suffix": ".bin", "enabled": True},
]

LOGGING_CONFIGS = [
    {"target_bucket": "log-target-a", "target_prefix": "a/", "enabled": True},
    {"target_bucket": "log-target-b", "target_prefix": "b/", "enabled": True},
]


def _notification_view(value):
    if value is None:
        return None
    return (value["destination"], tuple(value["events"]),
            value["filter_prefix"], value["filter_suffix"], value["enabled"])


def test_get_bucket_notification_reads_one_complete_config(service):
    """GetBucketNotification/Configuration: old, new, or absent — complete."""
    bucket = _bucket(service, "race-notify")

    def store():
        db, catalog = _fresh(service)
        return db, NotificationStore(catalog, master_key=service[4])

    db, notification = store()
    try:
        notification.replace_config(bucket, NOTIFICATION_CONFIGS[0])
    finally:
        db.close()
    stop = threading.Event()

    def reader():
        db, notification = store()
        try:
            samples = []
            while not stop.is_set():
                samples.append(_notification_view(
                    notification.get_config(bucket)))
                db.connection.rollback()
                time.sleep(0.002)
            return samples
        finally:
            db.close()

    def replace(config):
        db, notification = store()
        try:
            notification.replace_config(bucket, config)
        finally:
            db.close()

    results: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: results.update(samples=reader()))
    thread.start()
    try:
        outcomes = _run([
            lambda: replace(NOTIFICATION_CONFIGS[1]),
            lambda: replace(None),
        ])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()
    assert all(status == "ok" for status, _ in outcomes), outcomes
    legal = [None] + [_notification_view(config)
                      for config in NOTIFICATION_CONFIGS]
    torn = [sample for sample in results["samples"] if sample not in legal]
    assert not torn, torn[:3]
    assert _count(service, notification_configs,
                  notification_configs.c.bucket == bucket) <= 1


def test_get_bucket_logging_reads_one_complete_config(service):
    """GetBucketLogging: old, new, or absent — never a mixed row."""
    bucket = _bucket(service, "race-logging")

    def store():
        db, catalog = _fresh(service)
        return db, NotificationStore(catalog, master_key=service[4])

    db, notification = store()
    try:
        notification.replace_logging(bucket, LOGGING_CONFIGS[0])
    finally:
        db.close()
    stop = threading.Event()

    def reader():
        db, notification = store()
        try:
            samples = []
            while not stop.is_set():
                samples.append(notification.get_logging(bucket))
                db.connection.rollback()
                time.sleep(0.002)
            return samples
        finally:
            db.close()

    def replace(config):
        db, notification = store()
        try:
            notification.replace_logging(bucket, config)
        finally:
            db.close()

    results: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: results.update(samples=reader()))
    thread.start()
    try:
        outcomes = _run([
            lambda: replace(LOGGING_CONFIGS[1]),
            lambda: replace(None),
        ])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()
    assert all(status == "ok" for status, _ in outcomes), outcomes
    legal = [None, *LOGGING_CONFIGS]
    torn = [sample for sample in results["samples"] if sample not in legal]
    assert not torn, torn[:3]
    assert _count(service, logging_configs,
                  logging_configs.c.bucket == bucket) <= 1


# ---------------------------------------------------------------------------
# bucket policy: PutBucketPolicy / GetBucketPolicyStatus
# ---------------------------------------------------------------------------

def _policy_document(bucket: str, principal: str, effect: str) -> bytes:
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": effect,
        "Principal": {"CanonicalUser": [principal]},
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{bucket}/*",
    }]}).encode()


def test_two_concurrent_policy_puts_leave_one_complete_document(service):
    """PutBucketPolicy-vs-put: one stored document, never a merge."""
    bucket = _bucket(service, "race-policy-put")
    db = service[3]()
    try:
        principal = S3CredentialStore(db, service[4]).create(
            "race-policy-principal", ["s3:GetObject"]).access_key
    finally:
        db.close()

    def put(effect):
        db, catalog = _fresh(service)
        try:
            document = _policy_document(bucket, principal, effect)
            compiled = parse_policy(
                document, bucket=bucket,
                credential_store=S3CredentialStore(db, service[4]))
            BucketPolicyStore(catalog).replace(bucket, compiled, "race-test")
        finally:
            db.close()

    def read():
        db, catalog = _fresh(service)
        try:
            document = BucketPolicyStore(catalog).get(bucket)
        finally:
            db.close()
        if document is None:
            return None
        return json.loads(document)["Statement"][0]["Effect"]

    stop = threading.Event()

    def sampler():
        samples = []
        while not stop.is_set():
            samples.append(read())
            time.sleep(0.002)
        return samples

    results: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: results.update(samples=sampler()))
    thread.start()
    try:
        outcomes = _run([lambda: put("Allow"), lambda: put("Deny")])
    finally:
        stop.set()
        thread.join(timeout=60)
    assert not thread.is_alive()
    assert all(status == "ok" for status, _ in outcomes), outcomes
    assert _count(service, bucket_policy,
                  bucket_policy.c.bucket == bucket) == 1
    assert read() in ("Allow", "Deny")
    torn = [sample for sample in results["samples"]
            if sample not in (None, "Allow", "Deny")]
    assert not torn, torn[:3]


def test_policy_status_stays_one_complete_answer_under_writes(service):
    """GetBucketPolicyStatus: 200 with complete XML while grants mutate."""
    bucket = _bucket(service, "race-policy-status")
    owner = service[1].access_key

    def mutate(index):
        db, catalog = _fresh(service)
        try:
            catalog.set_public_access_block(bucket, {
                "BlockPublicAcls": index % 2 == 0,
                "IgnorePublicAcls": index % 2 == 1,
                "BlockPublicPolicy": index % 2 == 0,
                "RestrictPublicBuckets": index % 2 == 1,
            })
            catalog.set_bucket_acl(
                bucket, owner, [(f"race-grantee-{index}", "READ")])
            return True
        finally:
            db.close()

    def reader():
        samples = []
        for _ in range(40):
            response = signed(service, "GET", f"/{bucket}?policyStatus")
            assert response.status_code == 200, response.text
            root = ET.fromstring(response.content)
            assert root.tag.rsplit("}", 1)[-1] == "PolicyStatus"
            is_public = root.findtext(NS + "IsPublic")
            assert is_public in ("true", "false")
            samples.append(is_public)
        return samples

    outcomes = _run([reader,
                     lambda: [mutate(index) for index in range(5)],
                     lambda: [mutate(index + 10) for index in range(5)]])
    values = outcomes[0][1]
    assert len(values) == 40
    assert set(values) <= {"true", "false"}
    # Public grantees are unwritable, so the honest answer never flips.
    assert set(values) == {"false"}, set(values)
