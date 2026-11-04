"""Race-column evidence for the configuration families of the S3 matrix.

Fills the ``race`` cells of ``docs/reference/s3-evidence.md`` for the
bucket/object configuration families (CORS, versioning, replication,
tiering, encryption, lifecycle, ownership, public access block, policy,
tagging, website, storage reports, annotations, ACL and ABAC).

The contract proven here is the honest one for a SQL-backed
single-owner gateway whose configuration state is one row (or one JSON
column) per bucket:

* **put-vs-put** — two concurrent writers replacing the same
  configuration through two independent ``Database`` connections (two
  processes, exactly) converge to exactly one stored value: one
  writer's document, last-write-wins, or a clean CAS refusal
  (``OperationAborted``). Never a merge of both writers' values, never
  duplicate rows, never an unhandled error.
* **delete-vs-put** — one writer deleting while another puts converges
  to *absent* or *exactly the putter's value*. The pre-race value never
  survives both writers, and the state is never simultaneously deleted
  and present.
* **read-under-write** — a reader on a third connection sampling the
  configuration while the writers contend observes only complete
  values: the seed value, one writer's value, or the deleted state.
  Never a torn document, never an error.

Every case forces the interleaving with a ``threading.Barrier`` (both
writers meet before touching the store) and asserts the negatives
above. The stores raced are exactly the ones the gateway handlers
call; where two manifest operations share one wire path (lifecycle
V1/V2 are both ``?lifecycle``), both rows point here because both
endpoints write through the raced store method. The encryption
document race uses the store's own rule validation (the AES256 default
shape parse_encryption_xml accepts when envelope encryption is on).
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Callable

import pytest
from sqlalchemy import func, select

from teledrive.s3.annotations import AnnotationStore
from teledrive.s3.annotations import annotations as annotation_rows
from teledrive.s3.bucket_encryption import (
    BucketEncryptionStore, bucket_encryption,
)
from teledrive.s3.cors import BucketCORSStore, cors_config
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.lifecycle import BucketLifecycleStore, rules_table
from teledrive.s3.policy import (
    BucketAbacStore, BucketPolicyStore, bucket_abac, bucket_policy,
    parse_policy,
)
from teledrive.s3.replication import (
    BucketReplicationStore, replication_configs,
)
from teledrive.s3.report_configs import KINDS, ReportConfigStore, report_configs
from teledrive.s3.tagging import BucketTagStore, ObjectTagStore
from teledrive.s3.tagging import bucket_tags, object_tags
from teledrive.s3.tiering import TieringStore, tiering_configs
from teledrive.s3.website import WebsiteConfigStore, website_configs
from teledrive.storage.catalog import BucketCatalog, heads
from teledrive.storage.catalog_tables import (
    bucket_acl_grants, buckets, object_acl_grants,
)
from teledrive.storage.manifest import ManifestStore
from tests.s3.test_s3_gateway import service, signed

REPL_DESTINATION = "race-repl-destination"


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

@dataclass
class FamilyCase:
    """One configuration family's race surface.

    ``seed`` creates the bucket/object the family attaches to and
    returns a context dict. ``put``/``delete``/``read`` each receive a
    FRESH ``Database`` (the two-process contract). ``expected`` is the
    normalized value ``read`` returns when that variant's write is the
    last one; ``absent`` is what ``read`` returns after ``delete``.
    ``deleted_rows`` is the backing row count in the deleted state
    (column-on-bucket-row families keep their single bucket row).
    """

    operations: tuple[str, ...]
    seed: Callable
    put: Callable
    read: Callable
    expected: Callable
    row_count: Callable
    delete: Callable | None = None
    absent: object = None
    deleted_rows: int = 0
    expected_rows: Callable = staticmethod(
        lambda ctx, value: 1)


def _catalog(db) -> BucketCatalog:
    return BucketCatalog(ManifestStore(db))


def _count(db, table, *where) -> int:
    return int(db.connection.execute(
        select(func.count()).select_from(table).where(*where)).scalar_one())


def _object_id(service, bucket: str, key: str) -> str:
    db = service[3]()
    try:
        catalog = _catalog(db)
        return db.connection.execute(select(heads.c.object_id).where(
            heads.c.bucket == bucket,
            heads.c.key_hash == catalog._keyhash(key))).scalar_one()
    finally:
        db.close()


def _is_clean_refusal(exc: BaseException) -> bool:
    """The designed CAS answer for a losing writer, not a failure."""
    if not isinstance(exc, Exception):
        return False
    return ("OperationAborted" in str(exc)
            or getattr(exc, "code", "") == "OperationAborted")


def _run_workers(service, bodies: list[Callable]):
    """Run each body on its own connection; all meet one barrier first."""
    barrier = threading.Barrier(len(bodies), timeout=30)
    connection = service[3]
    outcomes: list[tuple[str, BaseException | None]] = []
    lock = threading.Lock()

    def worker(body):
        db = connection()
        try:
            barrier.wait()
            body(db)
            outcome = ("ok", None)
        except BaseException as exc:
            outcome = (("refused", exc) if _is_clean_refusal(exc)
                       else ("error", exc))
        finally:
            db.close()
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=worker, args=(body,))
               for body in bodies]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads), (
        "a configuration race worker never finished")
    return outcomes


def _sample_reader(service, family, ctx, stop: threading.Event,
                   samples: list, lock: threading.Lock) -> None:
    """A third connection reading complete values while writers contend."""
    db = service[3]()
    try:
        while not stop.is_set():
            value = family.read(db, ctx)
            db.connection.rollback()  # never pin a stale read snapshot
            with lock:
                samples.append(value)
    except BaseException as exc:  # surfaced by the caller
        with lock:
            samples.append(exc)
    finally:
        db.close()


def _read_quietly(service, family, ctx):
    db = service[3]()
    try:
        return family.read(db, ctx)
    finally:
        db.close()


def _seed_row(service, family, ctx) -> None:
    db = service[3]()
    try:
        family.put(db, ctx, "seed")
    finally:
        db.close()


def _race_with_reader(service, family, ctx, bodies):
    """Writers meet a barrier; a reader samples throughout; both join."""
    stop = threading.Event()
    samples: list = []
    lock = threading.Lock()
    reader = threading.Thread(
        target=_sample_reader,
        args=(service, family, ctx, stop, samples, lock))
    reader.start()
    try:
        outcomes = _run_workers(service, bodies)
    finally:
        stop.set()
        reader.join(timeout=30)
    assert not reader.is_alive(), "the configuration reader never stopped"
    return outcomes, samples


# ---------------------------------------------------------------------------
# shared document builders
# ---------------------------------------------------------------------------

def _seed_bucket(service, name: str) -> dict:
    assert signed(service, "PUT", f"/{name}").status_code == 200
    return {"bucket": name}


def _cors_rules(variant: str) -> list[dict]:
    return [{
        "origins": [f"https://{variant}.example"],
        "methods": ["GET"],
        "allowed_headers": [f"x-amz-{variant}"],
        "expose_headers": [],
        "max_age": 60,
        "id": f"rule-{variant}",
    }]


def _replication_config(variant: str) -> dict:
    return {"role": None, "rules": [{
        "id": f"rule-{variant}", "status": "Enabled",
        "prefixes": [f"{variant}-prefix/"],
        "destination": REPL_DESTINATION,
    }]}


def _tiering_document(variant: str) -> dict:
    days = {"seed": 30, "a": 90, "b": 180}[variant]
    return {
        "id": "tiering-race", "status": "Enabled",
        "filter": {"prefix": f"{variant}/", "tag": None},
        "tiers": [{"access_tier": "ARCHIVE_ACCESS", "days": days}],
        "archive_days": days, "deep_days": days * 2,
    }


def _encryption_rules(variant: str) -> list[dict]:
    if variant == "b":
        return [{"apply_server_side_encryption_by_default": {
            "sse_algorithm": "AES256"}}]
    return []


def _lifecycle_rules(variant: str) -> list[dict]:
    return [{
        "id": f"rule-{variant}", "status": "Enabled",
        "prefix": f"{variant}/", "abort_days": 7, "expiration": None,
        "transitions": [], "noncurrent_transitions": [],
        "noncurrent_expiration": None,
    }]


def _pab_flags(variant: str) -> dict:
    return {
        "seed": {"BlockPublicAcls": True, "IgnorePublicAcls": False,
                 "BlockPublicPolicy": True, "RestrictPublicBuckets": False},
        "a": {"BlockPublicAcls": False, "IgnorePublicAcls": True,
              "BlockPublicPolicy": False, "RestrictPublicBuckets": True},
        "b": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
              "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
    }[variant]


def _report_document(variant: str) -> dict:
    return {
        "id": "report-race",
        "filter": {"prefix": f"{variant}/"},
        "destination": {"bucket": "race-report-dest", "prefix": "reports/",
                        "format": "CSV"},
    }


def _acl_expected(ctx, variant):
    return sorted({(ctx["owner"], "FULL_CONTROL"),
                   (f"grantee-{variant}", "READ")})


def _policy_effect(variant: str) -> str:
    return {"seed": "Allow", "a": "Allow", "b": "Deny"}[variant]


# ---------------------------------------------------------------------------
# late helpers needing the service
# ---------------------------------------------------------------------------

def _seed_object_family(service) -> dict:
    ctx = _seed_bucket(service, "race-object")
    key = "target.bin"
    assert signed(service, "PUT", f"/race-object/{key}",
                  b"race-config-object").status_code == 200
    ctx.update(key=key, object_id=_object_id(service, "race-object", key),
               owner=service[1].access_key)
    return ctx


def _seed_policy_bucket(service) -> dict:
    ctx = _seed_bucket(service, "race-policy")
    db = service[3]()
    try:
        principal = S3CredentialStore(db, service[4]).create(
            "race-policy-principal", ["s3:GetObject"]).access_key
    finally:
        db.close()
    ctx.update(principal=principal, master=service[4])
    return ctx


def _policy_put(db, ctx, variant: str) -> None:
    document = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": _policy_effect(variant),
        "Principal": {"CanonicalUser": [ctx["principal"]]},
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{ctx['bucket']}/*",
    }]}).encode()
    compiled = parse_policy(
        document, bucket=ctx["bucket"],
        credential_store=S3CredentialStore(db, ctx["master"]))
    BucketPolicyStore(_catalog(db)).replace(
        ctx["bucket"], compiled, "race-test")


def _policy_read(db, ctx):
    document = BucketPolicyStore(_catalog(db)).get(ctx["bucket"])
    if document is None:
        return None
    return json.loads(document)["Statement"][0]["Effect"]


def _seed_report_bucket(service) -> dict:
    assert signed(service, "PUT", "/race-report-dest").status_code == 200
    return _seed_bucket(service, "race-report-source")


FAMILIES: dict[str, FamilyCase] = {
    "cors": FamilyCase(
        operations=("GetBucketCors", "PutBucketCors", "DeleteBucketCors"),
        seed=lambda service: _seed_bucket(service, "race-cors"),
        put=lambda db, ctx, v: BucketCORSStore(_catalog(db)).replace(
            ctx["bucket"], _cors_rules(v)),
        read=lambda db, ctx: BucketCORSStore(_catalog(db)).get(ctx["bucket"]),
        expected=lambda ctx, v: _cors_rules(v),
        row_count=lambda db, ctx: _count(
            db, cors_config, cors_config.c.bucket == ctx["bucket"]),
        delete=lambda db, ctx: BucketCORSStore(_catalog(db)).replace(
            ctx["bucket"], []),
    ),
    "versioning": FamilyCase(
        operations=("GetBucketVersioning", "PutBucketVersioning"),
        seed=lambda service: _seed_bucket(service, "race-versioning"),
        put=lambda db, ctx, v: _catalog(db).set_versioning(
            ctx["bucket"], {"seed": "Enabled", "a": "Enabled",
                            "b": "Suspended"}[v]),
        read=lambda db, ctx: _catalog(db).versioning_state(ctx["bucket"]),
        expected=lambda ctx, v: {"seed": "Enabled", "a": "Enabled",
                                 "b": "Suspended"}[v],
        row_count=lambda db, ctx: _count(
            db, buckets, buckets.c.name == ctx["bucket"]),
        delete=None,
    ),
    "replication": FamilyCase(
        operations=("GetBucketReplication", "PutBucketReplication",
                    "DeleteBucketReplication"),
        seed=lambda service: _seed_bucket(service, "race-replication"),
        put=lambda db, ctx, v: BucketReplicationStore(
            _catalog(db), destinations={REPL_DESTINATION}).replace(
                ctx["bucket"], _replication_config(v)),
        read=lambda db, ctx: (BucketReplicationStore(
            _catalog(db), destinations={REPL_DESTINATION}).get(
                ctx["bucket"]) or {}).get("rules"),
        expected=lambda ctx, v: _replication_config(v)["rules"],
        row_count=lambda db, ctx: _count(
            db, replication_configs,
            replication_configs.c.bucket == ctx["bucket"]),
        delete=lambda db, ctx: BucketReplicationStore(
            _catalog(db), destinations={REPL_DESTINATION}).delete(
                ctx["bucket"]),
    ),
    "tiering": FamilyCase(
        operations=("GetBucketIntelligentTieringConfiguration",
                    "PutBucketIntelligentTieringConfiguration",
                    "DeleteBucketIntelligentTieringConfiguration",
                    "ListBucketIntelligentTieringConfigurations"),
        seed=lambda service: _seed_bucket(service, "race-tiering"),
        put=lambda db, ctx, v: TieringStore(_catalog(db)).put(
            ctx["bucket"], "tiering-race", _tiering_document(v)),
        read=lambda db, ctx: next(
            (doc for doc in TieringStore(_catalog(db)).list(ctx["bucket"])
             if doc["id"] == "tiering-race"), None),
        expected=lambda ctx, v: _tiering_document(v),
        row_count=lambda db, ctx: _count(
            db, tiering_configs, tiering_configs.c.bucket == ctx["bucket"],
            tiering_configs.c.config_id == "tiering-race"),
        delete=lambda db, ctx: TieringStore(_catalog(db)).delete(
            ctx["bucket"], "tiering-race"),
    ),
    "encryption": FamilyCase(
        operations=("GetBucketEncryption", "PutBucketEncryption",
                    "DeleteBucketEncryption"),
        seed=lambda service: _seed_bucket(service, "race-encryption"),
        put=lambda db, ctx, v: BucketEncryptionStore(db).replace(
            ctx["bucket"], _encryption_rules(v), actor="race-test"),
        read=lambda db, ctx: BucketEncryptionStore(db).get(ctx["bucket"]),
        expected=lambda ctx, v: _encryption_rules(v),
        row_count=lambda db, ctx: _count(
            db, bucket_encryption,
            bucket_encryption.c.bucket == ctx["bucket"]),
        delete=lambda db, ctx: BucketEncryptionStore(db).delete(
            ctx["bucket"]),
    ),
    "lifecycle": FamilyCase(
        operations=("GetBucketLifecycle", "PutBucketLifecycle",
                    "GetBucketLifecycleConfiguration",
                    "PutBucketLifecycleConfiguration",
                    "DeleteBucketLifecycle"),
        seed=lambda service: _seed_bucket(service, "race-lifecycle"),
        put=lambda db, ctx, v: BucketLifecycleStore(_catalog(db)).replace(
            ctx["bucket"], _lifecycle_rules(v)),
        read=lambda db, ctx: BucketLifecycleStore(_catalog(db)).get(
            ctx["bucket"]),
        expected=lambda ctx, v: _lifecycle_rules(v),
        row_count=lambda db, ctx: _count(
            db, rules_table, rules_table.c.bucket == ctx["bucket"]),
        delete=lambda db, ctx: BucketLifecycleStore(_catalog(db)).replace(
            ctx["bucket"], None),
    ),
    "ownership": FamilyCase(
        operations=("GetBucketOwnershipControls", "PutBucketOwnershipControls",
                    "DeleteBucketOwnershipControls"),
        seed=lambda service: _seed_bucket(service, "race-ownership"),
        put=lambda db, ctx, v: _catalog(db).set_object_ownership(
            ctx["bucket"], {"seed": "ObjectWriter", "a": "ObjectWriter",
                            "b": "BucketOwnerPreferred"}[v]),
        read=lambda db, ctx: _catalog(db).object_ownership(ctx["bucket"]),
        expected=lambda ctx, v: {"seed": "ObjectWriter", "a": "ObjectWriter",
                                 "b": "BucketOwnerPreferred"}[v],
        row_count=lambda db, ctx: _count(
            db, buckets, buckets.c.name == ctx["bucket"]),
        delete=lambda db, ctx: _catalog(db).clear_object_ownership(
            ctx["bucket"]),
        absent="BucketOwnerEnforced",
        deleted_rows=1,
    ),
    "public-access-block": FamilyCase(
        operations=("GetPublicAccessBlock", "PutPublicAccessBlock",
                    "DeletePublicAccessBlock"),
        seed=lambda service: _seed_bucket(service, "race-pab"),
        put=lambda db, ctx, v: _catalog(db).set_public_access_block(
            ctx["bucket"], _pab_flags(v)),
        read=lambda db, ctx: _catalog(db).public_access_block(ctx["bucket"]),
        expected=lambda ctx, v: _pab_flags(v),
        row_count=lambda db, ctx: _count(
            db, buckets, buckets.c.name == ctx["bucket"]),
        delete=lambda db, ctx: _catalog(db).clear_public_access_block(
            ctx["bucket"]),
        absent={field: True for field in BucketCatalog.PAB_FIELDS},
        deleted_rows=1,
    ),
    "policy": FamilyCase(
        operations=("GetBucketPolicy", "DeleteBucketPolicy"),
        seed=_seed_policy_bucket,
        put=_policy_put,
        read=_policy_read,
        expected=lambda ctx, v: _policy_effect(v),
        row_count=lambda db, ctx: _count(
            db, bucket_policy, bucket_policy.c.bucket == ctx["bucket"]),
        delete=lambda db, ctx: BucketPolicyStore(_catalog(db)).delete(
            ctx["bucket"]),
    ),
    "bucket-tagging": FamilyCase(
        operations=("GetBucketTagging", "DeleteBucketTagging"),
        seed=lambda service: _seed_bucket(service, "race-bucket-tags"),
        put=lambda db, ctx, v: BucketTagStore(_catalog(db)).replace(
            ctx["bucket"], [("writer", v)]),
        read=lambda db, ctx: BucketTagStore(_catalog(db)).get(ctx["bucket"]),
        expected=lambda ctx, v: [("writer", v)],
        row_count=lambda db, ctx: _count(
            db, bucket_tags, bucket_tags.c.bucket == ctx["bucket"]),
        delete=lambda db, ctx: BucketTagStore(_catalog(db)).replace(
            ctx["bucket"], []),
        absent=[],
    ),
    "object-tagging": FamilyCase(
        operations=("GetObjectTagging", "DeleteObjectTagging"),
        seed=_seed_object_family,
        put=lambda db, ctx, v: ObjectTagStore(_catalog(db)).replace_published(
            ctx["bucket"], ctx["key"], ctx["object_id"], [("writer", v)]),
        read=lambda db, ctx: ObjectTagStore(_catalog(db)).get(
            ctx["object_id"]),
        expected=lambda ctx, v: [("writer", v)],
        row_count=lambda db, ctx: _count(
            db, object_tags, object_tags.c.object_id == ctx["object_id"]),
        delete=lambda db, ctx: ObjectTagStore(_catalog(db)).replace_published(
            ctx["bucket"], ctx["key"], ctx["object_id"], []),
        absent=[],
    ),
    "website": FamilyCase(
        operations=("GetBucketWebsite", "DeleteBucketWebsite"),
        seed=lambda service: _seed_bucket(service, "race-website"),
        put=lambda db, ctx, v: WebsiteConfigStore(_catalog(db)).replace(
            ctx["bucket"], {"index_document": f"index-{v}.html"}),
        read=lambda db, ctx: WebsiteConfigStore(_catalog(db)).get(
            ctx["bucket"]),
        expected=lambda ctx, v: {"index_document": f"index-{v}.html",
                                 "error_document": None, "enabled": True},
        row_count=lambda db, ctx: _count(
            db, website_configs, website_configs.c.bucket == ctx["bucket"]),
        delete=lambda db, ctx: WebsiteConfigStore(_catalog(db)).delete(
            ctx["bucket"]),
    ),
    "annotations": FamilyCase(
        operations=("GetObjectAnnotation", "PutObjectAnnotation",
                    "DeleteObjectAnnotation", "ListObjectAnnotations"),
        seed=_seed_object_family,
        put=lambda db, ctx, v: AnnotationStore(_catalog(db)).put(
            ctx["object_id"], "race-note", f"writer-{v}"),
        read=lambda db, ctx: (AnnotationStore(_catalog(db)).get(
            ctx["object_id"], "race-note") or {}).get("value"),
        expected=lambda ctx, v: f"writer-{v}",
        row_count=lambda db, ctx: _count(
            db, annotation_rows,
            annotation_rows.c.object_id == ctx["object_id"],
            annotation_rows.c.name == "race-note"),
        delete=lambda db, ctx: AnnotationStore(_catalog(db)).delete(
            ctx["object_id"], "race-note"),
    ),
    "bucket-acl": FamilyCase(
        operations=("GetBucketAcl", "PutBucketAcl"),
        seed=lambda service: {**_seed_bucket(service, "race-bucket-acl"),
                              "owner": service[1].access_key},
        put=lambda db, ctx, v: _catalog(db).set_bucket_acl(
            ctx["bucket"], ctx["owner"], [(f"grantee-{v}", "READ")]),
        read=lambda db, ctx: sorted(
            _catalog(db).bucket_acl(ctx["bucket"])[1]),
        expected=lambda ctx, v: _acl_expected(ctx, v),
        expected_rows=lambda ctx, value: len(value),
        row_count=lambda db, ctx: _count(
            db, bucket_acl_grants,
            bucket_acl_grants.c.bucket == ctx["bucket"]),
        delete=None,
    ),
    "object-acl": FamilyCase(
        operations=("GetObjectAcl", "PutObjectAcl"),
        seed=_seed_object_family,
        put=lambda db, ctx, v: _catalog(db).set_object_acl(
            ctx["bucket"], ctx["key"], ctx["owner"],
            [(f"grantee-{v}", "READ")]),
        read=lambda db, ctx: sorted(
            _catalog(db).object_acl(ctx["bucket"], ctx["key"])[1]),
        expected=lambda ctx, v: _acl_expected(ctx, v),
        expected_rows=lambda ctx, value: len(value),
        row_count=lambda db, ctx: _count(
            db, object_acl_grants,
            object_acl_grants.c.bucket == ctx["bucket"],
            object_acl_grants.c.key_hash == _catalog(db)._keyhash(
                ctx["key"])),
        delete=None,
    ),
    "abac": FamilyCase(
        operations=("GetBucketAbac", "PutBucketAbac"),
        seed=lambda service: _seed_bucket(service, "race-abac"),
        put=lambda db, ctx, v: BucketAbacStore(_catalog(db)).replace(
            ctx["bucket"], {"Status": {"seed": "Enabled", "a": "Enabled",
                                       "b": "Disabled"}[v]}, "race-test"),
        read=lambda db, ctx: (BucketAbacStore(_catalog(db)).get(
            ctx["bucket"]) or {}).get("status"),
        expected=lambda ctx, v: {"seed": "Enabled", "a": "Enabled",
                                 "b": "Disabled"}[v],
        row_count=lambda db, ctx: _count(
            db, bucket_abac, bucket_abac.c.bucket == ctx["bucket"]),
        delete=None,
    ),
}

_REPORT_KIND_OPERATIONS = {
    "analytics": ("GetBucketAnalyticsConfiguration",
                  "DeleteBucketAnalyticsConfiguration",
                  "ListBucketAnalyticsConfigurations"),
    "inventory": ("GetBucketInventoryConfiguration",
                  "DeleteBucketInventoryConfiguration",
                  "ListBucketInventoryConfigurations"),
    "metrics": ("GetBucketMetricsConfiguration",
                "DeleteBucketMetricsConfiguration",
                "ListBucketMetricsConfigurations"),
}
for _kind in KINDS:
    FAMILIES[f"report-{_kind}"] = FamilyCase(
        operations=_REPORT_KIND_OPERATIONS[_kind],
        seed=_seed_report_bucket,
        put=lambda db, ctx, v, kind=_kind: ReportConfigStore(
            _catalog(db)).put(ctx["bucket"], kind, "report-race",
                              _report_document(v)),
        read=lambda db, ctx, kind=_kind: next(
            (doc for doc in ReportConfigStore(_catalog(db)).list(
                ctx["bucket"], kind)
             if doc["id"] == "report-race"), None),
        expected=lambda ctx, v: _report_document(v),
        row_count=lambda db, ctx, kind=_kind: _count(
            db, report_configs, report_configs.c.bucket == ctx["bucket"],
            report_configs.c.kind == kind,
            report_configs.c.config_id == "report-race"),
        delete=lambda db, ctx, kind=_kind: ReportConfigStore(
            _catalog(db)).delete(ctx["bucket"], kind, "report-race"),
    )


# ---------------------------------------------------------------------------
# the race contract
# ---------------------------------------------------------------------------

def _cases():
    return [pytest.param(case, id=name) for name, case in sorted(FAMILIES.items())]


@pytest.mark.parametrize("family", _cases())
def test_two_concurrent_configuration_puts_leave_one_winner(service, family):
    """Put-vs-put plus a concurrent reader: one value, never a merge."""
    ctx = family.seed(service)
    _seed_row(service, family, ctx)
    seed_value = _read_quietly(service, family, ctx)
    assert seed_value == family.expected(ctx, "seed")

    outcomes, samples = _race_with_reader(service, family, ctx, [
        lambda db: family.put(db, ctx, "a"),
        lambda db: family.put(db, ctx, "b"),
    ])

    errors = [exc for outcome, exc in outcomes if outcome == "error"]
    assert not errors, errors
    # At least one writer won; the loser either lost cleanly or never
    # conflicted (last-write-wins). Both writers refused is a finding.
    assert any(outcome == "ok" for outcome, _ in outcomes), outcomes

    allowed = [family.expected(ctx, "a"), family.expected(ctx, "b")]
    db = service[3]()
    try:
        rows = family.row_count(db, ctx)
        stored = family.read(db, ctx)
    finally:
        db.close()
    assert rows == family.expected_rows(ctx, stored), (
        f"two concurrent writers left {rows} rows for {stored!r}")
    assert any(stored == value for value in allowed), (
        f"the stored configuration is neither writer's value: {stored!r}")
    # Negative: the reader never observed a torn document or an error —
    # every sample is one complete value from the legal set.
    legal = allowed + [seed_value]
    torn = [sample for sample in samples
            if isinstance(sample, BaseException)
            or not any(sample == value for value in legal)]
    assert not torn, torn[:3]


@pytest.mark.parametrize("family", _cases())
def test_delete_versus_put_never_leaves_both_states(service, family):
    """Delete-vs-put: absent or exactly the putter's value, never the seed."""
    if family.delete is None:
        pytest.skip("this family has no delete operation")
    ctx = family.seed(service)
    _seed_row(service, family, ctx)
    seed_value = _read_quietly(service, family, ctx)
    assert seed_value == family.expected(ctx, "seed")

    outcomes, samples = _race_with_reader(service, family, ctx, [
        lambda db: family.delete(db, ctx),
        lambda db: family.put(db, ctx, "b"),
    ])

    errors = [exc for outcome, exc in outcomes if outcome == "error"]
    assert not errors, errors

    put_value = family.expected(ctx, "b")
    db = service[3]()
    try:
        rows = family.row_count(db, ctx)
        stored = family.read(db, ctx)
    finally:
        db.close()
    assert (rows == family.deleted_rows and stored == family.absent) or (
        rows == family.expected_rows(ctx, put_value)
        and stored == put_value), (
        f"a concurrent delete+put left {rows} rows holding {stored!r}")
    # Negative: the pre-race value never survives both writers, and the
    # state is never simultaneously deleted and present.
    assert stored != seed_value, (
        "the pre-race configuration survived both a delete and a put")
    if stored == family.absent:
        assert rows == family.deleted_rows, (
            "a deleted configuration still has backing rows")
    # Negative: the reader only ever saw complete legal values.
    legal = [seed_value, put_value, family.absent]
    torn = [sample for sample in samples
            if isinstance(sample, BaseException)
            or not any(sample == value for value in legal)]
    assert not torn, torn[:3]


def test_the_family_table_names_only_supported_operations():
    """A renamed/removed operation must fail here, not test nothing."""
    import pathlib
    manifest = json.loads(
        (pathlib.Path(__file__).resolve().parents[2]
         / "teledrive/s3/operation_manifest.json").read_text())
    supported = {op["name"] for op in manifest["operations"]
                 if op.get("status") == "supported"}
    named = {name for case in FAMILIES.values()
             for name in case.operations}
    stale = sorted(named - supported)
    assert not stale, f"the race table names non-supported operations: {stale}"
    for name, case in FAMILIES.items():
        assert case.operations, f"{name} proves no operation"
        if case.delete is None:
            assert not any(operation.startswith("Delete")
                           for operation in case.operations), name
