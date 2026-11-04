"""Handoff 09, bucket-policy row: the expanded common condition
operators, each proven on its true and false path.

AWS semantics verified against the IAM User Guide ("IAM JSON policy
elements: Condition operators"):

* positive operators OR their policy values; negated operators
  (``StringNotEquals``/``StringNotLike``/``NotIpAddress``) require that
  NO value matches;
* a condition key MISSING from the request context fails a positive
  operator and satisfies a negated one;
* date conditions compare temporally over ISO 8601 values (never
  lexically), and IP conditions use CIDR networks with the /32 (IPv4)
  or /128 (IPv6) default.

TeleDrive's documented stricter subset (rejected at write time, never
accepted-and-ignored): Arn* operators (no ARN context keys exist),
set-operator qualifiers, ``Null``, ``...IfExists`` and epoch-valued
Date conditions (epoch time is covered by ``aws:EpochTime`` with the
Numeric operators instead).
"""
from __future__ import annotations

import json
import logging

import pytest

from tests.s3.test_s3_gateway import service, signed  # noqa: F401
from teledrive.s3.credentials import S3CredentialStore
from teledrive.s3.policy import (
    PolicyError, _compile_stored, evaluate, parse_policy,
)

BUCKET = "operators"


def _store(service):
    return S3CredentialStore(service[3](), service[4])


def _statement(service, *, condition, effect="Allow",
               action="s3:GetObject", resource="/*"):
    return {
        "Effect": effect,
        "Principal": {"CanonicalUser": [service[1].access_key]},
        "Action": action,
        "Resource": f"arn:aws:s3:::{BUCKET}{resource}",
        "Condition": condition,
    }


def _compiled(service, condition):
    document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [_statement(service, condition=condition)],
    }).encode()
    return parse_policy(document, bucket=BUCKET,
                        credential_store=_store(service))


def _decision(service, condition, context):
    """allow / deny / None for one Allow statement under a context."""
    compiled = _compiled(service, condition)
    return evaluate(compiled.statements, "s3:GetObject",
                    f"{BUCKET}/a", service[1].access_key, context)


# ---------------------------------------------------------------------------
# String operators
# ---------------------------------------------------------------------------

def test_string_equals_multivalue_or(service):
    assert _decision(service, {"StringEquals": {"s3:prefix": ["a/", "b/"]}},
                     {"s3:prefix": "b/"}) == "allow"
    assert _decision(service, {"StringEquals": {"s3:prefix": ["a/", "b/"]}},
                     {"s3:prefix": "c/"}) is None


def test_string_not_equals_requires_no_value_to_match(service):
    condition = {"StringNotEquals": {"s3:delimiter": ["/", "|"]}}
    assert _decision(service, condition, {"s3:delimiter": ":"}) == "allow"
    assert _decision(service, condition, {"s3:delimiter": "|"}) is None
    # A missing key satisfies a negated operator (AWS semantics).
    assert _decision(service, condition, {}) == "allow"


def test_string_like_wildcards_and_multivalue(service):
    condition = {"StringLike": {"s3:prefix": ["private/*", "public/?"]}}
    assert _decision(service, condition,
                     {"s3:prefix": "private/x"}) == "allow"
    assert _decision(service, condition,
                     {"s3:prefix": "public/a"}) == "allow"
    assert _decision(service, condition,
                     {"s3:prefix": "public/ab"}) is None
    assert _decision(service, condition,
                     {"s3:prefix": "other/"}) is None


def test_string_not_like_requires_no_value_to_match(service):
    condition = {"StringNotLike": {"s3:prefix": ["private/*"]}}
    assert _decision(service, condition,
                     {"s3:prefix": "public/x"}) == "allow"
    assert _decision(service, condition,
                     {"s3:prefix": "private/x"}) is None
    # Missing key satisfies the negated operator.
    assert _decision(service, condition, {}) == "allow"


# ---------------------------------------------------------------------------
# IP operators
# ---------------------------------------------------------------------------

def test_ip_address_cidr_v4_v6_and_bare_address(service):
    condition = {"IpAddress": {"aws:SourceIp": [
        "203.0.113.0/24", "2001:db8:1234:5678::/64"]}}
    assert _decision(service, condition,
                     {"aws:SourceIp": "203.0.113.7"}) == "allow"
    assert _decision(service, condition,
                     {"aws:SourceIp": "2001:db8:1234:5678::1"}) == "allow"
    assert _decision(service, condition,
                     {"aws:SourceIp": "198.51.100.1"}) is None
    assert _decision(service, condition, {}) is None
    # A bare address gets AWS's /32 default.
    assert _decision(service, {"IpAddress": {"aws:SourceIp": ["198.51.100.9"]}},
                     {"aws:SourceIp": "198.51.100.9"}) == "allow"
    assert _decision(service, {"IpAddress": {"aws:SourceIp": ["198.51.100.9"]}},
                     {"aws:SourceIp": "198.51.100.10"}) is None


def test_not_ip_address_excludes_every_listed_network(service):
    condition = {"NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}}
    assert _decision(service, condition,
                     {"aws:SourceIp": "192.0.2.1"}) == "allow"
    assert _decision(service, condition,
                     {"aws:SourceIp": "10.1.2.3"}) is None
    # Missing key satisfies the negated operator.
    assert _decision(service, condition, {}) == "allow"


# ---------------------------------------------------------------------------
# Bool and Numeric operators
# ---------------------------------------------------------------------------

def test_bool_operator_true_and_false_paths(service):
    # Bool values are validated as true/false at write time; matching
    # against the context is case-insensitive equality, like AWS.
    condition = {"Bool": {"s3:x-amz-acl": ["true"]}}
    assert _decision(service, condition,
                     {"s3:x-amz-acl": "true"}) == "allow"
    assert _decision(service, condition,
                     {"s3:x-amz-acl": "TRUE"}) == "allow"
    assert _decision(service, condition,
                     {"s3:x-amz-acl": "false"}) is None
    # Write-time validation: only true/false are accepted values.
    with pytest.raises(PolicyError, match="[Bb]ool"):
        _compiled(service, {"Bool": {"s3:x-amz-acl": ["maybe"]}})


@pytest.mark.parametrize("operator,limit,actual,expected", [
    ("NumericLessThan", "100", "10", "allow"),
    ("NumericLessThan", "100", "100", None),
    ("NumericLessThanEquals", "100", "100", "allow"),
    ("NumericLessThanEquals", "100", "101", None),
    ("NumericGreaterThan", "100", "101", "allow"),
    ("NumericGreaterThan", "100", "100", None),
    ("NumericGreaterThanEquals", "100", "100", "allow"),
    ("NumericGreaterThanEquals", "100", "99", None),
])
def test_numeric_operator_paths(service, operator, limit, actual, expected):
    assert _decision(service, {operator: {"s3:max-keys": [limit]}},
                     {"s3:max-keys": actual}) == expected


def test_numeric_conditions_require_integers_at_write_time(service):
    with pytest.raises(PolicyError, match="[Nn]umeric"):
        _compiled(service, {"NumericLessThan": {"s3:max-keys": ["ten"]}})


# ---------------------------------------------------------------------------
# Date operators
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("operator,limit,actual,expected", [
    ("DateGreaterThan", "2026-11-04T00:00:00Z",
     "2026-11-04T01:00:00Z", "allow"),
    ("DateGreaterThan", "2026-11-04T00:00:00Z",
     "2025-11-04T00:00:00Z", None),
    ("DateGreaterThanEquals", "2026-11-04T00:00:00Z",
     "2026-11-04T00:00:00Z", "allow"),
    ("DateGreaterThanEquals", "2026-11-04T00:00:00Z",
     "2026-11-03T23:59:59Z", None),
    ("DateLessThan", "2026-11-04T00:00:00Z",
     "2026-11-03T23:59:59Z", "allow"),
    ("DateLessThan", "2026-11-04T00:00:00Z",
     "2026-11-05T00:00:00Z", None),
    ("DateLessThanEquals", "2026-11-04T00:00:00Z",
     "2026-11-04T00:00:00Z", "allow"),
    ("DateLessThanEquals", "2026-11-04T00:00:00Z",
     "2026-11-04T00:00:01Z", None),
])
def test_date_operator_paths(service, operator, limit, actual, expected):
    assert _decision(service, {operator: {"aws:CurrentTime": [limit]}},
                     {"aws:CurrentTime": actual}) == expected


def test_date_comparison_is_temporal_never_lexical(service):
    """+02:00 offset: 01:00 local is 23:00 UTC the PREVIOUS day, so a
    lexical string comparison of the raw values would answer the
    opposite of the temporal truth."""
    condition = {"DateGreaterThan": {"aws:CurrentTime": ["2026-11-04T00:00:00Z"]}}
    assert _decision(service, condition,
                     {"aws:CurrentTime": "2026-11-04T01:00:00+02:00"}) is None
    condition = {"DateLessThan": {"aws:CurrentTime": ["2026-11-04T00:00:00Z"]}}
    assert _decision(service, condition,
                     {"aws:CurrentTime": "2026-11-04T01:00:00+02:00"}) == "allow"


def test_date_conditions_accept_date_only_and_plain_utc(service):
    # Date-only reads as midnight UTC; naive values read as UTC.
    assert _decision(service, {"DateGreaterThan":
                               {"aws:CurrentTime": ["2026-11-04"]}},
                     {"aws:CurrentTime": "2026-11-04T00:00:01Z"}) == "allow"
    assert _decision(service, {"DateLessThan":
                               {"aws:CurrentTime": ["2026-11-04"]}},
                     {"aws:CurrentTime": "2026-11-03T12:00:00"}) == "allow"


def test_date_conditions_require_iso8601_at_write_time(service):
    for bad in ("not-a-date", "1860131200", "2026-13-40T99:00:00Z"):
        with pytest.raises(PolicyError, match="[Dd]ate"):
            _compiled(service, {"DateGreaterThan": {"aws:CurrentTime": [bad]}})


def test_date_condition_with_unparsable_context_fails_closed(service):
    """A context value that is not a timestamp fails the condition
    instead of being skipped or compared lexically."""
    condition = {"DateLessThan": {"aws:CurrentTime": ["2099-01-01T00:00:00Z"]}}
    assert _decision(service, condition,
                     {"aws:CurrentTime": "garbage"}) is None


def test_epoch_time_works_through_the_numeric_operators(service):
    """AWS also allows epoch values in Date conditions; TeleDrive's
    documented stricter subset routes epoch time through aws:EpochTime
    + Numeric operators, proven here."""
    condition = {"NumericGreaterThanEquals": {"aws:EpochTime": ["1762224000"]}}
    assert _decision(service, condition,
                     {"aws:EpochTime": "1762224000"}) == "allow"
    assert _decision(service, condition,
                     {"aws:EpochTime": "1762223999"}) is None


# ---------------------------------------------------------------------------
# Operator/keys outside the subset stay rejected at write time
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("operator", [
    "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike",
    "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
    "NumericEquals", "NumericNotEquals", "DateEquals", "DateNotEquals",
    "BinaryEquals", "Null",
    "ForAllValues:StringEquals", "ForAnyValue:StringLike",
    "StringLikeIfExists",
])
def test_operators_outside_the_subset_are_rejected_not_ignored(service, operator):
    with pytest.raises(PolicyError, match="[Uu]nsupported condition operator"):
        _compiled(service, {operator: {"s3:prefix": ["x"]}})


def test_unknown_condition_keys_are_rejected(service):
    with pytest.raises(PolicyError, match="[U]nsupported condition key"):
        _compiled(service, {"StringEquals": {"aws:Username": ["x"]}})


# ---------------------------------------------------------------------------
# Deny precedence over conditions and statements
# ---------------------------------------------------------------------------

def test_deny_beats_allow_across_statements_and_conditions(service):
    document = json.dumps({"Version": "2012-10-17", "Statement": [
        _statement(service, condition={
            "IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]}}),
        _statement(service, effect="Deny", condition={
            "StringEquals": {"s3:prefix": ["secret/"]}}),
    ]}).encode()
    compiled = parse_policy(document, bucket=BUCKET,
                            credential_store=_store(service))
    # Both statements match: the Deny wins regardless of order.
    context = {"aws:SourceIp": "203.0.113.1", "s3:prefix": "secret/"}
    assert evaluate(compiled.statements, "s3:GetObject",
                    f"{BUCKET}/a", service[1].access_key, context) == "deny"
    # Only the Allow matches.
    context = {"aws:SourceIp": "203.0.113.1", "s3:prefix": "public/"}
    assert evaluate(compiled.statements, "s3:GetObject",
                    f"{BUCKET}/a", service[1].access_key, context) == "allow"
    # Only the Deny matches.
    context = {"aws:SourceIp": "198.51.100.1", "s3:prefix": "secret/"}
    assert evaluate(compiled.statements, "s3:GetObject",
                    f"{BUCKET}/a", service[1].access_key, context) == "deny"


# ---------------------------------------------------------------------------
# Auditable compile: stored documents fail closed with a logged reason
# ---------------------------------------------------------------------------

def test_corrupt_stored_policy_raises_and_logs_a_reason(service, caplog):
    with caplog.at_level(logging.WARNING, logger="teledrive.s3.policy"):
        with pytest.raises(PolicyError):
            _compile_stored(BUCKET, '{"Version": "2012-10-17"', 123)
    assert any(BUCKET in record.message
               and "corrupt" in record.message.lower()
               for record in caplog.records)


def test_no_longer_valid_stored_policy_raises_and_logs_a_reason(
        service, caplog):
    """A document that parses but no longer compiles (for example a
    schema change or a manual SQL edit) is re-raised, never degraded
    into an allow."""
    document = json.dumps({"Version": "2012-10-17", "Statement": [
        _statement(service, condition={
            "StringEquals": {"s3:prefix": ["x"]}})]})
    broken = json.dumps({"Version": "2012-10-17", "Statement": [
        _statement(service, condition={
            "ArnLike": {"s3:prefix": ["x"]}})]})
    # Sanity: the valid document compiles.
    assert _compile_stored(BUCKET, document, 1).statements
    with caplog.at_level(logging.WARNING, logger="teledrive.s3.policy"):
        with pytest.raises(PolicyError):
            _compile_stored(BUCKET, broken, 456)
    assert any(BUCKET in record.message
               and "failed to compile" in record.message.lower()
               for record in caplog.records)


def test_gateway_fails_closed_when_the_stored_policy_is_corrupt(service):
    """End to end: a corrupt stored row denies requests with an
    AWS-shaped error — never a fallback to the no-policy baseline."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/obj.bin", b"x").status_code == 200
    stored = _put_policy(service, [{
        "Effect": "Allow",
        "Principal": {"CanonicalUser": [service[1].access_key]},
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET}/*"}])
    assert stored.status_code == 204, stored.text
    connection = service[3]()
    try:
        from sqlalchemy import text
        connection.connection.execute(text(
            "UPDATE storage_bucket_policy SET document = "
            "'{\"Version\": \"2012-10-17\"', updated_ns = updated_ns + 1 "
            "WHERE bucket = :b"),
            {"b": BUCKET})
        connection.commit()
    finally:
        connection.close()
    refused = signed(service, "GET", f"/{BUCKET}/obj.bin")
    assert refused.status_code == 400
    assert b"MalformedPolicy" in refused.content


# ---------------------------------------------------------------------------
# Time semantics over the real gateway context
# ---------------------------------------------------------------------------

def _put_policy(service, statements):
    return signed(service, "PUT", f"/{BUCKET}?policy",
                  json.dumps({"Version": "2012-10-17",
                              "Statement": statements}).encode())


def test_request_time_context_is_populated_for_date_conditions(service):
    """aws:CurrentTime/aws:EpochTime must exist in the real request
    context (the IAM guide: the keys are always present). If the key
    were missing, a positive Date condition would silently never match:
    a Deny meant to fire "before 2999" would let everything through."""
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    assert signed(service, "PUT", f"/{BUCKET}/timed.bin", b"x").status_code == 200
    principal = {"CanonicalUser": [service[1].access_key]}

    # DateLessThan 2999 matches the real current time -> the Deny fires.
    fires = _put_policy(service, [{
        "Effect": "Deny", "Principal": principal, "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET}/*",
        "Condition": {"DateLessThan": {"aws:CurrentTime": [
            "2999-01-01T00:00:00Z"]}},
    }])
    assert fires.status_code == 204, fires.text
    denied = signed(service, "GET", f"/{BUCKET}/timed.bin")
    assert denied.status_code == 403, denied.text

    # DateLessThan 2000 cannot match now: the same Deny stops firing,
    # which also proves the compiled-policy cache invalidates on
    # replace within this process.
    expired = _put_policy(service, [{
        "Effect": "Deny", "Principal": principal, "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET}/*",
        "Condition": {"DateLessThan": {"aws:CurrentTime": [
            "2000-01-01T00:00:00Z"]}},
    }])
    assert expired.status_code == 204, expired.text
    allowed = signed(service, "GET", f"/{BUCKET}/timed.bin")
    assert allowed.status_code == 200, allowed.text

    # The epoch context key carries the same instant in seconds.
    epoch = _put_policy(service, [{
        "Effect": "Deny", "Principal": principal, "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET}/*",
        "Condition": {"NumericGreaterThanEquals": {"aws:EpochTime": ["1"]}},
    }])
    assert epoch.status_code == 204, epoch.text
    denied = signed(service, "GET", f"/{BUCKET}/timed.bin")
    assert denied.status_code == 403, denied.text


def test_public_principal_stays_gated(service):
    assert signed(service, "PUT", f"/{BUCKET}").status_code == 200
    reply = _put_policy(service, [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET}/*"}])
    assert reply.status_code == 501
    assert b"NotImplemented" in reply.content
