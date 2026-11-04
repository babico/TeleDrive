"""The s3:BypassGovernanceRetention scope and its request header.

AWS semantics verified against the S3 User Guide ("Locking objects with
Object Lock", Retention modes) and the PutObjectRetention API reference:

* COMPLIANCE: "a protected object version can't be overwritten or
  deleted by any user, including the root user in your AWS account ...
  its retention mode can't be changed, and its retention period can't
  be shortened" — no bypass exists, ever;
* GOVERNANCE: "To override or remove governance-mode retention
  settings, you must have the s3:BypassGovernanceRetention permission
  and must explicitly include x-amz-bypass-governance-retention:true
  as a request header" — the permission AND the header, together;
* the API reference types the header as a Boolean whose only
  bypass-meaning value is ``true`` (botocore serializes an explicit
  False as ``false``): only the exact value ``true`` requests a bypass,
  ``false`` is the explicit negative, and any other value is a
  malformed request rather than a silent no-op.

TeleDrive's wire contract, pinned here end to end through the real S3
gateway:

* PUT ?retention with the signed header ``true`` and a credential that
  holds s3:BypassGovernanceRetention shortens or clears an active
  GOVERNANCE window (200);
* the same header with a credential that lacks the scope is 403
  AccessDenied before any retention state changes — PutObjectRetention
  alone is never enough, exactly like AWS's dedicated permission;
* COMPLIANCE stays immutable for a bypass-holding principal too;
* the header remains 501 on every other route (AWS scopes it to
  retention writes): GET ?retention, ?legal-hold, plain object PUT and
  versioned DELETE all keep refusing it.
"""
from __future__ import annotations

import time

import pytest

from tests.s3.test_s3_gateway import service, signed  # noqa: F401
from teledrive.s3.credentials import DEFAULT_PERMISSIONS, S3CredentialStore

ACL_XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"
BYPASS_HEADER = "x-amz-bypass-governance-retention"


def _iso(seconds_from_now: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() + seconds_from_now))


def _time_of_day(iso: str) -> bytes:
    """The ``THH:MM:`` marker that distinguishes two same-day windows."""
    return ("T" + iso[11:16] + ":").encode()


def _retention_body(mode, until_iso) -> bytes:
    return (f'<Retention xmlns="{ACL_XMLNS}">'
            f"<Mode>{mode}</Mode>"
            f"<RetainUntilDate>{until_iso}</RetainUntilDate>"
            f"</Retention>").encode()


def _put_retention(service, path, mode, until_iso, *, credential=None,
                   extra_headers=None):
    kwargs = {"extra_headers": extra_headers} if extra_headers else {}
    if credential is not None:
        kwargs.update(access=credential.access_key,
                      secret=credential.secret_key)
    return signed(service, "PUT", f"{path}?retention",
                  _retention_body(mode, until_iso), **kwargs)


def _clear_retention(service, path, *, credential=None, extra_headers=None):
    kwargs = {"extra_headers": extra_headers} if extra_headers else {}
    if credential is not None:
        kwargs.update(access=credential.access_key,
                      secret=credential.secret_key)
    return signed(service, "PUT", f"{path}?retention",
                  f'<Retention xmlns="{ACL_XMLNS}"/>'.encode(), **kwargs)


def _retention(service, path):
    return signed(service, "GET", f"{path}?retention")


@pytest.fixture
def lock_bucket(service):
    assert signed(service, "PUT", "/bypass-bucket").status_code == 200
    return "bypass-bucket"


@pytest.fixture
def governed(service, lock_bucket):
    """``(path, window)``: an object under an active GOVERNANCE window.

    The exact ISO timestamp is returned so assertions compare the
    marker of the window that was actually written, never a recomputed
    one."""
    assert signed(service, "PUT", "/bypass-bucket/gov.bin",
                  b"governed").status_code == 200
    path = "/bypass-bucket/gov.bin"
    window = _iso(3600)
    assert _put_retention(service, path, "GOVERNANCE",
                          window).status_code == 200
    return path, window


@pytest.fixture
def bypass_scope(service):
    """A credential holding PutObjectRetention + BypassGovernanceRetention."""
    store = S3CredentialStore(service[3](), service[4])
    return store.create("bypass-scope", [
        "s3:PutObjectRetention", "s3:GetObjectRetention",
        "s3:BypassGovernanceRetention"])


@pytest.fixture
def no_bypass_scope(service):
    """The control principal: PutObjectRetention WITHOUT the bypass scope."""
    store = S3CredentialStore(service[3](), service[4])
    return store.create("retention-only", [
        "s3:PutObjectRetention", "s3:GetObjectRetention"])


# ---------------------------------------------------------------------------
# The bypass itself: GOVERNANCE shortening/clearing with permission + header
# ---------------------------------------------------------------------------

def test_shortening_governance_with_scope_and_header_succeeds(
        service, governed, bypass_scope):
    path, original = governed
    shortened_at = _iso(60)
    reply = _put_retention(service, path, "GOVERNANCE", shortened_at,
                           credential=bypass_scope,
                           extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 200, reply.text
    state = _retention(service, path)
    assert b"<Mode>GOVERNANCE</Mode>" in state.content
    assert _time_of_day(shortened_at) in state.content
    assert _time_of_day(original) not in state.content


def test_clearing_governance_with_scope_and_header_succeeds(
        service, governed, bypass_scope):
    path, _original = governed
    reply = _clear_retention(service, path, credential=bypass_scope,
                             extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 200, reply.text
    assert _retention(service, path).status_code == 404


def test_mode_switch_with_shortened_date_is_a_permitted_bypass(
        service, governed, bypass_scope):
    """GOVERNANCE -> COMPLIANCE with an EARLIER date shortens protection,
    so it is a bypass — allowed with permission + header (the window that
    replaces the old one must still end in the future)."""
    path, _original = governed
    reply = _put_retention(service, path, "COMPLIANCE", _iso(300),
                           credential=bypass_scope,
                           extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 200, reply.text
    state = _retention(service, path)
    assert b"<Mode>COMPLIANCE</Mode>" in state.content


def test_full_default_permission_set_can_bypass(service, governed):
    """The fixture credential mints with DEFAULT_PERMISSIONS — the full,
    admin-equivalent set — so it holds the new scope: the header alone
    performs a real bypass with no extra grant. Narrower presets that
    omit s3:BypassGovernanceRetention deliberately cannot."""
    assert "s3:BypassGovernanceRetention" in DEFAULT_PERMISSIONS
    path, _original = governed
    shortened_at = _iso(120)
    reply = _put_retention(service, path, "GOVERNANCE", shortened_at,
                           extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 200, reply.text
    assert _time_of_day(shortened_at) in _retention(service, path).content


# ---------------------------------------------------------------------------
# The permission gate: header present, scope missing
# ---------------------------------------------------------------------------

def test_header_without_the_scope_is_access_denied(
        service, governed, no_bypass_scope):
    path, original = governed
    reply = _put_retention(service, path, "GOVERNANCE", _iso(60),
                           credential=no_bypass_scope,
                           extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 403, reply.text
    assert b"AccessDenied" in reply.content
    assert b"BypassGovernanceRetention" in reply.content
    # The retention window is untouched.
    assert _time_of_day(original) in _retention(service, path).content


def test_clearing_without_the_scope_is_access_denied(
        service, governed, no_bypass_scope):
    path, _original = governed
    reply = _clear_retention(service, path, credential=no_bypass_scope,
                             extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 403, reply.text
    assert b"AccessDenied" in reply.content
    assert _retention(service, path).status_code == 200


def test_unsigned_bypass_header_is_rejected(service, governed):
    """The header must be covered by the SigV4 signature like every
    other x-amz-* option, or a valid signature could be replayed with a
    header the signer never sent."""
    path, _original = governed
    extension = signed(service, "PUT", f"{path}?retention",
                       _retention_body("GOVERNANCE", _iso(7200)))
    assert extension.status_code == 200, extension.text
    headers = dict(extension.request.headers)
    headers[BYPASS_HEADER] = "true"
    stripped = service[0].put(f"{path}?retention", headers=headers)
    assert stripped.status_code == 403, stripped.text
    assert b"AccessDenied" in stripped.content
    # The unsigned header changed nothing: the extension itself held.
    assert _retention(service, path).status_code == 200


# ---------------------------------------------------------------------------
# Header value grammar and COMPLIANCE immutability
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["True", "TRUE", "yes", "1", ""])
def test_malformed_bypass_header_values_are_rejected(
        service, governed, bypass_scope, value):
    path, _original = governed
    reply = _put_retention(service, path, "GOVERNANCE", _iso(60),
                           credential=bypass_scope,
                           extra_headers={BYPASS_HEADER: value})
    assert reply.status_code == 400, reply.text
    assert b"InvalidArgument" in reply.content
    assert _retention(service, path).status_code == 200


def test_false_is_the_explicit_negative_and_needs_no_scope(
        service, governed, no_bypass_scope):
    """botocore serializes BypassGovernanceRetention=False as ``false``:
    the header is present but requests no bypass, so no scope is
    demanded and the shortening is judged on its own (refused for an
    active GOVERNANCE window)."""
    path, original = governed
    reply = _put_retention(service, path, "GOVERNANCE", _iso(60),
                           credential=no_bypass_scope,
                           extra_headers={BYPASS_HEADER: "false"})
    assert reply.status_code == 403, reply.text
    assert b"governance" in reply.content.lower()
    assert _time_of_day(original) in _retention(service, path).content


def test_compliance_is_immutable_even_for_a_bypass_principal(
        service, lock_bucket, bypass_scope):
    assert signed(service, "PUT", "/bypass-bucket/worm.bin",
                  b"worm").status_code == 200
    path = "/bypass-bucket/worm.bin"
    window = _iso(3600)
    assert _put_retention(service, path, "COMPLIANCE",
                          window).status_code == 200
    shortened = _put_retention(service, path, "COMPLIANCE", _iso(60),
                               credential=bypass_scope,
                               extra_headers={BYPASS_HEADER: "true"})
    assert shortened.status_code == 403, shortened.text
    switched = _put_retention(service, path, "GOVERNANCE", _iso(7200),
                              credential=bypass_scope,
                              extra_headers={BYPASS_HEADER: "true"})
    assert switched.status_code == 403, switched.text
    cleared = _clear_retention(service, path, credential=bypass_scope,
                               extra_headers={BYPASS_HEADER: "true"})
    assert cleared.status_code == 403, cleared.text
    state = _retention(service, path)
    assert b"<Mode>COMPLIANCE</Mode>" in state.content
    assert _time_of_day(window) in state.content


def test_header_present_without_scope_refuses_even_a_non_bypass_write(
        service, governed, no_bypass_scope):
    """Extending never needs a bypass, but the header explicitly claims
    one: the scope is demanded whenever ``true`` is sent, so a
    scope-less principal cannot probe the bypass machinery at all."""
    path, _original = governed
    reply = _put_retention(service, path, "GOVERNANCE", _iso(7200),
                           credential=no_bypass_scope,
                           extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 403, reply.text
    assert b"AccessDenied" in reply.content


# ---------------------------------------------------------------------------
# Route scoping: every other route keeps refusing the header (501)
# ---------------------------------------------------------------------------

def test_header_stays_rejected_on_the_legal_hold_route(
        service, lock_bucket):
    # The fixture credential holds every scope (including legal hold and
    # the bypass), so only the header's route scoping can refuse this.
    assert signed(service, "PUT", "/bypass-bucket/hold.bin",
                  b"hold").status_code == 200
    body = (f'<LegalHold xmlns="{ACL_XMLNS}">'
            f"<Status>ON</Status></LegalHold>").encode()
    reply = signed(service, "PUT", "/bypass-bucket/hold.bin?legal-hold",
                   body, extra_headers={BYPASS_HEADER: "true"})
    assert reply.status_code == 501, reply.text
    assert b"NotImplemented" in reply.content


def test_header_stays_rejected_on_reads_and_object_writes(
        service, governed, lock_bucket):
    path, _original = governed
    read = signed(service, "GET", f"{path}?retention",
                  extra_headers={BYPASS_HEADER: "true"})
    assert read.status_code == 501, read.text
    put = signed(service, "PUT", "/bypass-bucket/plain.bin", b"x",
                 extra_headers={BYPASS_HEADER: "true"})
    assert put.status_code == 501, put.text
    version = signed(service, "GET", path).headers.get("x-amz-version-id")
    delete = signed(service, "DELETE", f"{path}?versionId={version}",
                    extra_headers={BYPASS_HEADER: "true"})
    assert delete.status_code == 501, delete.text
    # Nothing was mutated by any of them.
    assert signed(service, "GET", path).content == b"governed"
    assert _retention(service, path).status_code == 200
