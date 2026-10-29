"""Error formatting and secret scrubbing shared by every router.

Moved verbatim out of :mod:`web.app` so a router can format a safe error
without importing the application module. ``web.app`` re-exports every name
here during the transition.

``_telegram_error_response`` still logs through ``web.app._log`` (the log
buffer and its file handler are app-owned until a later split step); the
import is deferred for the same reason as in :mod:`web.deps`.
"""
from __future__ import annotations

import re

from fastapi import HTTPException

_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:password|passwd|pwd|token|access_token|secret|api_key|apikey)=)[^&#\s]+"
)


def _scrub_text(value: str) -> str:
    value = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+:)[^@\s]+(@)", r"\1***\2", value)
    return _QUERY_SECRET_RE.sub(r"\1***", value)


def _credential_error(exc: Exception) -> HTTPException:
    """Map a credential-store failure without leaking the master-key path."""
    if isinstance(exc, (RuntimeError, OSError)):
        return HTTPException(
            503, "S3 credentials are unavailable: the master key cannot be "
                 "loaded")
    return HTTPException(422, str(exc))


def _telegram_error_response(exc: Exception, action: str) -> HTTPException:
    """Log the exact Telegram failure reason and map known errors to hints.

    The http middleware only records the status code, so the *why* behind a
    failed request-code/verify-code must be logged here, right before the
    http entry that shows the -> 400 line.
    """
    from web.app import _log
    from telethon import errors as tg_errors
    name = type(exc).__name__
    hints = (
        (tg_errors.SessionPasswordNeededError,
         "Two-factor authentication is required: fill the 2FA password "
         "field and retry"),
        (tg_errors.PhoneCodeExpiredError,
         "The code has expired: request a new code"),
        (tg_errors.PhoneCodeInvalidError,
         "The code is invalid: check the code Telegram sent and retry"),
        (tg_errors.PhoneCodeEmptyError,
         "The code is empty: enter the code Telegram sent"),
        (tg_errors.PhoneNumberUnoccupiedError,
         "No Telegram account exists for this phone number"),
        (tg_errors.PasswordHashInvalidError,
         "The 2FA password is incorrect: check it and retry"),
    )
    message = next((hint for cls, hint in hints if isinstance(exc, cls)), None)
    if message is None:
        message = _scrub_text(str(exc)) or name
    _log(f"{action} FAILED: {name}: {message}", "telegram-session")
    return HTTPException(400, f"{message} [{name}]")
