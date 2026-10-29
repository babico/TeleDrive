# 02a — `web/deps.py` + `web/errors.py` (step 2 of the `web/app.py` split)

Base commit: `f09db82`. Move-only. No behaviour change, no route moved, no
test edited.

## What moved

### `web/deps.py` (new, 257 lines)

| Symbol | Why it is here |
|---|---|
| `bearer_auth` | the single `HTTPBearer(auto_error=False)` instance `require_api_scope` closes over; moved so there is still exactly one |
| `_ROLE_ADMIN`, `_ROLE_WRITE`, `_ROLE_READ` | role constants used by `_required_roles` |
| `_required_roles` | outer role gate |
| `_enforce_role_policy` | admin/operator/viewer gate |
| `_permission_registry_cache`, `_route_provider_installed` | registry cache state (module-private; not re-exported, nothing outside read them) |
| `permission_registry` | permission catalog + the `admin:*` route-table provider hook |
| `require_auth` | session **and** API-key branch, including `request.state.api_key_scopes` / `api_key_expires_at` |
| `require_api_scope` | scoped bearer dependency for the data plane |
| `_same_origin` | CSRF header + Origin check (invariant #4) |
| `_delegation_limit`, `_require_within_delegation`, `_require_within_lifetime` | API-key delegation ceiling and lifetime |
| `_require_interactive_session` | interactive-session-only gate (invariant #5) |

### `web/errors.py` (new, 65 lines)

| Symbol | Notes |
|---|---|
| `_QUERY_SECRET_RE` | compiled pattern used by `_scrub_text` |
| `_scrub_text` | URL/query secret scrubbing (invariant #8) |
| `_credential_error` | credential-store error mapping, no path leak |
| `_telegram_error_response` | Telegram error → hint mapping; **does** log, see below |

There are no `@app.exception_handler` functions in `web/app.py`, so there was
no "exception handler that only formats an error" to move.

## Bodies are verbatim, with one deliberate exception

`web/app.py` imports `web.deps` / `web.errors` at the top, so those modules
cannot import `web.app` at module scope (cycle: `web.app` is only half-built).
Functions that need app-owned state therefore import it **inside the
function**:

- `_log` — `require_auth` (deny branch), `_enforce_role_policy`,
  `_require_within_delegation`, `_require_within_lifetime`,
  `_require_interactive_session`, `_telegram_error_response`;
- `db_connect` — `require_auth`, `require_api_scope`;
- `_get_current_user`, `_enforce_user_permission` — `require_auth`;
- the `app` object — `permission_registry` (`app.routes` became
  `_application.app.routes`).

These imports resolve the attribute at call time, which is also why every
existing test that monkeypatches `webapp.db_connect` (or `webapp._log`)
still takes effect. `_log` was deliberately **not** shimmed or duplicated —
there is exactly one log buffer.

An AST comparison of every moved function against `HEAD:web/app.py`
(function source, injected import lines removed) reports all bodies
identical; the only textual change is `app.routes` →
`_application.app.routes` in `permission_registry`.

## `permission_registry()` installation point: unchanged

- The cache is still built lazily on first call, and the provider hook is
  still installed **inside** `permission_registry()` in the same
  `if _permission_registry_cache is None:` branch — invariant #2 intact.
- `app.include_router(...)` is still at the bottom of `web/app.py`, and
  `permission_registry()` is still first reached at request time (or from a
  test), i.e. after every router is included.
- The only change is how the live route table is reached: the body resolves
  `web.app.app` at call time instead of a same-module global. Same object,
  same moment. No import-order fix was invented; nothing was moved to import
  time.
- `tests/web/test_api_key_delegation.py` still calls
  `webapp.permission_registry()` and still gets the provider installed.

## Re-export block in `web/app.py`

Inserted after `from web.permissions import READ_METHODS, is_admin_only`:

```python
from web.deps import (
    _ROLE_ADMIN, _ROLE_READ, _ROLE_WRITE, _delegation_limit,
    _enforce_role_policy, _require_interactive_session,
    _require_within_delegation, _require_within_lifetime, _required_roles,
    _same_origin, bearer_auth, permission_registry, require_api_scope,
    require_auth,
)
from web.errors import (
    _QUERY_SECRET_RE, _credential_error, _scrub_text, _telegram_error_response,
)
```

All deleted definitions are covered by this block, so every internal call site
and every test that reaches `webapp.require_auth`, `webapp._same_origin`,
`webapp.permission_registry`, `webapp._telegram_error_response`, etc. resolves
to the moved object. `web/s3_governance_api.py`'s
`webapp._same_origin(request)` is unaffected.

## What router agents must import from where

| Need | Import from |
|---|---|
| `require_auth`, `require_api_scope`, `_same_origin` | `web.deps` |
| `_require_interactive_session`, `_delegation_limit`, `_require_within_delegation`, `_require_within_lifetime` | `web.deps` |
| `_required_roles`, `_enforce_role_policy`, `_ROLE_*` | `web.deps` |
| `permission_registry` (e.g. `/api/permissions`, data-plane scope checks) | `web.deps` |
| `_telegram_error_response`, `_credential_error`, `_scrub_text` | `web.errors` |
| `db_connect`, `effective_config`, `_log`, `_audit` | still `web.app` until the logging/config step |
| `_get_current_user`, `_enforce_user_permission` | still `web.app` (private; only `require_auth` uses them) |
| `_valid_rest_key` | still `web.app`; take it with the REST data-plane step |

Routers must **not** import `web.app` for anything in the first four rows; that
would re-create the coupling this module exists to remove.

## Deliberately left behind

- `_valid_rest_key` — it encodes REST object-key rules (1..1024 UTF-8 bytes)
  and is called by `_stream_object_response` (REST step) and the signed-share
  handler (public step). It is route/data-plane specific, not auth or error
  infrastructure.
- `_get_current_user`, `_session_token_digest` — session-store resolution that
  `require_auth` imports at call time; they belong with the auth router step
  together with `db_connect`.
- `_enforce_user_permission` — the inner per-route permission gate; only
  `require_auth` calls it. `require_auth` imports it at call time.
- `_log`, `_audit`, `db_connect`, the middleware, `_create_default_admin`,
  startup/shutdown — out of scope by the plan; they need the log buffer/DB.

## Cleanup notes for later steps

- `web/app.py` now has four unused imports left in place to keep the commit
  move-only: `HTTPBearer`, `HTTPAuthorizationCredentials`, `READ_METHODS`,
  `is_admin_only`, and `urlsplit`. They are harmless; drop them in the step
  that removes the temporary re-exports.
- `web/permissions.py`'s module docstring still says the path gate lives in
  `web.app._required_roles`; it now lives in `web.deps._required_roles`.
  Documentation-only drift, not fixed here.

## Line counts

| File | Before | After |
|---|---|---|
| `web/app.py` | 6027 | **5762** |
| `web/deps.py` | — | **257** |
| `web/errors.py` | — | **65** |

(`git diff --stat`: `web/app.py` −275/+10.)

## Evidence

```
python -m compileall -q teledrive web            # clean
bandit -q -r teledrive web -ll                   # exit 0, no findings
pytest tests/web -q -n 4                         # 249 passed
pytest tests/meta/test_route_surface.py -q       # 2 passed (no edits)
pytest tests/s3 tests/web tests/storage tests/meta -q -n 4
                                                 # 1970 passed, 48 skipped,
                                                 # 1 failed (pre-existing)
```

The single failure is
`tests/meta/test_ci_workflows.py::test_every_test_file_is_referenced_by_a_real_ci_workflow`
(`tests/web/test_page_composition.py` is not named in any workflow). It is not
caused by this move: the test reads only `tests/**` and `.github/workflows/**`,
neither of which is touched (`git status` shows only `web/app.py` modified plus
the two new modules), and running that one test in a clean worktree of
`f09db82` fails identically. A later agent must schedule that module or relax
the test; it is outside a move-only commit.
