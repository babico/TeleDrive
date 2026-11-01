# Contributing

TeleDrive is a single-container WebUI/REST/S3 service backed by a Telethon
USER session and a shared SQL catalog. This page is the contract for changing
it: how to set up, what must pass, which structural rules are enforced by
tests, and how to write commits, pull requests and documentation.

## 1. Before changing code

- Open a focused issue or describe the intended change in the pull request.
- Preserve the shared storage contract: REST, S3 and durable local-file jobs
  must observe the same catalog, manifest and published generation. Do not
  add a second object catalog or a parallel metadata path.
- Keep Telegram physical deletion, legacy migration and production acceptance
  behind their owner gates. A code change does not authorize them.
- Never commit `.env`, Telethon sessions, API hashes, bot tokens, login codes,
  2FA passwords, SQL URLs, master keys, S3 secrets, original channel data or
  logs containing secrets.

## 2. Local setup

Python 3.11+ is required; CI uses 3.12.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pip install --no-deps -e .
```

`requirements.txt` is the runtime image; `requirements-dev.txt` adds pytest,
xdist, httpx, boto3, Bandit and the other check tools. The editable install
matters: the live workflows install with `pip install -e .` and read
`pyproject.toml`, so a runtime import missing there is a collection error,
not a test failure.

For the container path:

```bash
docker compose config --quiet
docker compose up -d --build
```

One service, two listeners: WebUI/REST on 8080 and S3 on 9000. Ports, bind
address and TLS are environment-only; see
[Configuration reference](../reference/configuration.md).

## 3. Validation contract

Run this before every pull request. A change is not ready because it compiles;
it is ready when each line below passes on the commit you are proposing.

```bash
python -m compileall -q teledrive web tests
bandit -q -r teledrive web -ll
python -m pytest -q -n 4
python scripts/ops/sync_s3_inventory.py --check
python -m pytest tests/meta/test_docs_nav.py -q
docker compose config --quiet
```

- **Full suite, `-n 4`.** `pyproject.toml` sets `--dist loadfile`, so each test
  file stays on one worker. A serial run is fine for debugging; do not claim
  a green suite from a subset.
- **Inventory check.** `sync_s3_inventory.py --check` fails when
  `teledrive/s3/operation_manifest.json`, the inventory script and the
  [S3 matrix](../reference/s3-specs.md) disagree. Never edit one of the three
  by hand alone.
- **Docs nav test.** `tests/meta/test_docs_nav.py` verifies that every page is
  in `mkdocs.yml`, every relative link resolves inside `docs/`, there is one
  H1 and an opening paragraph, and no placeholder survived. The strict MkDocs
  build additionally requires `python -m pip install -r docs/requirements.txt`
  and `python -m mkdocs build --strict`.
- **Fault injection** is required when changing upload durability, SQL state,
  scheduler behaviour, recovery, container wiring or the default config:
  `bash scripts/dev/run_docker_fault_injection.sh`. It must pass all 13 gates
  (`DEV-01`..`DEV-13`) and scoped teardown; see [CI and tests](../reference/ci.md).
- **Live Telegram** tests use the dedicated test channel and repository
  secrets. Never point them at production media.

If a check is expensive or cannot run locally (live MTProto, Docker), say so
in the pull request and name the workflow that will cover it. Do not describe
a skipped check as passing.

## 4. Code conventions

### Layering

`routers → stores → storage` is not decorative. A request handler parses and
authorizes, then calls a typed store or a catalog/engine method.

- **No raw SQL in `web/` except annotated read-only aggregates.** A `text()`
  call is allowed for a cross-table count/sum in an observability endpoint
  (the `/api/v1/metrics` scrape is the model) and must carry a comment saying
  so. Anything that mutates a row belongs in `teledrive/stores/*` or a storage
  module.
- **MySQL portability is mandatory.** No `ON CONFLICT`, `INSERT OR IGNORE`,
  `RETURNING` or dialect-specific upserts. Use UPDATE-then-INSERT or
  SELECT-then-INSERT. Every supported backend is tested; a PostgreSQL-only
  write is a bug even if SQLite lets it pass.
- **Typed stores return plain dicts or small dataclasses**, take the
  `Database` wrapper, commit once at the end of a logical operation, and use
  `LIMIT 1` plus a deterministic `ORDER BY` when a `WHERE` can match several
  rows. The missing `ORDER BY` once let an identifier match the wrong row.
- **`teledrive/storage/schema.py` is the only DDL issuer.** Add an idempotent
  step to `_STEPS`; `SCHEMA_VERSION` is the step count. Never run
  `create_all`/`ALTER` from a store constructor or a startup handler. The
  coordinator owns the cross-process lock.
- **FastAPI 0.142 keeps included routers lazy.** Reason about routes through
  `web.permissions.route_views()`, never by iterating `app.routes`. Use
  `include_router`; do not mutate the router table.
- **One route, one permission.** A new non-public route gets a permission from
  the method+path registry. If it is admin-only, classify it centrally in
  `web/permissions.py`; do not add an ad-hoc role check in the handler.
- **The route surface is frozen.** Update `tests/meta/test_route_surface.py`
  in the same commit as a deliberate route/gate change, and say so in the
  message. A moved route that loses its dependency is an unauthenticated
  route, and the surface test is what catches it.
- **Frontend fragments load before `app.js`**, and a page must load every
  fragment its `init()` calls, not only the ones its markup names.
- **Test names describe behaviour**, not roadmap phases such as P0/P1/P2, and
  every new `tests/**/test_*.py` must be referenced by a real workflow. The
  meta-test fails an unscheduled module.

Structural rules and the meta-tests that enforce them are listed in the
[module map](../reference/module-map.md#5-meta-tests-that-enforce-this-map).

## 5. Commits and pull requests

- Use the existing Conventional Commit-style prefixes: `feat(scope):`,
  `fix(scope):`, `refactor(scope):`, `docs(scope):`, `test(scope):`,
  `chore(scope):`. Keep one logical change per commit when practical.
- Explain **why** in the body, especially for a security or data-loss fix.
  Name the failure the old code could produce.
- Say how it was tested: the commands, the exact suite result, and any check
  that could not run. "Tests pass" without a command is not evidence.
- Keep pull requests focused. A refactor plus a behaviour change plus a
  documentation rewrite in one PR cannot be reviewed for the behaviour.
- Do not merge with a failing required workflow, and do not reuse a green run
  from another SHA. Release tags are per-SHA evidence.
- Do not delete or weaken a test to make a change pass. If a test encodes the
  wrong contract, change it deliberately and explain the old contract in the
  PR.
- Branch cleanup is automated only for PRs that are closed, merged into
  `main` and unprotected; do not force-push shared branches.

## 6. Documentation rules

The manual is the MkDocs Material site under `docs/`, built by
`docs-pages.yml`. The README is a landing page, not the manual.

- Write in **English**. No Turkish glyphs in prose.
- One `#` H1 on the first line, an opening paragraph, then `##` sections. Link
  to a page instead of duplicating its tables.
- **Relative links only inside `docs/`.** A repository file outside the site
  (`CHANGELOG.md`, `LICENSE`, `pyproject.toml`, `scripts/...`) is linked with
  `https://github.com/babico/TeleDrive/blob/main/<path>`.
- Add a new page to `mkdocs.yml` in the same change; the nav test fails
  otherwise. Handoff notes under `docs/project/handoffs/` are excluded from the
  build on purpose.
- Keep one copy of the S3 matrix ([S3 compatibility](../reference/s3-specs.md))
  and one copy of the 13 fault gates ([CI and tests](../reference/ci.md)).
  Link, do not fork.
- Do not write a placeholder marker. If a page is not ready, leave it out of
  the nav rather than shipping an empty shell.
- State uncertainty. "Not verified on this SHA" is better than an inferred
  pass, and a skip is never a pass.

## 7. Security rules

- Report vulnerabilities privately through the [Security policy](../security/policy.md);
  never in a public issue with exploit details or secrets.
- Do not add a configuration credential path, a Basic-auth fallback, or a way
  for an API key to mint authority beyond its own scopes/lifetime. Those
  ceilings exist because each was a demonstrated escalation.
- Do not make an S3 credential, presign or config write reachable by an API
  key. Those surfaces return or create durable secrets and require a human
  session.
- Do not log secrets. New error text passes through `_scrub_text`; the audit
  trail refuses values shaped like TeleDrive secrets.
- Do not enable physical GC, relax an owner gate, or make a safety check
  best-effort to fix a test. `deletion_permitted` stays `False` until the
  owner completes the gates in the [roadmap](roadmap.md#5-owner-gates-physical-gc).
- New dependencies need a reason and a pin consistent with the existing
  ranges. CI runs `pip-audit`; do not silence a finding without documenting
  why it does not apply.
