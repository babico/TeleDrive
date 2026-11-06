# CI and tests

How TeleDrive is verified: the workflows, the jobs inside them, the local
commands, and how to read a result without turning a skip into a pass. Test
details for individual features live with those features; this page is the
pipeline contract.

## 1. Workflow matrix

GitHub Actions has no workflow folders, so the `CI n` prefixes in display
names group related checks. Files live in
[`.github/workflows/`](https://github.com/babico/TeleDrive/tree/main/.github/workflows).

| Group | Workflow | Jobs | What it proves |
| --- | --- | --- | --- |
| CI 1 · Quality | [`quality-security.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/quality-security.yml) | `security`, `storage-tests`, `s3-tests`, `web-meta-tests` | Compile, packaged import, security/RBAC/API tests, storage recovery/GC/inventory, S3 protocol and compatibility, web/meta contracts, `pip check`, Bandit, `pip-audit`, Compose parse, S3 inventory sync. |
| CI 2 · Integration | [`integration-storage.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/integration-storage.yml) | `storage-api`, `s3-protocol`, `database` | Real SQL and HTTP with fake Telegram I/O; boto3, AWS CLI and pinned rclone v1.66.0; live PostgreSQL 17 and MySQL 8.4 plus native dump/restore into an isolated database. |
| CI 3 · Resilience | [`resilience-docker.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/resilience-docker.yml) | `image`, `disposable-docker-fault-injection` | Docker image build, single-container WebUI+S3 smoke test, Trivy scan, and the 13-gate fault-injection acceptance. |
| CI 4 · Live E2E | [`live-telegram-user.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/live-telegram-user.yml) | `telegram-roundtrip` | A real authorized USER MTProto session uploads, reads back, checks SHA-256, exercises Range and performs owned-fixture history inventory. |
| CI 4 · Live E2E | [`live-telegram-multiworker.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/live-telegram-multiworker.yml) | `three-process-telegram` | Three independent worker processes share PostgreSQL and a real Telegram test target. |
| CI 5 · Delivery | [`delivery-release.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/delivery-release.yml) | `verify`, `cleanup-merged-branches`, `build`, `publish` | Release regression and security gate, merged-branch hygiene, single-container image package, GitHub Release publication. |
| Docs | [`docs-pages.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/docs-pages.yml) | `build`, `deploy` | `mkdocs build --strict` on pushes and PRs that touch the docs paths; deploys to GitHub Pages only from `main`. |
| CI 6 · Endurance | [`endurance-capacity.yml`](https://github.com/babico/TeleDrive/blob/main/.github/workflows/endurance-capacity.yml) | `isolated-endurance` | Manual 60–110 minute synthetic-media SQLite endurance run. |

**Seven workflows are automatic** on `main`: CI 1–5 (including the two live
E2E workflows) plus Docs. Six of them verify the service; Docs builds the
site. Endurance is `workflow_dispatch` only. Count workflow runs and jobs
separately: a green `database` job does not make a failed CI 2 run green.

## 2. Run checks locally

Python 3.11+ is required by `pyproject.toml`; CI runs 3.12. Docker Engine and
Compose v2 are optional except for the fault-injection suite.

```bash
python -m pip install -r requirements.txt
python -m pip install pytest "pytest-xdist>=3.6,<4" httpx boto3
python -m compileall -q teledrive web tests
python -m pytest -q -n 4          # full suite, file-pinned parallelism
python -m pytest tests/meta -q    # contracts this page and the site depend on
bandit -q -r teledrive web -ll
pip-audit -r requirements.txt
docker compose config --quiet
```

`pyproject.toml` sets `--dist loadfile`, which keeps each test file on one
worker; module-level fixtures and temporary databases depend on that. A
serial run (`python -m pytest -q`) remains available for debugging.

Documentation changes additionally need the site toolchain:

```bash
python -m pip install -r docs/requirements.txt
python -m mkdocs build --strict
```

## 3. Docker fault-injection acceptance

```bash
bash scripts/dev/run_docker_fault_injection.sh
# optional interactive wrapper:
python scripts/ops/acceptance.py
```

The runner creates a randomly named, isolated Compose project with
PostgreSQL 17, **two** TeleDrive Web containers and a scenario container. That
two-container topology exists only to exercise shared state and crashes; the
production layout is one container. Telegram I/O is disk-backed synthetic
media, so no live credentials, original channel or legacy folder are needed.
Reports go to `.docker-fault-evidence/docker-fault-<random>.json` (override
with `TELEDRIVE_FAULT_REPORT_DIR`) with mode `0600`, and teardown is scoped to
that Compose project only — never `docker system prune`.

All thirteen gates plus teardown must pass. The identifiers are evidence
labels, not feature names.

| Gate | Fault or operation | Acceptance requirement |
| --- | --- | --- |
| DEV-01 | Fresh PostgreSQL + two Web instances | Both authenticated health checks work; anonymous access fails. |
| DEV-02 | 0 B, 1 B, 4,097 B, 65,537 B, 5 MiB + 7 B | Durable SQL heads/manifests match the disk-backed chunks. |
| DEV-03 | Remove local source after upload | Full SHA-256 and cross-chunk range readback match. |
| DEV-04 | Lost Telegram ACK / SQL crash | Persisted send intent prevents an unsafe duplicate send. |
| DEV-05 | Aged failed object / GC guard | Unknown ACK stays protected; physical deletion is not enabled. |
| DEV-06 | Synthetic Telegram HTTP 429 | SQL send slot reserved first; cooldown/metrics shared across nodes. |
| DEV-07 | Real `pg_dump` and isolated `pg_restore` | Object IDs, chunk offsets, SHA-256 and range reads survive. |
| DEV-08 | Corrupt SQL archive | Native restore validation rejects the damaged dump. |
| DEV-09 | Corrupt remote bytes | Hash mismatch never publishes partial output; repair permits readback. |
| DEV-10 | Isolated project teardown | Only the random Compose project and its volumes are removed. |
| DEV-11 | Web `SIGKILL` and PostgreSQL restart | Head, send fence, cooldown and remote bytes remain recoverable. |
| DEV-12 | Missing chunk / second-chunk timeout | Existing destination stays intact; repair restores checksums. |
| DEV-13 | Overall acceptance and cleanup | Four stages, all 13 gates, `checks_count == 13`, and successful scoped cleanup. |

A PASS requires the full four-stage evidence (`seed`, `restarted`,
`restored`, `acceptance`), `all_checks_verified == true`, and
`production_acceptance_signed_off == false`. Cleanup failure is a failure.

## 4. Live Telegram E2E and the fail-closed gate

The two live workflows run on every `main` push and on manual dispatch. They
are **not** skipped when unconfigured: the configuration step prints
`::error::` and exits 1, so a missing secret is a red workflow, not a green
one. The user workflow allows its pytest steps only after that probe sets
`enabled=true`; the probe itself is unconditional, and no workflow uses
`continue-on-error`.

Required repository **secrets**: `TELEDRIVE_E2E_SESSION`, `TELEDRIVE_E2E_API_ID`,
`TELEDRIVE_E2E_API_HASH`, and either `TELEDRIVE_E2E_TARGET` (numeric private
channel, masked as a secret before checkout) or `TELEDRIVE_E2E_CHANNEL_NAME`.
The target is never a repository variable: variable values can be printed
unredacted in an environment dump. Concurrency groups differ between the two
workflows (`cancel-in-progress: false` in both) so a pending multiworker run
cannot cancel a user run, and in-flight Telegram writes always get to clean
up.

The multiworker job uses PostgreSQL 17 and `TELEDRIVE_E2E_MULTIWORKER=1`;
the user job optionally runs a 5/16 MiB stress path on manual dispatch or a
`[p1-live-size]` commit marker. Neither substitutes for production
rate-limit behaviour.

## 5. Release gate

`delivery-release.yml` has four jobs, in order:

1. **`verify`** checks out full history, requires a tag to be an ancestor of
   `main` (`git merge-base --is-ancestor`), compiles, runs the offline
   regression/security suite and `pip-audit`.
2. **`cleanup-merged-branches`** runs only on `main` pushes after `verify`,
   with `contents: write` and `pull-requests: read`, and deletes only branches
   whose PR is closed, merged into `main`, and not protected. It uses the
   reviewed script, not `git push --delete`.
3. **`build`** needs `verify` and runs only for a tag or a `main` commit whose
   message contains `[publish-release]`. It builds the single-container image.
4. **`publish`** needs `build`, requires a tag or the same `[publish-release]`
   + `main` condition, and creates the GitHub Release with generated notes
   (`--generate-notes`; there is no `--notes-file`).

A successful `verify` is not a published release. Publication additionally
requires the explicit marker or tag and, for a `main` push, the same-SHA
P0/P1 matrix check. Tags are per-SHA evidence: a green commit elsewhere is
not evidence for the tag.

## 6. What a result means

| Result | Means |
| --- | --- |
| Success | The named checks passed at that exact commit SHA. It says nothing about a later SHA, about production data, or about physical GC. |
| Failure | A step failed at that SHA. Fix and re-run on the new SHA. |
| Cancelled / queued | Not acceptance. Start it again. |
| Skipped test inside a green job | Not evidence that the scenario ran. The live workflows are designed so the common case is failure, not skip; a conditional pytest step elsewhere is rejected by `tests/meta/test_ci_workflows.py`. |
| Green synthetic test | Proves SQL/HTTP/protocol behaviour with fake Telegram I/O. It does not prove live MTProto bytes. |
| Green live E2E | Proves the dedicated test channel, not the owner's original media or production capacity. |

## 7. Regression invariants worth knowing

- **Fault tests use the real config parser.** A container can answer
  `/api/health` while `load_config` fails; the harness runs
  `load_config("/config/config.yaml")` inside each Web container and asserts
  every required upload field is present.
- **S3 operation matrices are table-driven.** Five matrices each carry a
  meta-test that fails when a supported operation is added without an entry:
  unsigned (all supported operations answer 401/403 with no mutation or
  Telegram traffic), malformed XML (4xx, never 5xx), over-limit bodies,
  crash/restart, and retry/multiworker race matrices. A manifest addition fails all
  five until the case exists.
- **The authorization surface is frozen.** `tests/meta/test_route_surface.py`
  asserts the current 163-entry `(method, path, permission, admin_only)` set
  in both directions through `route_views()`.
- **DDL and swallowed-name tests** catch two classes of silent refactor bug:
  DDL outside `schema.py`, and a broad `except` around an unresolvable name.
- **Cross-interface visibility** is covered by
  `tests/web/test_unified_service.py` (REST → S3 → local job share one
  catalog and generation).
- **Docs are tested too.** Every page must be in `mkdocs.yml`, links must
  resolve inside `docs/`, no Turkish glyphs, one H1 and no leftover
  placeholder. `docs-pages.yml` then runs the strict MkDocs build.

For production sign-off, see [Project status](../project/status.md); a green
pipeline is development evidence only.
