# Handoff 11 — Legacy branch retirement audit (2026-11-02)

**State:** COMPLETED (read-only verification after GitHub Actions). **Repository:** `babico/TeleDrive`.

Three diverged branch tips were **not assumed merged**. Their unique commits were preserved through lightweight archive tags **before branch deletion**. The maintenance job checked the exact expected SHA, branch protection and open PRs and verified every new archive ref before deleting anything.

| Former branch | Archived tag | Preserved commit |
| --- | --- | --- |
| `docs/fix-ci-matrix-count-20261023` | `archive/2026-11-02/docs-fix-ci-matrix-count-20261023` | `38b46bf89c1a4f8e5489189af5115920a22ccd0e` |
| `maintenance/2026-10-22-audit-ci-docs` | `archive/2026-11-02/maintenance-2026-10-22-audit-ci-docs` | `fdc066b56ebe3422d62ec8541e10c4ed4c90ef82` |
| `maintenance/2026-10-23-gc-security-doc-audit` | `archive/2026-11-02/maintenance-2026-10-23-gc-security-doc-audit` | `56a7a1adbd0d3a604b7028e5a2058c8b97fc330a` |

**Evidence:** [successful GitHub Actions job](https://github.com/babico/TeleDrive/actions/runs/41473372668). Following it, `GET /repos/babico/TeleDrive/branches` returned only `main`. Each archive tag was independently fetched and its object SHA compared against the archived commit shown above.

**Important:** Archive tags preserve commits but do not mean their changes were merged or are needed in current `main`. Before reusing a historical change, inspect its diff against modern code, cherry-pick only required fixes, and rerun the full test matrix. Never merge an old branch blindly.

The one-shot maintenance workflow was removed after success to avoid leaving an unneeded recurring destructive action. No active feature branch or open PR was modified.
