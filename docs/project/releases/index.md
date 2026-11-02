# Releases

Release notes kept with the documentation, plus the canonical sources. The
root [changelog](https://github.com/babico/TeleDrive/blob/main/CHANGELOG.md)
records every change; [GitHub Releases](https://github.com/babico/TeleDrive/releases)
carries the published artifacts and generated notes. A tag is cut only after
the mandatory workflows pass on that exact SHA.

## Documents

| Release | Notes | Theme |
| --- | --- | --- |
| v1.0.9 | [v1.0.9](v1.0.9.md) | The review release: every finding from the full-codebase review closed with its regression test, schema 27, the documentation site. |
| v1.0.8 | [v1.0.8](v1.0.8.md) | S3 metadata parity, removal of HTTP Basic, API-key delegation ceilings, opt-in envelope encryption, serialized schema coordination, and the security review that closed 64 defects before the tag. |
| v1.0.7 | No separate notes page | The previous release line of the single-container service; its contents are in the root changelog and the GitHub release. |

## What belongs here

A page in this folder describes the tree at a tag: what changed, what breaks,
and what the operator must do before upgrading. It is not a promise about
`main`, and it is not updated retroactively when later commits land. The
exact-SHA workflow result must be checked in
[Actions](https://github.com/babico/TeleDrive/actions); a green run elsewhere
is not evidence for a tag.

For the acceptance boundary behind a release, see
[Project status](../status.md). For the upgrade procedure, see
[Upgrade](../../operate/upgrade.md).
