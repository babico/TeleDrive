# Changelog

The canonical changelog is the root
[`CHANGELOG.md`](https://github.com/babico/TeleDrive/blob/main/CHANGELOG.md),
kept in Keep a Changelog format with an `Unreleased` section. Release
announcements and downloadable artifacts live on
[GitHub Releases](https://github.com/babico/TeleDrive/releases); this page only
points at them and summarises the theme of each release.

## Notable releases

| Version | Date | Theme |
| --- | --- | --- |
| [1.0.10](https://github.com/babico/TeleDrive/releases/tag/v1.0.10) | 2026-11-05 | The fidelity release: directory buckets with session credentials, a physical cold archive with real RestoreObject, AWS-exact null-version/ACL/policy/lock semantics, part reads, the enforced bootstrap rotation, and the complete per-operation evidence program. Schema 30. |
| [1.0.9](https://github.com/babico/TeleDrive/releases/tag/v1.0.9) | 2026-11-02 | The review release: 55 verified defects closed with regression tests, InnoDB deadlock recovery, schema 27 identity constraints, the documentation site, WTFPL. |
| [1.0.8](https://github.com/babico/TeleDrive/releases/tag/v1.0.8) | 2026-10-28 | S3 metadata parity (policies, ACLs, object lock, notifications, replication, website, reports, SSE-C), HTTP Basic removed, API-key delegation ceilings, opt-in envelope encryption, serialized schema coordinator. |
| [1.0.7](https://github.com/babico/TeleDrive/releases/tag/v1.0.7) | — | Previous release line: the single-container WebUI/REST/S3 service, published through the CI-gated release workflow. |

Dates are the changelog dates, not a promise about publication time. The
1.0.9 tag resolves to `69a503ab07b4d372d3dcdba887204228c3e52c4f` and the
1.0.8 tag to `7d2aa773d3839a65899815dd9f3fa2ed2e534324`; verify the
exact-SHA workflows in [Actions](https://github.com/babico/TeleDrive/actions)
rather than inferring them from this table.

## Where entries come from

- An entry is written only after the commits it describes exist. The
  `Unreleased` section is a working record, not a roadmap.
- A version heading is added when the release is prepared; the git tag is cut
  separately, after the mandatory checks pass on that exact SHA.
- Behaviour changes that operators must act on belong in both the changelog
  and [Upgrade](../operate/upgrade.md). A breaking change is never buried in
  a feature bullet.
- Release notes on GitHub are generated from the tag and the changelog; there
  is no second per-version Markdown file maintained in the docs tree.

For the acceptance boundary behind a release, see
[Project status](status.md). For the open work after 1.0.8, see the
[roadmap](roadmap.md).
