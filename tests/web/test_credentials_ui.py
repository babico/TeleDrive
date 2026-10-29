"""Structural contract for the S3 credentials console.

These are static-asset assertions on purpose: the page's job is to make a
large, dangerous permission surface navigable, and the failure modes that
matter are structural (a scope nobody can grant, a preset that silently
grants deletion, a secret written to browser storage). The Alpine component
is exercised indirectly — every method it calls must exist in the asset the
page loads.
"""
from __future__ import annotations

import re
from pathlib import Path

from teledrive.s3.credentials import PERMISSIONS

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "web" / "static"
HTML = (STATIC / "credentials.html").read_text(encoding="utf-8")
JS = (STATIC / "credentials.js").read_text(encoding="utf-8")
APP = (STATIC / "app.js").read_text(encoding="utf-8")


def _slice(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


GROUPS_SRC = _slice(JS, "var GROUPS = [", "var ALL = [];")
PRESETS_SRC = _slice(JS, "var PRESETS = [", "var PRESET_BY_ID")
RISK_SRC = _slice(JS, "var GOVERNANCE_RISKS = {", "var DESTRUCTIVE_SUFFIX")

GROUP_IDS = re.findall(r"id: '([a-z0-9-]+)',\s*\n\s*label:", GROUPS_SRC)
GROUP_SCOPES = set(re.findall(r"'(s3:[A-Za-z]+)'", GROUPS_SRC))
PRESET_IDS = re.findall(r"id: '([a-z0-9-]+)',\s*\n\s*label:", PRESETS_SRC)
# Scope literals in a preset's perms array. The bucket-admin predicate is
# removed first: its `p === 's3:...'` operands describe exclusions, not
# grants, and would otherwise be counted as granted scopes.
PRESET_GRANTS_SRC = "\n".join(
    line for line in PRESETS_SRC.splitlines() if "return false" not in line)
PRESET_SCOPES = set(re.findall(r"'(s3:[A-Za-z]+)'", PRESET_GRANTS_SRC))
RISK_SCOPES = set(re.findall(r"'(s3:[A-Za-z]+)':", RISK_SRC))


# ---------------------------------------------------------------------------
# Permission catalogue and grouping
# ---------------------------------------------------------------------------

def test_every_enforceable_scope_is_grouped():
    """A scope the server enforces but the UI cannot show is ungrantable."""
    assert GROUP_SCOPES == set(PERMISSIONS)


def test_catalogue_is_grouped_by_resource_family():
    assert len(GROUP_IDS) >= 20, GROUP_IDS
    assert len(GROUP_IDS) == len(set(GROUP_IDS))


def test_each_group_has_a_human_description_and_scopes():
    blocks = re.split(r"\n    \{\n      id: '", GROUPS_SRC)[1:]
    assert len(blocks) == len(GROUP_IDS)
    for block in blocks:
        label = re.search(r"label: '([^']+)'", block)
        description = re.search(r"description: '([^']+)'", block)
        scopes = re.findall(r"'(s3:[A-Za-z]+)'", block)
        assert label and label.group(1).strip()
        assert description and len(description.group(1)) > 30, label.group(1)
        assert scopes, label.group(1)


def test_group_names_cover_the_known_families():
    names = " ".join(GROUP_IDS)
    for family in ("policy", "object-lock", "website", "notifications",
                   "logging", "replication", "annotations", "metadata-config",
                   "tiering", "reports", "acl", "lifecycle", "cors",
                   "tagging", "versioning", "objects", "encryption"):
        assert family in names, family


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

def test_presets_exist_with_consequences():
    assert PRESET_IDS == ["read-only", "backup", "sync", "bucket-admin", "full"]
    assert PRESETS_SRC.count("consequence:") == len(PRESET_IDS)
    assert PRESETS_SRC.count("perms:") == len(PRESET_IDS)


def test_preset_scopes_are_real_and_non_empty():
    assert PRESET_SCOPES
    assert PRESET_SCOPES <= set(PERMISSIONS)
    assert "s3:ListBucket" in PRESET_SCOPES
    assert "s3:GetObject" in PRESET_SCOPES
    # Full access is the whole catalogue, so the preset must name every scope
    # it can grant through the ALL copy rather than a stale literal list.
    assert "perms: ALL.slice()" in PRESETS_SRC


def test_presets_are_editable_not_modes():
    # Applying a preset replaces the selection; nothing locks the editor.
    assert "s3ApplyPreset(" in JS
    reapplied = _slice(JS, "s3ApplyPreset(id) {", "s3PresetGroups()")
    assert "splice(0, m.length)" in reapplied
    assert "perms.forEach" in reapplied
    assert "s3PresetTouched = false" in reapplied
    assert 'x-for="p in s3Presets()"' in HTML
    assert 'data-testid="s3-preset-applied"' in HTML
    assert "Enabled groups" in HTML


def test_read_only_preset_cannot_write_or_delete():
    read_only = _slice(PRESETS_SRC, "id: 'read-only'", "id: 'backup'")
    scopes = set(re.findall(r"'(s3:[A-Za-z]+)'", read_only))
    assert scopes
    assert not [s for s in scopes if s.startswith("s3:Delete")]
    assert not [s for s in scopes if s.startswith("s3:Put")]
    assert not [s for s in scopes if s.startswith("s3:Create")]
    assert not [s for s in scopes if s.startswith("s3:Update")]


def test_backup_and_sync_presets_differ_on_delete():
    backup = _slice(PRESETS_SRC, "id: 'backup'", "id: 'sync'")
    sync = _slice(PRESETS_SRC, "id: 'sync'", "id: 'bucket-admin'")
    assert "s3:PutObject" in backup and "s3:DeleteObject" not in backup
    assert "s3:PutObject" in sync and "s3:DeleteObject" in sync


def test_bucket_admin_preset_excludes_governance_and_destruction():
    admin = _slice(PRESETS_SRC, "id: 'bucket-admin'", "id: 'full'")
    # Governance scopes are removed by explicit predicate, not by omission
    # from a hand-maintained list, so a new scope cannot slip in silently
    # unless someone edits the predicate.
    for governance in ("s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
                       "s3:PutBucketAcl", "s3:PutObjectAcl",
                       "s3:PutBucketPublicAccessBlock",
                       "s3:PutBucketOwnershipControls",
                       "s3:PutBucketAbac", "s3:PutObjectEncryption"):
        assert "p === '" + governance + "'" in admin, governance
    assert "p.indexOf('s3:PutBucketObjectLock') === 0" in admin
    assert "p.indexOf('s3:PutObjectRetention') === 0" in admin
    assert "p.indexOf('s3:PutObjectLegalHold') === 0" in admin
    assert "p.indexOf('s3:Delete') === 0" in admin
    assert "p.indexOf('s3:UpdateBucketMetadata') === 0" in admin
    # And it is derived from ALL, not a stale literal list.
    assert "ALL.filter(" in admin


# ---------------------------------------------------------------------------
# Risk surfacing
# ---------------------------------------------------------------------------

def test_dangerous_scope_list_exists():
    assert RISK_SCOPES
    for required in ("s3:PutBucketPolicy", "s3:PutBucketObjectLockConfiguration",
                     "s3:PutBucketAcl", "s3:PutObjectEncryption",
                     "s3:UpdateBucketMetadataJournalTableConfiguration",
                     "s3:UpdateBucketMetadataInventoryTableConfiguration",
                     "s3:UpdateBucketMetadataAnnotationTableConfiguration"):
        assert required in RISK_SCOPES, required
    # Every Delete* scope is dangerous by the prefix rule, not by an
    # enumerable list that can drift when a new delete operation lands.
    assert "scope.indexOf('s3:Delete') === 0" in JS
    assert "s3:DeleteObject" not in RISK_SCOPES


def test_risk_entries_state_a_consequence():
    for scope in RISK_SCOPES:
        match = re.search(re.escape(scope) + r"': '([^']{40,})'", RISK_SRC)
        assert match, scope


def test_risk_is_informational_only():
    assert "DANGEROUS" in JS and "riskFor" in JS
    assert "Your request is still allowed" not in JS
    assert "still allowed" in HTML
    assert 'data-testid="s3-risk-selected"' in HTML
    assert "s3GroupRisks(g).length" in HTML
    assert "chip-danger" in HTML and "chip-warn" in HTML


def test_risk_markers_are_not_colour_only():
    # The marker carries a glyph and a screen-reader label in addition to
    # the red/amber class.
    assert "✕" in HTML and "▲" in HTML
    assert "s3RiskFor(p).label" in HTML
    assert "r.label" in HTML


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------

def test_secret_is_never_persisted_client_side():
    for name, text in (("credentials.js", JS), ("credentials.html", HTML)):
        for forbidden in ("localStorage", "sessionStorage", "?token=",
                          "document.cookie", "access_token"):
            assert forbidden not in text, f"{forbidden} in {name}"


def test_app_state_does_not_store_credentials():
    # app.js keeps encryption key ids in local storage; no S3 secret may
    # share that path. The credential component lives in credentials.js.
    for line in APP.splitlines():
        if "localStorage" in line or "sessionStorage" in line:
            assert "s3" not in line.lower(), line
    assert "credentialState()" in APP
    assert "credentialMethods()" in APP
    # The guard matters: only /s3/credentials loads credentials.js, so the
    # spread must not throw on every other page.
    assert "typeof credentialState === 'function'" in APP
    assert "typeof credentialMethods === 'function'" in APP


def test_secret_surfaces_are_reveal_gated():
    assert "s3AskReveal" in JS and "s3ConfirmReveal" in JS
    assert "/secret" in JS
    assert 'data-testid="s3-created-secret"' in HTML
    assert 'data-testid="s3-revealed-secret"' in HTML
    assert "audit-logged" in HTML
    assert "shown once" in HTML.lower()


def test_rotate_and_revoke_state_the_consequence():
    assert "s3ConfirmRotate" in JS and "s3ConfirmRevoke" in JS
    assert "s3AskRotate" in JS and "s3AskRevoke" in JS
    assert 'data-testid="s3-rotate-dialog"' in HTML
    assert 'data-testid="s3-revoke-dialog"' in HTML
    assert "starts failing right away" in HTML
    assert "rejected from the next request onwards" in HTML
    # Rotation has no server endpoint: it must be issue-new-then-revoke-old.
    rotate = _slice(JS, "async s3ConfirmRotate() {", "async s3ConfirmReveal()")
    assert "method: 'POST'" in rotate
    assert "method: 'DELETE'" in rotate


def test_credential_states_are_textual():
    describe = _slice(JS, "function describeCredential(", "function groupLabels(")
    for state in ("revoked", "expired", "expires soon", "active"):
        assert state in describe
    assert "keyExpired(k)" in HTML or "s3Describe(k)" in HTML


def test_expiry_shows_absolute_and_relative():
    assert "fmtTs(k.expires_at)" in HTML
    assert "s3ExpiryRelative(k.expires_at)" in HTML
    assert "expiryState" in JS
    assert "7 * 86400" in JS


# ---------------------------------------------------------------------------
# Usability contract
# ---------------------------------------------------------------------------

def test_summary_chip_counts_selection():
    assert 'data-testid="s3-summary"' in HTML
    assert "s3SelectedCount()" in HTML and "s3Total()" in HTML
    assert "' of '" in HTML
    assert "s3SelectAll" in JS and "s3ClearAll" in JS


def test_live_search_filters_groups_and_scopes():
    visible = _slice(JS, "s3VisibleGroups() {", "s3GroupOpen(id)")
    assert "this.s3Search" in visible
    assert "g.description" in visible
    assert "p.toLowerCase()" in visible
    assert 'type="search"' in HTML
    assert 'placeholder="Search groups and actions' in HTML


def test_group_level_select_and_clear():
    assert "s3SelectGroup" in JS and "s3ClearGroup" in JS
    assert "s3ToggleGroup" in JS
    assert '>All</button>' in HTML and '>None</button>' in HTML


def test_empty_and_loading_states_exist():
    assert 'data-testid="s3-empty"' in HTML
    assert 'data-testid="s3-loading"' in HTML
    assert "No S3 credentials yet" in HTML
    assert "credential is not a user account" in HTML


def test_keyboard_access():
    assert "@keydown.escape.window" in HTML
    assert "s3Escape()" in JS
    assert "focus-visible" in HTML
    assert 'aria-modal="true"' in HTML
    assert "aria-expanded" in HTML
    assert 'role="status"' in HTML
    assert 'class="skip"' in HTML


def test_page_loads_its_assets_in_order():
    assert HTML.index("/static/credentials.js") < HTML.index("/static/app.js")
    assert HTML.rstrip().endswith("</html>")


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------

def test_s3_nav_order_is_credentials_buckets_governance_everywhere():
    pages = sorted(STATIC.glob("*.html"))
    asserting = 0
    for page in pages:
        text = page.read_text(encoding="utf-8")
        if "/s3/credentials" not in text:
            continue
        asserting += 1
        order = [text.index("/s3/credentials"),
                 text.index("/s3/buckets"),
                 text.index("/s3/governance")]
        assert order == sorted(order), page.name
        credentials = text.index("Credentials", order[0])
        assert credentials < text.index("Buckets", order[1]) < text.index("Governance", order[2]), page.name
    assert asserting >= 9, "expected the S3 nav group on every admin page"
