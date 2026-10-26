"""Phase J schema must exist before any publish, on every dialect.

publish() applies the pending-tag journal inside its head-move
transaction. If the journal table only appeared when an ObjectTagStore
was constructed, a service that only uploads (no tag writes) would fail
every publish on a fresh database.
"""
from __future__ import annotations

import pytest

from teledrive.db import connect_database
from teledrive.storage.catalog import BucketCatalog
from teledrive.storage.manifest import ManifestStore


@pytest.mark.parametrize("env_name", ["DB_TEST_POSTGRES_URL", "DB_TEST_MYSQL_URL"])
def test_publish_works_without_ever_constructing_a_tag_store(env_name):
    import os
    url = os.environ.get(env_name, "").strip()
    if not url:
        pytest.skip(f"{env_name} not configured")
    from sqlalchemy import inspect
    db = connect_database(url)
    try:
        catalog = BucketCatalog(ManifestStore(db))
        tables = set(inspect(db.engine).get_table_names())
        assert "storage_pending_tags" in tables
    finally:
        db.close()
