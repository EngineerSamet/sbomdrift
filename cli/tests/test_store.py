# SPDX-License-Identifier: Apache-2.0
"""Persistence round-trips.

The store is the feature, not plumbing: if history does not survive a close and
reopen, there is no drift to report.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sbomdrift.models import Component, Evaluation, Finding, Snapshot
from sbomdrift.store import Store, from_iso, to_iso


def _snapshot(artefact: str = "demo-app", **kwargs) -> Snapshot:
    return Snapshot(
        artefact=artefact,
        source="tests",
        ingested_at=datetime(2026, 7, 1, tzinfo=UTC),
        components=[
            Component("pkg:pypi/requests@2.31.0", "requests", "2.31.0"),
            Component("pkg:pypi/urllib3@2.0.7", "urllib3", "2.0.7"),
        ],
        **kwargs,
    )


def test_snapshot_survives_a_close_and_reopen(tmp_path):
    path = tmp_path / "drift.db"
    with Store(path) as store:
        snapshot_id = store.add_snapshot(_snapshot(digest="sha256:abc"))

    with Store(path) as store:
        restored = store.get_snapshot(snapshot_id)

    assert restored is not None
    assert restored.artefact == "demo-app"
    assert restored.digest == "sha256:abc"
    assert len(restored.components) == 2


def test_latest_snapshot_picks_the_most_recent_for_that_artefact(store):
    older = _snapshot()
    newer = _snapshot()
    newer.ingested_at = datetime(2026, 7, 20, tzinfo=UTC)
    other = _snapshot(artefact="something-else")

    store.add_snapshot(older)
    store.add_snapshot(newer)
    store.add_snapshot(other)

    latest = store.latest_snapshot("demo-app")
    assert latest is not None
    assert latest.id == newer.id


def test_evaluation_and_findings_round_trip(store):
    snapshot_id = store.add_snapshot(_snapshot())
    evaluation = Evaluation(
        snapshot_id=snapshot_id,
        evaluated_at=datetime(2026, 7, 24, tzinfo=UTC),
        as_of=datetime(2026, 3, 1, tzinfo=UTC),
        label="march",
        findings=[
            Finding(
                purl="pkg:pypi/requests@2.31.0",
                vuln_id="CVE-2026-0001",
                severity="HIGH",
                published=datetime(2026, 1, 5, tzinfo=UTC),
            )
        ],
    )
    store.add_evaluation(evaluation)

    by_label = store.get_evaluation("march")
    assert by_label is not None
    assert by_label.id == evaluation.id
    assert by_label.as_of == datetime(2026, 3, 1, tzinfo=UTC)
    assert by_label.findings[0].severity == "HIGH"

    assert store.get_evaluation(evaluation.id).label == "march"


def test_labels_are_unique(store):
    snapshot_id = store.add_snapshot(_snapshot())
    base = dict(snapshot_id=snapshot_id, evaluated_at=datetime(2026, 7, 24, tzinfo=UTC))
    store.add_evaluation(Evaluation(label="today", **base))

    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        store.add_evaluation(Evaluation(label="today", **base))


def test_vuln_cache_upserts_and_reads_back(store):
    store.cache_vulns(
        [
            {
                "vuln_id": "CVE-2026-0001",
                "severity": "LOW",
                "summary": "first",
                "published": datetime(2026, 1, 5, tzinfo=UTC),
                "modified": datetime(2026, 1, 6, tzinfo=UTC),
            }
        ]
    )
    store.cache_vulns(
        [
            {
                "vuln_id": "CVE-2026-0001",
                "severity": "CRITICAL",
                "summary": "re-rated",
                "published": datetime(2026, 1, 5, tzinfo=UTC),
                "modified": datetime(2026, 6, 1, tzinfo=UTC),
            }
        ]
    )

    cached = store.cached_vulns(["CVE-2026-0001", "CVE-2026-9999"])
    assert set(cached) == {"CVE-2026-0001"}
    assert cached["CVE-2026-0001"]["severity"] == "CRITICAL"


def test_deleting_a_snapshot_cascades(store):
    snapshot_id = store.add_snapshot(_snapshot())
    store._conn.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))
    store._conn.commit()

    assert store.components(snapshot_id) == []


def test_naive_datetimes_are_stored_as_utc():
    """Mixing naive and aware timestamps would make ordering silently wrong."""
    naive = datetime(2026, 3, 1, 12, 0, 0)
    assert to_iso(naive).endswith("+00:00")
    assert from_iso("2026-03-01T12:00:00Z").tzinfo is not None


def test_unreadable_timestamp_returns_none_rather_than_raising():
    assert from_iso("not-a-date") is None
    assert from_iso(None) is None
