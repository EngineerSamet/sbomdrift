# SPDX-License-Identifier: Apache-2.0
"""Evaluation, and the ``--as-of`` time machine.

These tests are the reason ``--as-of`` exists. Without it, "did drift work?"
could only be answered by waiting for the world to publish a new advisory. With
it, the answer is an exact assertion.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sbomdrift.evaluate import evaluate_snapshot
from sbomdrift.osv import OSVClient

MARCH = datetime(2026, 3, 1, tzinfo=UTC)
JUNE = datetime(2026, 6, 1, tzinfo=UTC)


def test_evaluation_without_a_cutoff_sees_everything(store, stored_snapshot, mock_osv):
    with OSVClient() as client:
        result = evaluate_snapshot(store, stored_snapshot, client)

    ids = {f.vuln_id for f in result.evaluation.findings}
    assert ids == {"GHSA-old-0001", "DSA-undated", "CVE-2026-1111"}
    assert result.queried_components == 2


def test_as_of_hides_advisories_published_later(store, stored_snapshot, mock_osv):
    """The whole point: March cannot know about a May disclosure."""
    with OSVClient() as client:
        result = evaluate_snapshot(store, stored_snapshot, client, as_of=MARCH)

    ids = {f.vuln_id for f in result.evaluation.findings}
    assert ids == {"GHSA-old-0001"}
    assert result.filtered_by_date == 1  # CVE-2026-1111, published 2026-05-20


def test_undated_advisories_are_excluded_and_counted_not_assumed(store, stored_snapshot, mock_osv):
    """An advisory that cannot be placed in time must not be silently bucketed."""
    with OSVClient() as client:
        result = evaluate_snapshot(store, stored_snapshot, client, as_of=MARCH)

    assert result.undated_excluded == 1
    assert any("no publication date" in note for note in result.notes)


def test_cutoff_boundary_includes_advisories_published_that_day(store, stored_snapshot, mock_osv):
    """`published <= as_of`: an advisory published on the cutoff date is known."""
    with OSVClient() as client:
        result = evaluate_snapshot(
            store, stored_snapshot, client, as_of=datetime(2026, 5, 20, tzinfo=UTC)
        )

    assert "CVE-2026-1111" in {f.vuln_id for f in result.evaluation.findings}


def test_severity_comes_from_the_cvss_vector(store, stored_snapshot, mock_osv):
    with OSVClient() as client:
        result = evaluate_snapshot(store, stored_snapshot, client)

    by_id = {f.vuln_id: f for f in result.evaluation.findings}
    assert by_id["CVE-2026-1111"].severity == "CRITICAL"  # AV:N/.../C:H/I:H/A:H  → 9.8
    assert by_id["GHSA-old-0001"].severity == "HIGH"  # availability only        → 7.5
    assert by_id["DSA-undated"].severity == "MEDIUM"  # declared, no vector


def test_the_second_evaluation_costs_no_hydration(store, stored_snapshot, mock_osv):
    """Cached records are what make re-evaluation at another date free."""
    with OSVClient() as client:
        first = evaluate_snapshot(store, stored_snapshot, client, as_of=MARCH)
        assert first.hydrated == 3

    with OSVClient() as second_client:
        second = evaluate_snapshot(store, stored_snapshot, second_client, as_of=JUNE)

    assert second.hydrated == 0
    assert second.cache_hits == 3
    assert second_client.stats.detail_requests == 0


def test_evaluating_an_unstored_snapshot_is_refused(store, mock_osv):
    from sbomdrift.models import Snapshot
    from sbomdrift.store import utcnow

    orphan = Snapshot(artefact="x", source="tests", ingested_at=utcnow())
    with OSVClient() as client:
        try:
            evaluate_snapshot(store, orphan, client)
        except ValueError as exc:
            assert "stored" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ValueError")
