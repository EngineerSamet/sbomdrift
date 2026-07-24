# SPDX-License-Identifier: Apache-2.0
"""The drift report — both kinds, and the CI gate."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sbomdrift.diff import compute_drift
from sbomdrift.evaluate import evaluate_snapshot
from sbomdrift.models import Component, Snapshot
from sbomdrift.osv import OSVClient
from sbomdrift.store import utcnow

MARCH = datetime(2026, 3, 1, tzinfo=UTC)


@pytest.fixture
def time_drift(store, stored_snapshot, mock_osv):
    """One artefact standing still while the world publishes advisories."""
    with OSVClient() as client:
        evaluate_snapshot(store, stored_snapshot, client, as_of=MARCH, label="march")
        evaluate_snapshot(store, stored_snapshot, client, label="today")
    return compute_drift(store, "march", "today")


def test_time_drift_reports_exactly_what_appeared(time_drift):
    assert time_drift.kind == "time drift"
    assert {f.vuln_id for f in time_drift.newly_vulnerable} == {"CVE-2026-1111", "DSA-undated"}
    assert time_drift.newly_fixed == []
    assert {f.vuln_id for f in time_drift.unchanged} == {"GHSA-old-0001"}


def test_newly_vulnerable_is_ordered_by_severity(time_drift):
    assert [f.severity for f in time_drift.newly_vulnerable] == ["CRITICAL", "MEDIUM"]
    assert time_drift.max_new_severity() == "CRITICAL"


def test_the_gate_fires_on_new_risk(time_drift):
    assert time_drift.exceeds("HIGH") is True
    assert time_drift.exceeds("CRITICAL") is True


def test_the_gate_ignores_the_existing_backlog(store, stored_snapshot, mock_osv):
    """A pipeline that fails on findings it already knew about gets muted in a week."""
    with OSVClient() as client:
        evaluate_snapshot(store, stored_snapshot, client, label="a")
        evaluate_snapshot(store, stored_snapshot, client, label="b")

    report = compute_drift(store, "a", "b")
    assert report.newly_vulnerable == []
    assert report.exceeds("LOW") is False
    assert len(report.unchanged) == 3


def test_identical_evaluations_are_clean(store, stored_snapshot, mock_osv):
    with OSVClient() as client:
        evaluate_snapshot(store, stored_snapshot, client, label="a")
        evaluate_snapshot(store, stored_snapshot, client, label="b")

    assert compute_drift(store, "a", "b").is_clean is True


def test_version_drift_reports_component_changes(store, stored_snapshot, mock_osv):
    """The artefact moved: urllib3 was upgraded away from the vulnerable version."""
    upgraded = Snapshot(
        artefact="demo-app",
        source="tests",
        ingested_at=utcnow(),
        components=[
            Component("pkg:pypi/requests@2.31.0", "requests", "2.31.0"),
            Component("pkg:pypi/urllib3@2.2.2", "urllib3", "2.2.2"),
        ],
    )
    store.add_snapshot(upgraded)

    with OSVClient() as client:
        evaluate_snapshot(store, stored_snapshot, client, label="before")
        evaluate_snapshot(store, upgraded, client, label="after")

    report = compute_drift(store, "before", "after")

    assert report.kind == "version drift"
    assert report.added_components == ["pkg:pypi/urllib3@2.2.2"]
    assert report.removed_components == ["pkg:pypi/urllib3@2.0.7"]
    assert {f.vuln_id for f in report.newly_fixed} == {"CVE-2026-1111"}
    assert report.newly_vulnerable == []


def test_findings_are_keyed_on_component_and_vulnerability(store, mock_osv):
    """The same CVE on two components is two findings; fixing one must show."""
    both = Snapshot(
        artefact="pair",
        source="tests",
        ingested_at=utcnow(),
        components=[
            Component("pkg:pypi/requests@2.31.0", "requests", "2.31.0"),
            Component("pkg:pypi/urllib3@2.0.7", "urllib3", "2.0.7"),
        ],
    )
    only_one = Snapshot(
        artefact="pair",
        source="tests",
        ingested_at=utcnow(),
        components=[Component("pkg:pypi/requests@2.31.0", "requests", "2.31.0")],
    )
    store.add_snapshot(both)
    store.add_snapshot(only_one)

    with OSVClient() as client:
        evaluate_snapshot(store, both, client, label="both")
        evaluate_snapshot(store, only_one, client, label="one")

    report = compute_drift(store, "both", "one")
    assert [f.purl for f in report.newly_fixed] == ["pkg:pypi/urllib3@2.0.7"]


def test_diffing_a_missing_evaluation_is_an_explicit_error(store):
    with pytest.raises(LookupError):
        compute_drift(store, "nope", "also-nope")


def test_severity_histogram(time_drift):
    assert time_drift.counts_by_severity() == {"CRITICAL": 1, "MEDIUM": 1}
