# SPDX-License-Identifier: Apache-2.0
"""Prometheus exposition tests.

The exposition format is whitespace- and precision-sensitive, and a malformed
document does not fail loudly: Prometheus drops the offending series and carries
on. So these tests assert the shape of the text, not just that it was produced.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sbomdrift.metrics import escape_label_value, format_value, render
from sbomdrift.models import Component, Evaluation, Finding, Snapshot


def _snapshot(store, artefact: str = "python:3.11-slim") -> Snapshot:
    snapshot = Snapshot(
        artefact=artefact,
        source="test",
        ingested_at=datetime(2026, 7, 1, tzinfo=UTC),
        components=[
            Component("pkg:pypi/requests@2.31.0", "requests", "2.31.0"),
            Component("pkg:pypi/urllib3@2.0.7", "urllib3", "2.0.7"),
        ],
    )
    snapshot.id = store.add_snapshot(snapshot)
    return snapshot


def _evaluate(store, snapshot, *, severities, as_of=None, when=None) -> Evaluation:
    evaluation = Evaluation(
        snapshot_id=snapshot.id,
        evaluated_at=when or datetime(2026, 7, 24, 12, 0, tzinfo=UTC),
        as_of=as_of,
        findings=[
            Finding(purl="pkg:pypi/requests@2.31.0", vuln_id=f"V-{i}", severity=severity)
            for i, severity in enumerate(severities)
        ],
    )
    evaluation.id = store.add_evaluation(evaluation)
    return evaluation


# ------------------------------------------------------------------ formatting


def test_timestamps_keep_their_precision():
    """The regression this file exists for.

    ``f"{value:g}"`` keeps six significant digits. A Unix timestamp needs ten, so
    the first implementation emitted 1.7849e+09 -- the same string for every
    instant inside a two-hundred-second window. Any alert on evaluation staleness
    would have been comparing against a clock that was minutes wrong.
    """
    stamp = 1784898070.541033
    assert format_value(stamp) == "1784898070.541033"
    assert float(format_value(stamp)) == stamp


def test_whole_numbers_are_not_printed_as_floats():
    assert format_value(115.0) == "115"
    assert format_value(0.0) == "0"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('quote"inside', 'quote\\"inside'),
        ("back\\slash", "back\\\\slash"),
        ("two\nlines", "two\\nlines"),
        ("python:3.11-slim", "python:3.11-slim"),
    ],
)
def test_label_values_are_escaped(raw, expected):
    """Colons and dots need no escaping in a *value*; the three that do are these."""
    assert escape_label_value(raw) == expected


# ---------------------------------------------------------------------- output


def test_every_metric_carries_help_and_type(store):
    snapshot = _snapshot(store)
    _evaluate(store, snapshot, severities=["HIGH"])

    document = render(store)
    names = {
        line.split()[2]
        for line in document.splitlines()
        if line.startswith("# HELP")
    }
    assert names == {
        "sbomdrift_snapshots",
        "sbomdrift_evaluations",
        "sbomdrift_components",
        "sbomdrift_findings",
        "sbomdrift_last_evaluation_timestamp_seconds",
        "sbomdrift_never_evaluated",
    }
    for name in names:
        assert f"# TYPE {name} gauge" in document

    assert document.endswith("\n"), "the format requires a trailing newline"


def test_all_severities_are_emitted_even_at_zero(store):
    """A series that is absent is invisible to an alert rule.

    ``sbomdrift_findings{severity="CRITICAL"} > 0`` can only fire if the series
    exists while the count is still zero, so the zero has to be published.
    """
    snapshot = _snapshot(store)
    _evaluate(store, snapshot, severities=["HIGH", "HIGH"])

    document = render(store)
    assert 'severity="CRITICAL"} 0' in document
    assert 'severity="HIGH"} 2' in document


def test_moderate_is_counted_under_its_cvss_band(store):
    """The severity vocabularies are reconciled before they reach a dashboard."""
    snapshot = _snapshot(store)
    _evaluate(store, snapshot, severities=["MODERATE"])

    document = render(store)
    assert 'severity="MEDIUM"} 1' in document
    assert "MODERATE" not in document


def test_as_of_evaluations_do_not_set_the_current_gauge(store):
    """A historical reconstruction describes the past on purpose.

    Letting one win the "most recent evaluation" race would make the dashboard
    assert something about now that the tool never claimed.
    """
    snapshot = _snapshot(store)
    _evaluate(store, snapshot, severities=["LOW"], when=datetime(2026, 7, 1, tzinfo=UTC))
    _evaluate(
        store,
        snapshot,
        severities=["CRITICAL", "CRITICAL", "CRITICAL"],
        as_of=datetime(2023, 1, 1, tzinfo=UTC),
        when=datetime(2026, 7, 24, tzinfo=UTC),
    )

    document = render(store)
    assert 'severity="CRITICAL"} 0' in document, "the --as-of evaluation must not win"
    assert 'severity="LOW"} 1' in document


def test_the_newest_live_evaluation_wins(store):
    snapshot = _snapshot(store)
    base = datetime(2026, 7, 1, tzinfo=UTC)
    _evaluate(store, snapshot, severities=["LOW"], when=base)
    _evaluate(store, snapshot, severities=["HIGH", "HIGH"], when=base + timedelta(days=3))

    document = render(store)
    assert 'severity="HIGH"} 2' in document
    assert 'severity="LOW"} 0' in document


def test_an_unevaluated_artefact_is_reported_rather_than_omitted(store):
    """Silence and "nothing found" must not look the same on a dashboard."""
    _snapshot(store)

    document = render(store)
    assert 'sbomdrift_never_evaluated{artefact="python:3.11-slim"} 1' in document
    assert "sbomdrift_last_evaluation_timestamp_seconds{" not in document


def test_an_empty_database_still_produces_a_valid_document(store):
    document = render(store)
    assert "sbomdrift_snapshots 0" in document
    assert "sbomdrift_evaluations 0" in document
