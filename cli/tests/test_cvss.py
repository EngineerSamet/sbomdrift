# SPDX-License-Identifier: Apache-2.0
"""CVSS scoring, checked against vectors whose published scores are fixed.

These are not self-consistent round-trips: each expected value is the score the
FIRST calculator produces for that vector, so the test fails if the formula is
mis-transcribed rather than merely if it changes.
"""

from __future__ import annotations

import pytest

from sbomdrift.cvss import base_score, parse_vector, score_to_severity, severity_from_vector

CASES = [
    # vector, expected base score, expected rating
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 3.7, "LOW"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
]


@pytest.mark.parametrize(("vector", "expected_score", "expected_rating"), CASES)
def test_base_score_matches_published_values(vector, expected_score, expected_rating):
    assert base_score(vector) == pytest.approx(expected_score)
    assert severity_from_vector(vector) == expected_rating


def test_cvss_30_vectors_are_accepted():
    """v3.0 and v3.1 share the base formula; only the rounding rule differs."""
    assert base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == pytest.approx(9.8)


def test_temporal_metrics_are_ignored_not_rejected():
    """Trailing temporal metrics must not break base scoring."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"
    assert base_score(vector) == pytest.approx(9.8)


def test_incomplete_vector_returns_none_rather_than_guessing():
    """A wrong severity in a CI gate is worse than an absent one."""
    assert base_score("CVSS:3.1/AV:N/AC:L") is None
    assert severity_from_vector("CVSS:3.1/AV:N/AC:L") == "UNKNOWN"


def test_cvss_v4_vector_is_not_scored_as_v3():
    """v4 uses a different formula; scoring it with the v3 one would be silently wrong."""
    assert base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H") is None


def test_parse_vector_drops_the_prefix():
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "CVSS" not in metrics
    assert metrics["AV"] == "N"
    assert metrics["S"] == "U"


@pytest.mark.parametrize(
    ("score", "rating"),
    [(None, "UNKNOWN"), (0.0, "NONE"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"),
     (6.9, "MEDIUM"), (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"), (10.0, "CRITICAL")],
)
def test_rating_boundaries(score, rating):
    """The boundaries are where an off-by-one silently mis-gates a pipeline."""
    assert score_to_severity(score) == rating
