# SPDX-License-Identifier: Apache-2.0
"""CVSS v3.x base score, computed locally.

Why this file exists at all: OSV records do not carry a severity *label*. They
carry either a ``database_specific.severity`` string (GitHub advisories do, most
Linux distribution advisories do not) or a CVSS **vector string** under
``severity[]`` — and a vector is not a number. Something has to turn
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`` into ``CRITICAL`` before a CI
policy gate can threshold on it.

The alternative was to pull in a CVSS library for one arithmetic formula, or to
ship no severity at all and make ``--fail-on HIGH`` impossible. The formula is
published, fixed, and 40 lines; it is implemented here from the FIRST
specification so the CLI stays pure-Python and the scoring is unit-testable
against the specification's own worked examples.

Reference: FIRST, *CVSS v3.1 Specification Document*, section 8.1.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def parse_vector(vector: str) -> dict[str, str]:
    """Split a CVSS vector string into its metric/value pairs.

    Tolerates the leading ``CVSS:3.0``/``CVSS:3.1`` prefix and ignores any
    temporal or environmental metrics that follow the base ones.
    """
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        if key == "CVSS":
            continue
        metrics[key] = value
    return metrics


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A rounding: round *up* to one decimal, without float drift.

    Plain ``round()`` is wrong here — 8.55 must become 8.6, and binary floating
    point makes the naive version return 8.5 often enough to matter.
    """
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score, or ``None`` if the vector is not v3 base.

    Returning ``None`` rather than guessing is deliberate: a wrong severity in a
    CI gate is worse than an absent one, because it is silently trusted.
    """
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        ui = _UI[m["UI"]]
        conf, integ, avail = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    return _roundup(raw)


def score_to_severity(score: float | None) -> str:
    """Map a base score onto the qualitative rating scale (specification §5)."""
    if score is None:
        return "UNKNOWN"
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def severity_from_vector(vector: str) -> str:
    """Convenience: vector string straight to a qualitative rating."""
    return score_to_severity(base_score(vector))
