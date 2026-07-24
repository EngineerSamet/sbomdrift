# SPDX-License-Identifier: Apache-2.0
"""Prometheus exposition of the drift database.

Why this is a *command* and not an HTTP endpoint: ``sbomdrift`` is a batch tool.
It runs, it finishes, it exits. Prometheus scrapes long-lived targets, and there
is nothing here for it to scrape -- by the time a scrape arrived the process
would be gone. The two ways to get a batch job's numbers into Prometheus are the
Pushgateway and the node exporter's textfile collector, and both want exactly
this: a block of exposition-format text on stdout or in a file.

Everything emitted is a **gauge**, because every number here is a level rather
than a running total. A counter that resets whenever the database is rebuilt
would be worse than no counter.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import SEVERITY_ORDER, normalise_severity
from .store import Store

NAMESPACE = "sbomdrift"


def escape_label_value(value: str) -> str:
    """Escape a label value per the exposition format.

    Backslash, double quote and newline are the only three characters the format
    defines escapes for. Artefact names carry colons and dots -- ``python:3.11-slim``
    -- which need no escaping inside a quoted value but would be invalid in a
    metric *name*, which is why the artefact is a label and not part of the name.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(pairs: dict[str, str]) -> str:
    if not pairs:
        return ""
    inner = ",".join(f'{k}="{escape_label_value(v)}"' for k, v in pairs.items())
    return "{" + inner + "}"


def format_value(value: float) -> str:
    """Render a sample value without losing precision.

    ``f"{value:g}"`` is the obvious choice and it is wrong here: %g keeps six
    significant digits, so a Unix timestamp -- ten digits before the point --
    came out as ``1.7849e+09``, silently rounded to the nearest few hundred
    seconds. A staleness alert built on that would fire against a clock that was
    minutes out. Integers are printed as integers, and anything else round-trips
    through ``repr``.
    """
    if value != value:
        return "NaN"
    if value == float("inf"):
        return "+Inf"
    if value == float("-inf"):
        return "-Inf"
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


@dataclass
class _Series:
    name: str
    help_text: str
    samples: list[tuple[dict[str, str], float]]

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} gauge"]
        lines.extend(
            f"{self.name}{_labels(labels)} {format_value(value)}" for labels, value in self.samples
        )
        return lines


def collect(store: Store) -> list[_Series]:
    """Read the current state of the database into a set of gauges.

    Only evaluations with no ``as_of`` are considered. A ``--as-of`` evaluation is
    a deliberate reconstruction of the past; letting one set the current gauge
    would make the dashboard assert something about now that the tool never
    claimed. They stay in the database and out of the metrics.
    """
    snapshots = store.list_snapshots()

    latest_snapshot: dict[str, object] = {}
    for snapshot in snapshots:
        current = latest_snapshot.get(snapshot.artefact)
        if current is None or snapshot.ingested_at >= current.ingested_at:  # type: ignore[attr-defined]
            latest_snapshot[snapshot.artefact] = snapshot

    components: list[tuple[dict[str, str], float]] = []
    findings: list[tuple[dict[str, str], float]] = []
    evaluated_at: list[tuple[dict[str, str], float]] = []
    stale: list[tuple[dict[str, str], float]] = []

    for artefact, snapshot in sorted(latest_snapshot.items()):
        components.append(({"artefact": artefact}, float(len(store.components(snapshot.id)))))

        live = [e for e in store.list_evaluations(snapshot.id) if e.as_of is None]
        if not live:
            # Emitted as 0 rather than omitted: a missing series is invisible to an
            # alert rule, and "this artefact has never been evaluated" is exactly
            # the condition worth alerting on.
            stale.append(({"artefact": artefact}, 1.0))
            continue

        newest = max(live, key=lambda e: e.evaluated_at)
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in store.findings(newest.id):
            counts[normalise_severity(finding.severity)] += 1

        for severity in SEVERITY_ORDER:
            findings.append(
                ({"artefact": artefact, "severity": severity}, float(counts[severity]))
            )
        evaluated_at.append(
            ({"artefact": artefact}, newest.evaluated_at.timestamp())
        )
        stale.append(({"artefact": artefact}, 0.0))

    return [
        _Series(
            f"{NAMESPACE}_snapshots",
            "Stored component inventories, across all artefacts.",
            [({}, float(len(snapshots)))],
        ),
        _Series(
            f"{NAMESPACE}_evaluations",
            "Stored evaluations, including historical --as-of reconstructions.",
            [({}, float(len(store.list_evaluations())))],
        ),
        _Series(
            f"{NAMESPACE}_components",
            "Components in the most recent snapshot of each artefact.",
            components,
        ),
        _Series(
            f"{NAMESPACE}_findings",
            "Vulnerability findings in the most recent live evaluation of each artefact.",
            findings,
        ),
        _Series(
            f"{NAMESPACE}_last_evaluation_timestamp_seconds",
            "When each artefact was last evaluated, as a Unix timestamp.",
            evaluated_at,
        ),
        _Series(
            f"{NAMESPACE}_never_evaluated",
            "1 when an artefact has been ingested but never evaluated live.",
            stale,
        ),
    ]


def render(store: Store) -> str:
    """The complete exposition document, newline-terminated as the format requires."""
    lines: list[str] = []
    for series in collect(store):
        lines.extend(series.render())
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"
