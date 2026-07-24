# SPDX-License-Identifier: Apache-2.0
"""Regenerate every measurement and figure in the internship report.

Run this and the numbers in the report are reproduced from scratch. That is the
point: a report figure whose provenance is "I remember making it in July" is not
evidence. Every value printed here is written to ``evaluation/raw/`` as JSON
beside the figure that displays it.

    uv run --project ../cli python run_evaluation.py

Two of the three measurements need no network (they read the committed Trivy
output and the drift database); the OSV evaluation does, and is skipped with a
clear message if the database already holds the evaluations it would create.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import MaxNLocator  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "evaluation" / "raw"
FIGURES = ROOT.parent / "SE_Internship_Report (1) (1)(1)" / "img"
DB = ROOT / "evaluation" / "demo.db"

OLD_IMAGE = "python:3.11.0-slim"
NEW_IMAGE = "python:3.11-slim"

AS_OF_DATES = ["2023-01-01", "2024-01-01", "2025-01-01", "2026-01-01", "2026-04-01", "2026-07-24"]

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# --------------------------------------------------------------------- palette
#
# Taken unchanged from a validated palette and checked with the accompanying
# validator rather than chosen by eye: the categorical pair, the diverging poles
# and the five-step ordinal ramp each pass the lightness-band, chroma, CVD-
# separation, normal-vision and contrast gates on a light surface.

INK = "#0b0b0b"
MUTED = "#898781"
GRID = "#e1e0d9"
SURFACE = "#fcfcfb"

SERIES = ["#2a78d6", "#eb6834"]  # categorical slots 1 and 2
POLE_BAD = "#d03b3b"  # diverging: newly vulnerable
POLE_GOOD = "#2a78d6"  # diverging: newly fixed

# Severity is ordered magnitude, so it gets one hue stepped light to dark —
# never five unrelated hues, which would imply five unrelated categories.
SEVERITY_RAMP = {
    "UNKNOWN": "#86b6ef",
    "LOW": "#5598e7",
    "MEDIUM": "#2a78d6",
    "HIGH": "#1c5cab",
    "CRITICAL": "#0d366b",
}


def style_axes(ax, *, xgrid: bool = False) -> None:
    """Recessive chrome: the data should be the darkest thing on the page."""
    ax.set_facecolor(SURFACE)
    ax.figure.set_facecolor(SURFACE)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)
    ax.grid(axis="x" if xgrid else "y", color=GRID, linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)


def save(fig, name: str) -> Path:
    FIGURES.mkdir(parents=True, exist_ok=True)
    path = FIGURES / name
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    print(f"  wrote {path.relative_to(ROOT.parent)}")
    return path


def write_raw(name: str, payload: object) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    (RAW / name).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"  wrote evaluation/raw/{name}")


# ----------------------------------------------------------------- measurement


def sbomdrift(*args: str) -> str:
    """Invoke the CLI exactly as a user would, rather than importing it."""
    result = subprocess.run(
        [sys.executable, "-m", "sbomdrift.cli", *args, "--db", str(DB)],
        capture_output=True,
        text=True,
        cwd=ROOT / "cli" / "src",
    )
    if result.returncode not in (0, 2):  # 2 is the drift gate, not a failure here
        raise RuntimeError(f"sbomdrift {' '.join(args)} failed:\n{result.stderr}")
    return result.stdout


def build_database() -> None:
    """Ingest both SBOMs and evaluate them, unless that has already been done."""
    if DB.exists():
        print("  database already present — reusing it (delete demo.db to rebuild)")
        return

    print("  ingesting SBOMs and querying OSV.dev (this needs the network)")
    for sample, artefact in (
        ("python-3.11.0-slim.cdx.json", NEW_IMAGE),
        ("python-3.11-slim.cdx.json", NEW_IMAGE),
    ):
        sbomdrift("ingest", str(ROOT / "samples" / sample), "-a", artefact)

    sbomdrift("eval", "-s", "1", "-l", "old-image")
    sbomdrift("eval", "-s", "2", "-l", "current-image")
    for date in AS_OF_DATES:
        # Every point in the time series is filtered by --as-of, including the
        # last one: comparing a filtered series against an unfiltered endpoint
        # would attribute the difference to time rather than to the filter.
        sbomdrift("eval", "-s", "2", "--as-of", date, "-l", f"asof-{date}")


def query(sql: str, *params: object) -> list[sqlite3.Row]:
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(sql, params).fetchall()
    finally:
        connection.close()


def severity_counts(evaluation_label: str) -> Counter:
    rows = query(
        """SELECT f.severity FROM findings f
           JOIN evaluations e ON e.id = f.evaluation_id
           WHERE e.label = ?""",
        evaluation_label,
    )
    return Counter(row["severity"] for row in rows)


# ------------------------------------------------------------------- figure 1


def figure_time_drift() -> dict:
    """One image standing still while the world publishes advisories."""
    series = []
    for date in AS_OF_DATES:
        counts = severity_counts(f"asof-{date}")
        series.append(
            {
                "as_of": date,
                "total": sum(counts.values()),
                "high_or_above": counts["HIGH"] + counts["CRITICAL"],
            }
        )

    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    style_axes(ax)

    # A real date axis, not evenly spaced categories. The sample points are
    # 12 months apart at the start and 3 months apart at the end; drawing them
    # equidistant would inflate the final rise into something the data does not
    # say.
    dates = [datetime.fromisoformat(point["as_of"]) for point in series]
    totals = [point["total"] for point in series]
    severe = [point["high_or_above"] for point in series]

    ax.plot(dates, totals, color=SERIES[0], linewidth=2, marker="o", markersize=5, zorder=3)
    ax.plot(dates, severe, color=SERIES[1], linewidth=2, marker="o", markersize=5, zorder=3)

    # Direct labels on the last point only — a number on every point is noise.
    for label, values, color in (
        ("all severities", totals, SERIES[0]),
        ("high & critical", severe, SERIES[1]),
    ):
        # Labelled to the right of the final point, clear of both lines — the
        # earlier placement put the second label across the first line.
        ax.annotate(
            f"{label} · {values[-1]}",
            (dates[-1], values[-1]),
            textcoords="offset points",
            xytext=(9, -3),
            ha="left",
            color=color,
            fontsize=9,
            fontweight="bold",
            annotation_clip=False,
        )

    ax.set_ylabel("known vulnerabilities", color=MUTED, fontsize=9)
    ax.set_xlabel("evaluated as of", color=MUTED, fontsize=9)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.xaxis.set_major_locator(mdates.YearLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
    ax.xaxis.set_minor_locator(mdates.MonthLocator(bymonth=(1, 4, 7, 10)))
    ax.set_ylim(bottom=0)
    ax.set_xlim(dates[0] - timedelta(days=60), dates[-1] + timedelta(days=45))
    fig.subplots_adjust(right=0.76)  # room for the direct labels

    write_raw("time-drift.json", series)
    save(fig, "fig-time-drift.png")
    return {"series": series}


# ------------------------------------------------------------------- figure 2


def figure_version_drift() -> dict:
    """What the base-image upgrade actually changed, by severity."""
    report = json.loads(sbomdrift("diff", "-f", "old-image", "-t", "current-image", "--json"))

    buckets = {
        "newly vulnerable": Counter(f["severity"] for f in report["newly_vulnerable"]),
        "newly fixed": Counter(f["severity"] for f in report["newly_fixed"]),
    }

    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    style_axes(ax, xgrid=True)

    for row, (name, counts) in enumerate(buckets.items()):
        left = 0.0
        for severity in SEVERITIES:
            value = counts.get(severity, 0)
            if not value:
                continue
            ax.barh(
                row,
                value,
                left=left,
                height=0.52,
                color=SEVERITY_RAMP[severity],
                # A 2px surface gap keeps adjacent segments legible without
                # relying on the hue difference alone.
                edgecolor=SURFACE,
                linewidth=1.5,
                zorder=3,
            )
            if value >= 6:  # label only where the segment can hold the text
                ax.text(
                    left + value / 2,
                    row,
                    str(value),
                    ha="center",
                    va="center",
                    color=SURFACE if severity in ("HIGH", "CRITICAL") else INK,
                    fontsize=8,
                    fontweight="bold",
                    zorder=4,
                )
            left += value

        ax.text(
            left + 2,
            row,
            f"{int(left)}",
            va="center",
            color=INK,
            fontsize=9,
            fontweight="bold",
            zorder=4,
        )

    ax.set_yticks(range(len(buckets)), list(buckets), fontsize=10, color=INK)
    ax.invert_yaxis()
    ax.set_xlabel("findings", color=MUTED, fontsize=9)

    handles = [
        plt.Rectangle((0, 0), 1, 1, color=SEVERITY_RAMP[s]) for s in reversed(SEVERITIES)
    ]
    ax.legend(
        handles,
        list(reversed(SEVERITIES)),
        loc="lower right",
        bbox_to_anchor=(1.0, -0.62),
        ncol=5,
        frameon=False,
        fontsize=8,
        labelcolor=MUTED,
        handlelength=1.0,
        columnspacing=1.2,
    )

    payload = {
        "kind": report["kind"],
        "newly_vulnerable": dict(buckets["newly vulnerable"]),
        "newly_fixed": dict(buckets["newly fixed"]),
        "unchanged": report["unchanged_count"],
        "components": {
            "added": len(report["added_components"]),
            "removed": len(report["removed_components"]),
            "upgraded": len(report["upgraded_components"]),
        },
    }
    write_raw("version-drift-summary.json", payload)
    save(fig, "fig-version-drift.png")
    return payload


# ------------------------------------------------------------------- figure 3


def load_trivy(path: Path) -> set[tuple[str, str]]:
    """Reduce a Trivy SBOM scan to (package name, vulnerability id) pairs."""
    document = json.loads(path.read_text(encoding="utf-8"))
    findings = set()
    for result in document.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            findings.add((vulnerability["PkgName"].lower(), vulnerability["VulnerabilityID"]))
    return findings


def osv_findings(label: str) -> dict[tuple[str, str], set[str]]:
    """The same reduction over sbomdrift's findings, keyed so the sets compare.

    Returns ``{(package, canonical id): {every identifier for that flaw}}``.
    Identifier aliasing is not a detail: the same flaw is ``GHSA-8rrh-rw8j-w5fx``
    to GitHub, ``PYSEC-2026-1469`` to the Python advisory database and
    ``CVE-2026-xxxxx`` to Trivy. Comparing raw ids would have scored two oracles
    that agree as total disagreement.
    """
    rows = query(
        """SELECT f.purl, f.vuln_id, v.aliases
           FROM findings f
           JOIN evaluations e ON e.id = f.evaluation_id
           LEFT JOIN vuln_cache v ON v.vuln_id = f.vuln_id
           WHERE e.label = ?""",
        label,
    )

    findings: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        package = row["purl"].split("@")[0].rsplit("/", 1)[-1].lower()

        identifiers = {row["vuln_id"]}
        identifiers.update(json.loads(row["aliases"]) if row["aliases"] else [])
        # OSV names Debian advisories DEBIAN-CVE-2022-1664; the underlying CVE is
        # the same record.
        identifiers.update(
            i[len("DEBIAN-") :] for i in list(identifiers) if i.startswith("DEBIAN-CVE-")
        )

        canonical = next(
            (i for i in sorted(identifiers) if i.startswith("CVE-")), row["vuln_id"]
        )
        findings.setdefault((package, canonical), set()).update(identifiers)
    return findings


def figure_oracle_agreement() -> dict:
    """Two vulnerability databases, one identical component list."""
    comparisons = []
    for label, trivy_file, title in (
        ("old-image", "trivy-python-3.11.0-slim.json", OLD_IMAGE),
        ("current-image", "trivy-python-3.11-slim.json", NEW_IMAGE),
    ):
        osv = osv_findings(label)
        trivy = load_trivy(RAW / trivy_file)

        # A finding matches if the packages agree and *any* identifier does.
        matched_osv, matched_trivy = set(), set()
        for key, identifiers in osv.items():
            package = key[0]
            hits = {(package, i) for i in identifiers} & trivy
            if hits:
                matched_osv.add(key)
                matched_trivy |= hits

        comparisons.append(
            {
                "image": title,
                "osv_only": len(osv) - len(matched_osv),
                "both": len(matched_osv),
                "trivy_only": len(trivy - matched_trivy),
                "osv_total": len(osv),
                "trivy_total": len(trivy),
                "jaccard": round(
                    len(matched_osv)
                    / (len(osv) + len(trivy - matched_trivy)),
                    3,
                )
                if osv or trivy
                else 0.0,
            }
        )

    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    style_axes(ax, xgrid=True)

    for row, comparison in enumerate(comparisons):
        segments = [
            ("OSV.dev only", comparison["osv_only"], SERIES[0]),
            ("both", comparison["both"], "#c3c2b7"),
            ("Trivy only", comparison["trivy_only"], SERIES[1]),
        ]
        left = 0.0
        for _, value, color in segments:
            if not value:
                continue
            ax.barh(
                row, value, left=left, height=0.5,
                color=color, edgecolor=SURFACE, linewidth=1.5, zorder=3,
            )
            if value >= 8:
                ax.text(
                    left + value / 2, row, str(value),
                    ha="center", va="center", fontsize=8, fontweight="bold",
                    color=SURFACE if color != "#c3c2b7" else INK, zorder=4,
                )
            left += value

    ax.set_yticks(
        range(len(comparisons)),
        [c["image"] for c in comparisons],
        fontsize=10,
        color=INK,
    )
    ax.invert_yaxis()
    ax.set_xlabel("distinct (package, vulnerability) findings", color=MUTED, fontsize=9)

    handles = [
        plt.Rectangle((0, 0), 1, 1, color=SERIES[0]),
        plt.Rectangle((0, 0), 1, 1, color="#c3c2b7"),
        plt.Rectangle((0, 0), 1, 1, color=SERIES[1]),
    ]
    ax.legend(
        handles, ["OSV.dev only", "both agree", "Trivy only"],
        loc="lower right", bbox_to_anchor=(1.0, -0.72), ncol=3,
        frameon=False, fontsize=8, labelcolor=MUTED, handlelength=1.0,
    )

    write_raw("oracle-agreement.json", comparisons)
    save(fig, "fig-oracle-agreement.png")
    return {"comparisons": comparisons}


def main() -> None:
    print("sbomdrift evaluation")
    print("\n[1/4] database")
    build_database()

    print("\n[2/4] time drift")
    time_drift = figure_time_drift()

    print("\n[3/4] version drift")
    version_drift = figure_version_drift()

    print("\n[4/4] oracle agreement")
    agreement = figure_oracle_agreement()

    print("\nsummary")
    last = time_drift["series"][-1]
    print(f"  time drift    : {time_drift['series'][0]['total']} → {last['total']} findings")
    print(
        f"  version drift : +{sum(version_drift['newly_vulnerable'].values())} new, "
        f"-{sum(version_drift['newly_fixed'].values())} fixed, "
        f"{version_drift['unchanged']} unchanged"
    )
    for comparison in agreement["comparisons"]:
        print(
            f"  agreement     : {comparison['image']} — {comparison['both']} shared, "
            f"{comparison['osv_only']} OSV-only, {comparison['trivy_only']} Trivy-only "
            f"(Jaccard {comparison['jaccard']})"
        )


if __name__ == "__main__":
    main()
