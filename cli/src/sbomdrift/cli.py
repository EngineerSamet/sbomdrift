# SPDX-License-Identifier: Apache-2.0
"""Command-line interface.

Four verbs, in the order you use them: ``ingest`` remembers, ``eval`` asks the
oracle, ``diff`` reports what changed, and ``pull``/``push`` move the memory
between ephemeral runners.

Typer was chosen over bare argparse because the type hints *are* the parser, so
there is one description of each option instead of two that drift apart.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .diff import DriftReport, compute_drift
from .evaluate import evaluate_snapshot
from .ingest import ingest_directory, ingest_file
from .models import SEVERITY_ORDER, normalise_severity
from .osv import OSVClient
from .store import Store

app = typer.Typer(
    name="sbomdrift",
    help="What became vulnerable since last time? SBOM drift detection with no server.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

DEFAULT_DB = "sbomdrift.db"

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
    "NONE": "dim",
}

DbOption = Annotated[
    Path,
    typer.Option("--db", envvar="SBOMDRIFT_DB", help="Path to the drift database."),
]


def _parse_date(value: str | None) -> datetime | None:
    """Accept ``YYYY-MM-DD`` or a full ISO timestamp, always ending up in UTC."""
    if value is None:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise typer.BadParameter(f"not a date: {value} (use YYYY-MM-DD)") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sbomdrift {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """sbomdrift — store SBOMs over time and report what changed."""


# ------------------------------------------------------------------------ ingest


@app.command()
def ingest(
    path: Annotated[Path, typer.Argument(help="SBOM file, or a directory of SBOM files.")],
    db: DbOption = Path(DEFAULT_DB),
    artefact: Annotated[
        str | None,
        typer.Option("--artefact", "-a", help="Identity to track drift under, e.g. python:3.11."),
    ] = None,
    digest: Annotated[
        str | None, typer.Option("--digest", help="Image digest this SBOM describes.")
    ] = None,
) -> None:
    """Record what an artefact contained, as described by an SBOM."""
    results = (
        ingest_directory(path, artefact=artefact)
        if path.is_dir()
        else [ingest_file(path, artefact=artefact, digest=digest)]
    )
    if not results:
        err_console.print(f"[red]no SBOM files found under {path}[/red]")
        raise typer.Exit(code=1)

    with Store(db) as store:
        for result in results:
            snapshot_id = store.add_snapshot(result.snapshot)
            console.print(
                f"[green]ingested[/green] snapshot [bold]{snapshot_id}[/bold] "
                f"· {result.snapshot.artefact} "
                f"· {len(result.snapshot.components)} components "
                f"· {result.snapshot.sbom_format}"
            )
            if result.skipped_non_packages:
                console.print(
                    f"  [dim]{result.skipped_non_packages} non-package entr(ies) "
                    f"(files, devices) skipped[/dim]"
                )
            if result.unmapped:
                err_console.print(
                    f"  [yellow]{len(result.unmapped)} package(s) had no PURL and cannot be "
                    f"evaluated[/yellow] (coverage {result.coverage:.1%})"
                )


# -------------------------------------------------------------------------- eval


@app.command(name="eval")
def evaluate_command(
    db: DbOption = Path(DEFAULT_DB),
    snapshot_id: Annotated[
        int | None, typer.Option("--snapshot", "-s", help="Evaluate this snapshot id.")
    ] = None,
    artefact: Annotated[
        str | None,
        typer.Option("--artefact", "-a", help="Evaluate the latest snapshot of this artefact."),
    ] = None,
    as_of: Annotated[
        str | None,
        typer.Option(
            "--as-of",
            help="Only count advisories published on or before this date (YYYY-MM-DD).",
        ),
    ] = None,
    label: Annotated[
        str | None, typer.Option("--label", "-l", help="Name this evaluation, for use in diff.")
    ] = None,
    osv_url: Annotated[
        str, typer.Option("--osv-url", help="OSV API base URL.", hidden=True)
    ] = "https://api.osv.dev",
) -> None:
    """Ask OSV.dev which components in a snapshot are vulnerable."""
    cutoff = _parse_date(as_of)

    with Store(db) as store:
        if snapshot_id is not None:
            snapshot = store.get_snapshot(snapshot_id)
        elif artefact:
            snapshot = store.latest_snapshot(artefact)
        else:
            snapshots = store.list_snapshots()
            snapshot = snapshots[-1] if snapshots else None

        if snapshot is None:
            err_console.print("[red]no snapshot to evaluate — run 'sbomdrift ingest' first[/red]")
            raise typer.Exit(code=1)

        with OSVClient(base_url=osv_url) as client:
            result = evaluate_snapshot(store, snapshot, client, as_of=cutoff, label=label)

        evaluation = result.evaluation
        scope = f" as of {cutoff.date()}" if cutoff else ""
        console.print(
            f"[green]evaluated[/green] snapshot [bold]{snapshot.id}[/bold] "
            f"({snapshot.artefact}){scope} "
            f"→ evaluation [bold]{evaluation.id}[/bold]"
            + (f" '{label}'" if label else "")
        )
        console.print(
            f"  {result.queried_components} components · {len(evaluation.findings)} findings · "
            f"{client.stats.batch_requests} batch call(s) · {result.hydrated} hydrated · "
            f"{result.cache_hits} from cache · {client.stats.seconds:.1f}s"
        )
        if result.filtered_by_date:
            console.print(
                f"  [dim]{result.filtered_by_date} advisory reference(s) published after "
                f"the cutoff were excluded[/dim]"
            )
        for note in result.notes:
            err_console.print(f"  [yellow]{note}[/yellow]")

        _print_severity_summary(evaluation.findings)


def _severity_cell(severity: str) -> str:
    """Render a severity with its colour, and without inventing empty markup.

    The naive form -- ``f"[{style}]{severity}[/]"`` -- produces ``[]MODERATE[/]``
    when the style lookup misses, and Rich rejects that with a MarkupError: the
    closing tag has nothing to close. That crashed ``diff`` outright on any report
    containing a GitHub-advisory severity.
    """
    label = normalise_severity(severity)
    style = SEVERITY_STYLE.get(label, "")
    return f"[{style}]{label}[/]" if style else label


def _print_severity_summary(findings: list) -> None:
    # Counted under the normalised label, so a database's own vocabulary lands in
    # the right bucket instead of being dropped: this loop only prints severities
    # it finds in SEVERITY_ORDER, so an untranslated MODERATE vanished silently.
    counts: dict[str, int] = {}
    for finding in findings:
        label = normalise_severity(finding.severity)
        counts[label] = counts.get(label, 0) + 1
    if not counts:
        return
    parts = [
        f"[{SEVERITY_STYLE.get(sev, '')}]{sev} {counts[sev]}[/]"
        for sev in reversed(SEVERITY_ORDER)
        if sev in counts
    ]
    console.print("  " + " · ".join(parts))


# -------------------------------------------------------------------------- diff


@app.command()
def diff(
    from_ref: Annotated[str, typer.Option("--from", "-f", help="Baseline evaluation id or label.")],
    to_ref: Annotated[str, typer.Option("--to", "-t", help="Comparison evaluation id or label.")],
    db: DbOption = Path(DEFAULT_DB),
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit non-zero if new drift reaches this severity (CI gate).",
        ),
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON instead of a table.")
    ] = False,
) -> None:
    """Report what changed between two evaluations."""
    with Store(db) as store:
        try:
            report = compute_drift(store, from_ref, to_ref)
        except LookupError as exc:
            err_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc

        if as_json:
            print(json.dumps(_report_to_dict(report), indent=2))
        else:
            _print_report(report)

        if fail_on:
            threshold = fail_on.upper()
            if threshold not in SEVERITY_ORDER:
                raise typer.BadParameter(f"unknown severity {fail_on!r}")
            if report.exceeds(threshold):
                err_console.print(
                    f"[bold red]drift gate: new finding at or above {threshold}[/bold red]"
                )
                raise typer.Exit(code=2)


def _report_to_dict(report: DriftReport) -> dict:
    def finding_dict(finding) -> dict:
        return {
            "purl": finding.purl,
            "vuln_id": finding.vuln_id,
            "severity": finding.severity,
            "published": finding.published.isoformat() if finding.published else None,
        }

    return {
        "kind": report.kind,
        "from": {
            "id": report.from_evaluation.id,
            "label": report.from_evaluation.label,
            "as_of": (
                report.from_evaluation.as_of.isoformat() if report.from_evaluation.as_of else None
            ),
        },
        "to": {
            "id": report.to_evaluation.id,
            "label": report.to_evaluation.label,
            "as_of": (
                report.to_evaluation.as_of.isoformat() if report.to_evaluation.as_of else None
            ),
        },
        "newly_vulnerable": [finding_dict(f) for f in report.newly_vulnerable],
        "newly_fixed": [finding_dict(f) for f in report.newly_fixed],
        "unchanged_count": len(report.unchanged),
        "added_components": report.added_components,
        "removed_components": report.removed_components,
        "upgraded_components": [
            {"component": identity, "from": old, "to": new}
            for identity, old, new in report.upgraded_components
        ],
        "max_new_severity": report.max_new_severity(),
    }


def _print_report(report: DriftReport) -> None:
    def moment(evaluation) -> str:
        return (
            evaluation.as_of.date().isoformat()
            if evaluation.as_of
            else evaluation.evaluated_at.date().isoformat()
        )

    console.rule(
        f"[bold]DRIFT[/bold] · {report.kind} · "
        f"{moment(report.from_evaluation)} → {moment(report.to_evaluation)}"
    )

    if report.is_clean:
        console.print("[green]no drift — nothing changed between these evaluations[/green]")
        return

    if report.newly_vulnerable:
        table = Table(
            title=f"+ newly vulnerable ({len(report.newly_vulnerable)})", title_justify="left"
        )
        table.add_column("severity")
        table.add_column("vulnerability")
        table.add_column("component", overflow="fold")
        for finding in report.newly_vulnerable:
            table.add_row(_severity_cell(finding.severity), finding.vuln_id, finding.purl)
        console.print(table)

    if report.newly_fixed:
        table = Table(title=f"- newly fixed ({len(report.newly_fixed)})", title_justify="left")
        table.add_column("severity")
        table.add_column("vulnerability")
        table.add_column("component", overflow="fold")
        for finding in report.newly_fixed:
            table.add_row(normalise_severity(finding.severity), finding.vuln_id, finding.purl)
        console.print(table)

    if report.added_components or report.removed_components or report.upgraded_components:
        console.print(
            f"~ components: [green]+{len(report.added_components)} added[/green] · "
            f"[red]-{len(report.removed_components)} removed[/red] · "
            f"[cyan]{len(report.upgraded_components)} upgraded[/cyan]"
        )

    console.print(
        f"[dim]{len(report.unchanged)} finding(s) unchanged · "
        f"highest new severity: {report.max_new_severity()}[/dim]"
    )


# ---------------------------------------------------------------------- listing


@app.command(name="list")
def list_command(
    db: DbOption = Path(DEFAULT_DB),
    what: Annotated[
        str, typer.Argument(help="'snapshots' or 'evaluations'.")
    ] = "snapshots",
) -> None:
    """List stored snapshots or evaluations."""
    with Store(db) as store:
        if what.startswith("snap"):
            table = Table("id", "artefact", "components", "ingested", "source")
            for snapshot in store.list_snapshots():
                table.add_row(
                    str(snapshot.id),
                    snapshot.artefact,
                    str(len(snapshot.components)),
                    snapshot.ingested_at.date().isoformat(),
                    snapshot.source,
                )
            console.print(table)
        else:
            table = Table("id", "label", "snapshot", "as of", "findings", "evaluated")
            for evaluation in store.list_evaluations():
                table.add_row(
                    str(evaluation.id),
                    evaluation.label or "",
                    str(evaluation.snapshot_id),
                    evaluation.as_of.date().isoformat() if evaluation.as_of else "now",
                    str(len(evaluation.findings)),
                    evaluation.evaluated_at.date().isoformat(),
                )
            console.print(table)


# ---------------------------------------------------------------------- metrics


@app.command()
def metrics(
    db: DbOption = Path(DEFAULT_DB),
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write to this file instead of stdout."),
    ] = None,
) -> None:
    """Emit the current drift state as Prometheus metrics.

    A scheduled job cannot be scraped -- it has exited by the time Prometheus
    calls. Write this to the node exporter's textfile collector directory, or
    pipe it to a Pushgateway.
    """
    from .metrics import render

    with Store(db) as store:
        document = render(store)

    if output is None:
        # Deliberately not console.print: Rich would wrap long lines and treat
        # the braces as markup, and the exposition format is whitespace-sensitive.
        sys.stdout.write(document)
        return

    # Written atomically. A textfile collector reads this directory on its own
    # schedule, and a half-written file is a parse error that silently drops
    # every metric in it.
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(document, encoding="utf-8")
    temporary.replace(output)
    err_console.print(f"[dim]wrote {output}[/dim]")


# ----------------------------------------------------------------------- remote


@app.command()
def pull(
    uri: Annotated[str, typer.Argument(help="s3://bucket/key of the drift database.")],
    db: DbOption = Path(DEFAULT_DB),
) -> None:
    """Fetch the drift database from S3 — run this first in CI."""
    from .remote import RemoteError
    from .remote import pull as remote_pull

    try:
        existed = remote_pull(uri, db)
    except RemoteError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    if existed:
        console.print(f"[green]pulled[/green] {uri} → {db}")
    else:
        console.print(f"[yellow]no history at {uri} yet — starting a new database[/yellow]")


@app.command()
def push(
    uri: Annotated[str, typer.Argument(help="s3://bucket/key to write the drift database to.")],
    db: DbOption = Path(DEFAULT_DB),
) -> None:
    """Store the drift database back in S3 — run this last in CI."""
    from .remote import RemoteError
    from .remote import push as remote_push

    try:
        remote_push(db, uri)
    except RemoteError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]pushed[/green] {db} → {uri}")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
