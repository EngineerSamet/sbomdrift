# SPDX-License-Identifier: Apache-2.0
"""The command line itself.

The CLI is the product's only interface, so the exit codes matter as much as the
output: a CI gate that prints a scary table and still exits 0 is decoration.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from sbomdrift.cli import app

runner = CliRunner()


def _run(*args: str) -> object:
    return runner.invoke(app, list(args))


def test_version():
    result = _run("--version")
    assert result.exit_code == 0
    assert "sbomdrift" in result.stdout


def test_ingest_then_list(tmp_path, sbom_path):
    db = str(tmp_path / "drift.db")

    ingested = _run("ingest", str(sbom_path), "--db", db, "--artefact", "demo")
    assert ingested.exit_code == 0
    assert "ingested" in ingested.stdout

    listed = _run("list", "snapshots", "--db", db)
    assert listed.exit_code == 0
    assert "demo" in listed.stdout


def test_ingest_reports_unmapped_components(tmp_path, sbom_path):
    """Coverage below 100% must be visible, not buried."""
    result = _run("ingest", str(sbom_path), "--db", str(tmp_path / "drift.db"))
    assert result.exit_code == 0
    assert "no PURL" in result.output


def test_eval_without_a_snapshot_fails_clearly(tmp_path):
    result = _run("eval", "--db", str(tmp_path / "empty.db"))
    assert result.exit_code == 1
    assert "ingest" in result.output


def test_full_workflow_ends_in_a_drift_table(tmp_path, sbom_path, mock_osv):
    db = str(tmp_path / "drift.db")

    assert _run("ingest", str(sbom_path), "--db", db, "-a", "demo").exit_code == 0
    assert _run("eval", "--db", db, "--as-of", "2026-03-01", "-l", "march").exit_code == 0
    assert _run("eval", "--db", db, "-l", "today").exit_code == 0

    drift = _run("diff", "--db", db, "--from", "march", "--to", "today")
    assert drift.exit_code == 0
    assert "newly vulnerable" in drift.stdout
    assert "CVE-2026-1111" in drift.stdout


def test_fail_on_returns_a_distinct_exit_code(tmp_path, sbom_path, mock_osv):
    """Exit 2 for 'gate tripped' so CI can tell it apart from exit 1, 'tool broke'."""
    db = str(tmp_path / "drift.db")
    _run("ingest", str(sbom_path), "--db", db, "-a", "demo")
    _run("eval", "--db", db, "--as-of", "2026-03-01", "-l", "march")
    _run("eval", "--db", db, "-l", "today")

    tripped = _run("diff", "--db", db, "-f", "march", "-t", "today", "--fail-on", "HIGH")
    assert tripped.exit_code == 2

    tolerant = _run("diff", "--db", db, "-f", "march", "-t", "today", "--fail-on", "CRITICAL")
    assert tolerant.exit_code == 2

    # Nothing new between two identical evaluations: the gate stays quiet.
    _run("eval", "--db", db, "-l", "again")
    quiet = _run("diff", "--db", db, "-f", "today", "-t", "again", "--fail-on", "LOW")
    assert quiet.exit_code == 0


def test_json_output_is_machine_readable(tmp_path, sbom_path, mock_osv):
    db = str(tmp_path / "drift.db")
    _run("ingest", str(sbom_path), "--db", db, "-a", "demo")
    _run("eval", "--db", db, "--as-of", "2026-03-01", "-l", "march")
    _run("eval", "--db", db, "-l", "today")

    result = _run("diff", "--db", db, "-f", "march", "-t", "today", "--json")
    payload = json.loads(result.stdout)

    assert payload["kind"] == "time drift"
    assert payload["max_new_severity"] == "CRITICAL"
    assert {f["vuln_id"] for f in payload["newly_vulnerable"]} == {"CVE-2026-1111", "DSA-undated"}


def test_diff_with_unknown_label_fails(tmp_path):
    result = _run("diff", "--db", str(tmp_path / "drift.db"), "-f", "a", "-t", "b")
    assert result.exit_code == 1


def test_unknown_severity_threshold_is_rejected(tmp_path, sbom_path, mock_osv):
    db = str(tmp_path / "drift.db")
    _run("ingest", str(sbom_path), "--db", db, "-a", "demo")
    _run("eval", "--db", db, "-l", "a")
    _run("eval", "--db", db, "-l", "b")

    result = _run("diff", "--db", db, "-f", "a", "-t", "b", "--fail-on", "SCARY")
    assert result.exit_code != 0


def test_bad_date_is_rejected_before_any_network_call(tmp_path, sbom_path):
    db = str(tmp_path / "drift.db")
    _run("ingest", str(sbom_path), "--db", db, "-a", "demo")

    result = _run("eval", "--db", db, "--as-of", "last tuesday")
    assert result.exit_code != 0


def test_diff_renders_a_github_advisory_severity_without_crashing(tmp_path, monkeypatch):
    """Regression: `diff` died with a Rich MarkupError on any report containing a
    severity outside the CVSS vocabulary.

    The printer built `f"[{style}]{severity}[/]"`, and the style lookup missed for
    MODERATE, so the markup came out as `[]MODERATE[/]` -- a closing tag with
    nothing to close. The suite never caught it because every fixture severity was
    already a CVSS band.
    """
    from rich.console import Console

    from sbomdrift import cli as cli_module
    from sbomdrift.diff import DriftReport
    from sbomdrift.models import Evaluation, Finding
    from sbomdrift.store import utcnow

    recorded = Console(file=open(tmp_path / "out.txt", "w", encoding="utf-8"), width=100)
    monkeypatch.setattr(cli_module, "console", recorded)

    now = utcnow()
    report = DriftReport(
        from_evaluation=Evaluation(snapshot_id=1, evaluated_at=now, label="before", id=1),
        to_evaluation=Evaluation(snapshot_id=1, evaluated_at=now, label="after", id=2),
        newly_vulnerable=[
            Finding(purl="pkg:pypi/wheel", vuln_id="GHSA-qwer-tyui-opas", severity="MODERATE"),
            Finding(purl="pkg:deb/debian/openssl", vuln_id="DEBIAN-CVE-2026-1", severity="HIGH"),
        ],
    )

    cli_module._print_report(report)  # must not raise
    recorded.file.close()

    rendered = (tmp_path / "out.txt").read_text(encoding="utf-8")
    assert "MEDIUM" in rendered, "MODERATE should be shown under its CVSS band"
    assert "MODERATE" not in rendered
