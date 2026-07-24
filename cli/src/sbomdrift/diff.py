# SPDX-License-Identifier: Apache-2.0
"""The diff — the only thing here a one-shot scanner cannot produce.

A drift report is computed between two **evaluations**, and that single choice
is what lets one implementation express both kinds of drift:

* two snapshots evaluated at the same time  → *version drift* (the artefact moved)
* one snapshot evaluated at two dates       → *time drift* (the world moved)

Findings are keyed on ``(purl, vuln_id)`` rather than on the vulnerability alone.
The same CVE affecting two components is two findings: patching one of them is
genuine progress and has to appear in the report, not be masked by the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Evaluation, Finding, normalise_severity, severity_rank
from .store import Store


@dataclass
class DriftReport:
    """What changed between two evaluations."""

    from_evaluation: Evaluation
    to_evaluation: Evaluation
    newly_vulnerable: list[Finding] = field(default_factory=list)
    newly_fixed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    added_components: list[str] = field(default_factory=list)
    removed_components: list[str] = field(default_factory=list)
    upgraded_components: list[tuple[str, str, str]] = field(default_factory=list)
    """``(identity, old version, new version)`` for components present in both."""

    @property
    def is_clean(self) -> bool:
        """True when nothing at all changed between the two evaluations."""
        return not (
            self.newly_vulnerable
            or self.newly_fixed
            or self.added_components
            or self.removed_components
            or self.upgraded_components
        )

    @property
    def kind(self) -> str:
        """Name the drift, since the two kinds are read very differently."""
        same_snapshot = self.from_evaluation.snapshot_id == self.to_evaluation.snapshot_id
        if same_snapshot:
            return "time drift"
        return "version drift"

    def max_new_severity(self) -> str:
        """Highest severity among *newly* vulnerable findings, as a CVSS band.

        Normalised on the way out: this string is printed and compared against
        thresholds, so returning a database's own word here would reintroduce the
        vocabulary mismatch one layer further up.
        """
        if not self.newly_vulnerable:
            return "NONE"
        return normalise_severity(
            max((f.severity for f in self.newly_vulnerable), key=severity_rank)
        )

    def exceeds(self, threshold: str) -> bool:
        """Whether new drift reaches a severity threshold — the CI gate condition.

        Deliberately blind to ``unchanged``: a pipeline that fails on the backlog
        it already knew about gets muted within a week, and a muted gate protects
        nothing. Only *new* risk breaks the build.
        """
        limit = severity_rank(threshold)
        return any(severity_rank(f.severity) >= limit for f in self.newly_vulnerable)

    def counts_by_severity(self, findings: list[Finding] | None = None) -> dict[str, int]:
        """Severity histogram, used by the terminal table and the report figures.

        Bucketed under the normalised label so that a GitHub advisory's MODERATE
        is counted as MEDIUM rather than opening a seventh column nobody reads.
        """
        source = self.newly_vulnerable if findings is None else findings
        counts: dict[str, int] = {}
        for finding in source:
            label = normalise_severity(finding.severity)
            counts[label] = counts.get(label, 0) + 1
        return counts


def compute_drift(store: Store, from_ref: int | str, to_ref: int | str) -> DriftReport:
    """Build the drift report between two stored evaluations."""
    before = store.get_evaluation(from_ref)
    after = store.get_evaluation(to_ref)
    if before is None:
        raise LookupError(f"no evaluation {from_ref!r}")
    if after is None:
        raise LookupError(f"no evaluation {to_ref!r}")

    before_keys = {f.key: f for f in before.findings}
    after_keys = {f.key: f for f in after.findings}

    report = DriftReport(
        from_evaluation=before,
        to_evaluation=after,
        newly_vulnerable=[f for key, f in after_keys.items() if key not in before_keys],
        newly_fixed=[f for key, f in before_keys.items() if key not in after_keys],
        unchanged=[f for key, f in after_keys.items() if key in before_keys],
    )

    if before.snapshot_id != after.snapshot_id:
        # Compared on versionless identity, so an upgrade is an upgrade rather
        # than a removal plus an unrelated addition.
        before_components = {c.identity: c.version for c in store.components(before.snapshot_id)}
        after_components = {c.identity: c.version for c in store.components(after.snapshot_id)}

        report.added_components = sorted(set(after_components) - set(before_components))
        report.removed_components = sorted(set(before_components) - set(after_components))
        report.upgraded_components = sorted(
            (identity, before_components[identity], after_components[identity])
            for identity in set(before_components) & set(after_components)
            if before_components[identity] != after_components[identity]
        )

    report.newly_vulnerable.sort(key=lambda f: (-severity_rank(f.severity), f.purl, f.vuln_id))
    report.newly_fixed.sort(key=lambda f: (-severity_rank(f.severity), f.purl, f.vuln_id))
    return report
