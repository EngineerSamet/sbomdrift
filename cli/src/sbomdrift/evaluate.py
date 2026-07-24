# SPDX-License-Identifier: Apache-2.0
"""Ask the oracle about a snapshot, and record the answer as an evaluation.

The interesting parameter is ``as_of``. With it, the evaluation only counts
advisories that OSV says were **published on or before that date**, which
reconstructs what a scan would have known then — without waiting a month for
real time to pass. That is what makes time drift demonstrable on day one, and
what makes drift deterministic enough for a test suite to assert an exact diff.

Its honest limits are enforced in code rather than left in a docstring:

* an advisory with **no publication date** cannot be placed in time, so under
  ``as_of`` it is excluded and counted in ``undated_excluded`` — never silently
  swept into either bucket;
* OSV records are *amended* after publication, so ``as_of`` reconstructs when an
  advisory became known, not the precise payload the API would have served that
  day. Stated in the report, stated in the README, not glossed over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .models import Evaluation, Finding, Snapshot
from .osv import OSVClient
from .store import Store, utcnow


@dataclass
class EvaluationResult:
    """An evaluation plus the counters that make the run auditable."""

    evaluation: Evaluation
    queried_components: int = 0
    hydrated: int = 0
    cache_hits: int = 0
    undated_excluded: int = 0
    """Advisories skipped under ``--as-of`` because OSV gave them no date."""

    filtered_by_date: int = 0
    """Advisories skipped under ``--as-of`` because they were published later."""

    notes: list[str] = field(default_factory=list)


def evaluate_snapshot(
    store: Store,
    snapshot: Snapshot,
    client: OSVClient,
    as_of: datetime | None = None,
    label: str | None = None,
) -> EvaluationResult:
    """Evaluate one snapshot and persist the resulting findings.

    The cache is consulted before the network, so a fleet whose images share base
    layers hydrates each advisory exactly once, and a re-evaluation at a
    different ``--as-of`` costs no HTTP traffic at all.
    """
    if snapshot.id is None:
        raise ValueError("snapshot must be stored before it can be evaluated")

    purls = [component.purl for component in snapshot.components]
    hits = client.query_batch(purls)

    vuln_ids = {vuln_id for ids in hits.values() for vuln_id in ids}
    cached = store.cached_vulns(vuln_ids)
    missing = [vuln_id for vuln_id in vuln_ids if vuln_id not in cached]

    if missing:
        fetched = client.hydrate(missing)
        store.cache_vulns(fetched)
        cached.update({record["vuln_id"]: record for record in fetched})

    findings: list[Finding] = []
    undated = 0
    filtered = 0

    for purl, ids in hits.items():
        for vuln_id in ids:
            record = cached.get(vuln_id)
            if record is None:
                continue
            published = record.get("published")
            if as_of is not None:
                if published is None:
                    undated += 1
                    continue
                if published > as_of:
                    filtered += 1
                    continue
            findings.append(
                Finding(
                    purl=purl,
                    vuln_id=vuln_id,
                    severity=record.get("severity") or "UNKNOWN",
                    summary=record.get("summary") or "",
                    published=published,
                    modified=record.get("modified"),
                )
            )

    evaluation = Evaluation(
        snapshot_id=snapshot.id,
        evaluated_at=utcnow(),
        oracle="osv.dev",
        as_of=as_of,
        label=label,
        findings=sorted(findings, key=lambda f: (f.purl, f.vuln_id)),
    )
    store.add_evaluation(evaluation)

    result = EvaluationResult(
        evaluation=evaluation,
        queried_components=len(purls),
        hydrated=len(missing),
        cache_hits=len(vuln_ids) - len(missing),
        undated_excluded=undated,
        filtered_by_date=filtered,
    )
    if as_of is not None and undated:
        result.notes.append(
            f"{undated} advisory reference(s) had no publication date in OSV and were "
            f"excluded from the --as-of {as_of.date()} view rather than assumed"
        )
    return result
