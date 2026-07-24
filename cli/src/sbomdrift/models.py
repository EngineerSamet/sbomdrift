# SPDX-License-Identifier: Apache-2.0
"""Domain objects.

Three nouns carry the whole product:

``Snapshot``    what an artefact contained at one moment (an ingested SBOM).
``Evaluation``  the act of asking the oracle about a snapshot, at a point in time.
``Finding``     one (component, vulnerability) pair belonging to one evaluation.

Drift is always a diff between two *evaluations*, never between two scans. That
single choice is what lets the same code express both kinds of drift:

* **version drift** — two snapshots (different digests), evaluated at the same time
* **time drift**    — one snapshot, evaluated as of two different dates
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_ORDER = ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(severity: str) -> int:
    """Order severities so they can be compared and thresholded."""
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return 0


def purl_identity(purl: str) -> str:
    """The versionless PURL — what a component *is*, independent of which release.

    This distinction is load-bearing and was learned the hard way. Keying drift on
    the full versioned PURL made an upgrade unreadable: comparing two releases of
    ``python:3.11-slim`` produced "114 components removed, 115 added, 0 unchanged",
    because ``openssl@1.1.1n`` and ``openssl@3.5.6`` are different strings. Every
    finding was simultaneously new and fixed, which is churn, not drift.

    Identity is the package; version is an attribute of it. With that split,
    "openssl was upgraded and CVE-2022-4899 went away" is expressible.
    """
    base = purl.split("?", 1)[0].split("#", 1)[0]
    name, _, _version = base.rpartition("@") if "@" in base else (base, "", "")
    return normalise_purl_case(name or base)


def purl_version(purl: str) -> str:
    """The version component of a PURL, or an empty string when it carries none."""
    base = purl.split("?", 1)[0].split("#", 1)[0]
    _, separator, version = base.rpartition("@")
    return version if separator else ""


def normalise_purl_case(purl_name: str) -> str:
    """Lower-case the parts of a PURL that the specification defines as case-insensitive.

    Syft emits both ``pkg:deb/debian/...`` and ``pkg:deb/Debian/...`` in the same
    document. Left alone, those are two components, and one image appears to
    contain the same package twice.
    """
    parts = purl_name.split("/")
    if parts:
        parts[0] = parts[0].lower()  # the "pkg:type" prefix
    if len(parts) > 2:
        parts[1] = parts[1].lower()  # the namespace
    return "/".join(parts)


@dataclass(frozen=True)
class Component:
    """One software component, identified by its Package URL.

    The PURL is the join key across the whole system: it is what the SBOM gives
    us and what OSV.dev accepts, so no name/ecosystem translation table is needed.
    """

    purl: str
    name: str
    version: str

    @property
    def ecosystem(self) -> str:
        """Best-effort ecosystem from the PURL type, e.g. ``pkg:pypi/x`` -> ``pypi``."""
        if not self.purl.startswith("pkg:"):
            return "unknown"
        return self.purl[4:].split("/", 1)[0]

    @property
    def identity(self) -> str:
        """This component regardless of version — the key drift is measured on."""
        return purl_identity(self.purl)


@dataclass
class Snapshot:
    """The component inventory of one artefact at one moment."""

    artefact: str
    """Logical identity that persists across versions, e.g. ``python:3.11-slim``.

    Drift is only meaningful *within* an artefact: comparing nginx to postgres is
    not drift, it is a different program.
    """

    source: str
    """Where the SBOM came from — a file path, an ECR reference, or ``syft:<image>``."""

    ingested_at: datetime
    components: list[Component] = field(default_factory=list)
    digest: str | None = None
    sbom_format: str | None = None
    id: int | None = None

    def __len__(self) -> int:
        return len(self.components)


@dataclass
class Finding:
    """One vulnerability affecting one component within one evaluation."""

    purl: str
    vuln_id: str
    severity: str = "UNKNOWN"
    summary: str = ""
    published: datetime | None = None
    modified: datetime | None = None
    id: int | None = None

    @property
    def key(self) -> tuple[str, str]:
        """Identity used when diffing. A finding is the *pair*, not the CVE alone.

        The same CVE affecting two different components is two findings: fixing
        one of them is real progress and must show up in the diff. The package
        side of the pair is versionless (see :func:`purl_identity`) so that
        upgrading a package reads as "this finding went away", not as "the whole
        component was replaced".
        """
        return (purl_identity(self.purl), self.vuln_id)


@dataclass
class Evaluation:
    """One run of the oracle against one snapshot."""

    snapshot_id: int
    evaluated_at: datetime
    oracle: str = "osv.dev"
    as_of: datetime | None = None
    """If set, only vulnerabilities published on or before this date were counted."""

    label: str | None = None
    findings: list[Finding] = field(default_factory=list)
    id: int | None = None
