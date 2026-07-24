# SPDX-License-Identifier: Apache-2.0
"""Turn an SBOM file into a :class:`~sbomdrift.models.Snapshot`.

Parsing is delegated to ``lib4sbom``, which reads both CycloneDX and SPDX in
either JSON or tag-value form. Hand-rolling that was never worth it: the two
specifications disagree in enough small ways that a home-made parser becomes a
maintenance tax paid forever, for no differentiating value.

What this module *does* own is the part that matters to drift: reducing a
document to a set of **Package URLs**. The PURL is the only identifier that
survives the trip from SBOM to vulnerability oracle unchanged, so a component
without one cannot be evaluated — and rather than quietly dropping those, the
count is surfaced (see :class:`IngestResult.unmapped`) because "we checked 412
of 480 components" is a materially different claim from "we checked everything".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from lib4sbom.parser import SBOMParser

from .models import Component, Snapshot, normalise_purl_case
from .store import utcnow

NON_PACKAGE_TYPES = frozenset({"FILE", "DEVICE", "FIRMWARE", "DATA", "MACHINE-LEARNING-MODEL"})
"""CycloneDX component types that describe something other than a package.

Syft catalogues individual *files* alongside packages — a ``python:3.11-slim``
SBOM contains 483 of them against 130 packages. They carry no PURL because there
is no such thing as a PURL for ``/etc/apt/apt.conf.d/01autoremove``, so counting
them as "components we failed to map" reported 22% coverage for an ingest that
had in fact mapped nearly everything there was to map. They are skipped, not
counted as failures.
"""


@dataclass
class IngestResult:
    """A parsed snapshot plus the honesty counters."""

    snapshot: Snapshot
    unmapped: list[str] = field(default_factory=list)
    """Package names that carried no PURL and therefore cannot be evaluated."""

    skipped_non_packages: int = 0
    """Entries that are not packages at all (files, devices) and were ignored."""

    @property
    def coverage(self) -> float:
        """Fraction of *packages* that could be mapped to a PURL.

        Deliberately excludes non-package entries from the denominator: coverage
        is meant to answer "how much of this SBOM could we actually check?", and
        a file entry was never checkable in the first place.
        """
        total = len(self.snapshot.components) + len(self.unmapped)
        return len(self.snapshot.components) / total if total else 1.0


def _purl_of(package: dict) -> str | None:
    """Pull the PURL out of a lib4sbom package record.

    lib4sbom normalises external references into ``[category, type, locator]``
    triples rather than keeping a ``purl`` key, so both shapes are accepted:
    the flat key (some producers) and the triple (CycloneDX and SPDX as parsed).
    """
    direct = package.get("purl")
    if isinstance(direct, str) and direct.startswith("pkg:"):
        return direct

    for reference in package.get("externalreference") or []:
        if len(reference) >= 3 and str(reference[1]).lower() == "purl":
            locator = str(reference[2])
            if locator.startswith("pkg:"):
                return locator
    return None


def _canonical_purl(purl: str) -> str:
    """Reduce a PURL to the form used everywhere downstream.

    Two normalisations, each fixing a real double-count seen in Syft output:

    *Qualifiers are stripped.* ``pkg:deb/debian/zlib1g@1.2.13?arch=amd64`` and the
    ``arch=arm64`` build are the same package for vulnerability purposes; keeping
    the qualifier would make an image that changed architecture look like it had
    replaced its entire inventory. The ``#subpath`` goes for the same reason.

    *Type and namespace are lower-cased.* One ``python:3.11-slim`` SBOM contains
    both ``pkg:deb/debian/...`` and ``pkg:deb/Debian/...``; the PURL specification
    makes those the same package, so string equality has to agree.
    """
    base = purl.split("?", 1)[0].split("#", 1)[0]
    name, separator, version = base.rpartition("@")
    if not separator:
        return normalise_purl_case(base)
    return f"{normalise_purl_case(name)}@{version}"


def _artefact_and_digest(path: Path, document: dict) -> tuple[str, str | None]:
    """Derive the artefact identity and, if the SBOM records one, the image digest.

    Identity has to be stable across versions — drift is only meaningful within
    one artefact — so the *name* is used and the version deliberately is not.
    """
    name = document.get("name") or path.stem
    digest = None

    # Syft records the image digest in the metadata component of a CycloneDX
    # document; read it straight from the file since lib4sbom does not expose it.
    if path.suffix == ".json":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return str(name), None
        component = (raw.get("metadata") or {}).get("component") or {}
        for prop in component.get("properties") or []:
            if prop.get("name", "").endswith("imageID") or "digest" in prop.get("name", "").lower():
                digest = prop.get("value")
                break
        if digest is None:
            for hash_entry in component.get("hashes") or []:
                if hash_entry.get("alg") in {"SHA-256", "SHA256"}:
                    digest = f"sha256:{hash_entry.get('content')}"
                    break

    return str(name), digest


def ingest_file(
    path: str | Path,
    artefact: str | None = None,
    digest: str | None = None,
) -> IngestResult:
    """Parse one SBOM file into a snapshot.

    :param artefact: overrides the identity taken from the document, which is
        what you want when the SBOM's own metadata is generic (``syft`` names a
        directory scan after the directory).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)

    parser = SBOMParser()
    parser.parse_file(str(path))

    document = parser.get_document() or {}
    detected_artefact, detected_digest = _artefact_and_digest(path, document)

    components: dict[str, Component] = {}
    unmapped: list[str] = []
    skipped = 0

    for package in parser.get_packages() or []:
        if str(package.get("type", "")).upper() in NON_PACKAGE_TYPES:
            skipped += 1
            continue
        purl = _purl_of(package)
        name = package.get("name", "")
        if not purl:
            unmapped.append(name or "<unnamed>")
            continue
        canonical = _canonical_purl(purl)
        components.setdefault(
            canonical,
            Component(purl=canonical, name=name, version=package.get("version", "")),
        )

    snapshot = Snapshot(
        artefact=artefact or detected_artefact,
        source=str(path),
        ingested_at=utcnow(),
        components=sorted(components.values(), key=lambda c: c.purl),
        digest=digest or detected_digest,
        sbom_format=parser.get_type(),
    )
    return IngestResult(snapshot=snapshot, unmapped=unmapped, skipped_non_packages=skipped)


def ingest_directory(
    directory: str | Path,
    artefact: str | None = None,
    pattern: str = "*.json",
) -> list[IngestResult]:
    """Ingest every SBOM in a directory — the shape a CI job produces."""
    directory = Path(directory)
    results = []
    for path in sorted(directory.glob(pattern)):
        results.append(ingest_file(path, artefact=artefact))
    return results
