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

from .models import Component, Snapshot
from .store import utcnow


@dataclass
class IngestResult:
    """A parsed snapshot plus the honesty counters."""

    snapshot: Snapshot
    unmapped: list[str] = field(default_factory=list)
    """Component names that carried no PURL and were therefore not evaluated."""

    @property
    def coverage(self) -> float:
        """Fraction of components that could be mapped to a PURL."""
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
    """Strip qualifiers that split one component into several.

    ``pkg:deb/debian/zlib1g@1.2.13?arch=amd64`` and the ``arch=arm64`` build are
    the same package for vulnerability purposes; keeping the qualifier would make
    an image that changed architecture look like it replaced its entire
    inventory. The subpath after ``#`` is dropped for the same reason.
    """
    return purl.split("?", 1)[0].split("#", 1)[0]


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

    for package in parser.get_packages() or []:
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
    return IngestResult(snapshot=snapshot, unmapped=unmapped)


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
