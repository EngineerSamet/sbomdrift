# SPDX-License-Identifier: Apache-2.0
"""Ingestion: SBOM document in, component inventory out."""

from __future__ import annotations

import json

import pytest

from sbomdrift.ingest import _canonical_purl, ingest_file


def test_ingest_reads_components_and_format(sbom_path):
    result = ingest_file(sbom_path)
    purls = {c.purl for c in result.snapshot.components}

    assert result.snapshot.sbom_format == "cyclonedx"
    assert "pkg:pypi/requests@2.31.0" in purls
    assert "pkg:pypi/urllib3@2.0.7" in purls


def test_purl_qualifiers_are_stripped(sbom_path):
    """arch=/distro= qualifiers split one component into many if left in place."""
    result = ingest_file(sbom_path)
    purls = {c.purl for c in result.snapshot.components}

    assert "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1" in purls
    assert not any("?" in purl for purl in purls)


def test_components_without_a_purl_are_reported_not_dropped(sbom_path):
    """'We checked 3 of 4 components' is a different claim from 'we checked everything'."""
    result = ingest_file(sbom_path)

    assert result.unmapped == ["vendored-blob"]
    assert result.coverage == pytest.approx(0.75)


def test_artefact_defaults_to_the_document_and_can_be_overridden(sbom_path):
    assert ingest_file(sbom_path).snapshot.artefact == "demo-app"
    override = ingest_file(sbom_path, artefact="python:3.11-slim")
    assert override.snapshot.artefact == "python:3.11-slim"


def test_duplicate_purls_collapse_to_one_component(tmp_path):
    """The same package listed twice is one component, not two."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "dupes", "version": "1"}},
        "components": [
            {"type": "library", "name": "zlib1g", "version": "1.2.13",
             "purl": "pkg:deb/debian/zlib1g@1.2.13?arch=amd64"},
            {"type": "library", "name": "zlib1g", "version": "1.2.13",
             "purl": "pkg:deb/debian/zlib1g@1.2.13?arch=arm64"},
        ],
    }
    path = tmp_path / "dupes.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    assert len(ingest_file(path).snapshot.components) == 1


def test_file_entries_are_skipped_not_counted_as_failures(tmp_path):
    """Syft catalogues files beside packages; they are not unmapped packages.

    Regression test for a real miscount: a python:3.11-slim SBOM reported 22%
    coverage because its 483 file entries were treated as components we had
    failed to map.
    """
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "container", "name": "img", "version": "1"}},
        "components": [
            {"type": "library", "name": "zlib1g", "version": "1.2.13",
             "purl": "pkg:deb/debian/zlib1g@1.2.13"},
            {"type": "file", "name": "/etc/apt/apt.conf.d/01autoremove"},
            {"type": "file", "name": "/etc/hostname"},
        ],
    }
    path = tmp_path / "img.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    result = ingest_file(path)

    assert len(result.snapshot.components) == 1
    assert result.unmapped == []
    assert result.skipped_non_packages == 2
    assert result.coverage == pytest.approx(1.0)


def test_missing_file_is_an_explicit_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        ingest_file(tmp_path / "nope.json")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("pkg:pypi/requests@2.31.0", "pkg:pypi/requests@2.31.0"),
        ("pkg:deb/debian/zlib1g@1.2?arch=amd64", "pkg:deb/debian/zlib1g@1.2"),
        ("pkg:golang/x/text@v0.3.0#subpath", "pkg:golang/x/text@v0.3.0"),
        # Syft emits both spellings of the namespace in one document.
        ("pkg:deb/Debian/libzstd@1.5.7", "pkg:deb/debian/libzstd@1.5.7"),
        ("pkg:PyPI/Requests@2.31.0", "pkg:pypi/Requests@2.31.0"),
    ],
)
def test_canonical_purl(raw, expected):
    assert _canonical_purl(raw) == expected


def test_case_variants_of_a_namespace_collapse_to_one_component(tmp_path):
    """Regression: 'debian' and 'Debian' listed the same package twice."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "container", "name": "img", "version": "1"}},
        "components": [
            {"type": "library", "name": "libzstd", "version": "1.5.7",
             "purl": "pkg:deb/debian/libzstd@1.5.7"},
            {"type": "library", "name": "libzstd", "version": "1.5.7",
             "purl": "pkg:deb/Debian/libzstd@1.5.7"},
        ],
    }
    path = tmp_path / "case.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    assert len(ingest_file(path).snapshot.components) == 1
