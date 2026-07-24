# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures.

Every test in this suite is offline. The oracle is mocked with recorded response
shapes, which is not merely faster — it is what makes the assertions *exact*.
A test that queried the live OSV.dev API would change its answer whenever a new
advisory was published, so it could only ever assert "more than zero findings",
which is not a test of drift at all.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sbomdrift.models import Component, Snapshot
from sbomdrift.store import Store

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def store(tmp_path: Path) -> Store:
    """A throwaway database per test."""
    with Store(tmp_path / "drift.db") as store:
        yield store


@pytest.fixture
def sbom_path(tmp_path: Path) -> Path:
    """A small but realistic CycloneDX document written to disk."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "container", "name": "demo-app", "version": "1.0.0"}
        },
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
            {
                "type": "library",
                "name": "urllib3",
                "version": "2.0.7",
                "purl": "pkg:pypi/urllib3@2.0.7",
            },
            {
                "type": "library",
                "name": "zlib1g",
                "version": "1:1.2.13.dfsg-1",
                # Qualifiers must be stripped, or an architecture change would
                # read as a wholesale replacement of the inventory.
                "purl": "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=amd64&distro=debian-12",
            },
            {
                # No PURL: must be counted as unmapped, never silently dropped.
                "type": "library",
                "name": "vendored-blob",
                "version": "0.1",
            },
        ],
    }
    path = tmp_path / "demo.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.fixture
def stored_snapshot(store: Store) -> Snapshot:
    """A snapshot already in the database, ready to evaluate."""
    snapshot = Snapshot(
        artefact="demo-app",
        source="tests",
        ingested_at=datetime(2026, 7, 1, tzinfo=UTC),
        components=[
            Component("pkg:pypi/requests@2.31.0", "requests", "2.31.0"),
            Component("pkg:pypi/urllib3@2.0.7", "urllib3", "2.0.7"),
        ],
    )
    store.add_snapshot(snapshot)
    return snapshot


# --------------------------------------------------------------- oracle payloads

OSV_VULNS: dict[str, dict] = {
    # Published well before any cutoff used in the tests: always visible.
    "GHSA-old-0001": {
        "id": "GHSA-old-0001",
        "summary": "Old but still present issue in requests",
        "published": "2025-01-15T00:00:00Z",
        "modified": "2025-02-01T00:00:00Z",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        ],
    },
    # Published between the two cutoffs: this is the drift the tests assert on.
    "CVE-2026-1111": {
        "id": "CVE-2026-1111",
        "summary": "Newly disclosed flaw in urllib3",
        "published": "2026-05-20T00:00:00Z",
        "modified": "2026-05-21T00:00:00Z",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
    },
    # No publication date at all: must be excluded under --as-of and counted.
    "DSA-undated": {
        "id": "DSA-undated",
        "summary": "Distribution advisory with no publication date",
        "modified": "2026-06-01T00:00:00Z",
        "database_specific": {"severity": "MEDIUM"},
    },
}

OSV_HITS: dict[str, list[str]] = {
    "pkg:pypi/requests@2.31.0": ["GHSA-old-0001", "DSA-undated"],
    "pkg:pypi/urllib3@2.0.7": ["CVE-2026-1111"],
}


@pytest.fixture
def mock_osv():
    """Serve the recorded oracle payloads for both endpoints.

    The router is built explicitly rather than via the ``respx_mock`` fixture so
    that ``assert_all_called`` can be relaxed: several tests legitimately never
    reach the hydrate endpoint because the vulnerability cache already answered.
    """
    import httpx
    import respx

    def querybatch(request: httpx.Request) -> httpx.Response:
        queries = json.loads(request.content)["queries"]
        results = []
        for query in queries:
            purl = query["package"]["purl"]
            ids = OSV_HITS.get(purl, [])
            results.append(
                {"vulns": [{"id": i, "modified": OSV_VULNS[i].get("modified")} for i in ids]}
                if ids
                else {}
            )
        return httpx.Response(200, json={"results": results})

    def vuln(request: httpx.Request) -> httpx.Response:
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        if vuln_id not in OSV_VULNS:
            return httpx.Response(404, json={"message": "not found"})
        return httpx.Response(200, json=OSV_VULNS[vuln_id])

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.osv.dev/v1/querybatch").mock(side_effect=querybatch)
        router.get(url__regex=r"https://api\.osv\.dev/v1/vulns/.+").mock(side_effect=vuln)
        yield router
