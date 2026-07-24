# SPDX-License-Identifier: Apache-2.0
"""The oracle client — batching, severity extraction, and failure behaviour."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from sbomdrift.osv import MAX_BATCH, OSVClient, OSVError, extract_severity, normalise_record


def test_query_batch_maps_every_purl_including_the_clean_ones(mock_osv):
    with OSVClient() as client:
        hits = client.query_batch(
            ["pkg:pypi/requests@2.31.0", "pkg:pypi/urllib3@2.0.7", "pkg:pypi/clean@1.0"]
        )

    assert hits["pkg:pypi/urllib3@2.0.7"] == ["CVE-2026-1111"]
    # "asked and clean" must be distinguishable from "never asked"
    assert hits["pkg:pypi/clean@1.0"] == []
    assert client.stats.batch_requests == 1


def test_two_thousand_components_cost_two_calls_not_two_thousand():
    """The scalability property the whole design rests on."""
    purls = [f"pkg:pypi/pkg{i}@1.0" for i in range(MAX_BATCH + 500)]

    def empty_results(request: httpx.Request) -> httpx.Response:
        queries = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{} for _ in queries]})

    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://api.osv.dev/v1/querybatch").mock(side_effect=empty_results)
        with OSVClient() as client:
            hits = client.query_batch(purls)

    assert route.call_count == 2
    assert len(hits) == len(purls)


def test_hydrate_deduplicates_ids(mock_osv):
    with OSVClient() as client:
        records = client.hydrate(["GHSA-old-0001", "GHSA-old-0001", "CVE-2026-1111"])

    assert [r["vuln_id"] for r in records] == ["GHSA-old-0001", "CVE-2026-1111"]
    assert client.stats.detail_requests == 2


def test_server_errors_are_retried_then_give_up():
    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(503)
        )
        with OSVClient(max_retries=2) as client:
            # Backoff sleeps are real but short at max_retries=2.
            with pytest.raises(OSVError):
                client.query_batch(["pkg:pypi/x@1"])

    assert route.call_count == 2


def test_client_errors_are_not_retried():
    """Retrying a malformed query just produces the same rejection more slowly."""
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__regex=r".+/v1/vulns/.+").mock(return_value=httpx.Response(404))
        with OSVClient(max_retries=4) as client, pytest.raises(OSVError):
            client.hydrate(["NOPE-1"])

    assert route.call_count == 1


# ------------------------------------------------------------------- severity

def test_cvss_vector_is_preferred_over_a_declared_label():
    record = {
        "id": "X",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "LOW"},
    }
    assert extract_severity(record) == "CRITICAL"


def test_database_specific_severity_is_the_fallback():
    """Note the expected value: MEDIUM, not MODERATE.

    This assertion used to read ``== "MODERATE"``, faithfully pinning what the
    code did -- pass GitHub's own word straight through. That was the defect, not
    the contract: downstream, MODERATE matched no CVSS band, ranked alongside
    UNKNOWN, and let a MEDIUM gate pass a moderate finding. The test was green
    throughout, because it had been written from the same misunderstanding as the
    code it was checking.
    """
    record = {"id": "X", "database_specific": {"severity": "moderate"}}
    assert extract_severity(record) == "MEDIUM"


def test_affected_level_severity_is_read_when_the_top_level_has_none():
    record = {"id": "X", "affected": [{"database_specific": {"severity": "High"}}]}
    assert extract_severity(record) == "HIGH"


def test_missing_severity_stays_unknown_rather_than_being_invented():
    """Most Debian and Alpine advisories genuinely carry no severity."""
    assert extract_severity({"id": "X"}) == "UNKNOWN"


def test_normalise_truncates_long_summaries_and_parses_dates():
    record = normalise_record(
        {
            "id": "CVE-2026-1111",
            "details": "x" * 900,
            "published": "2026-05-20T00:00:00Z",
            "modified": "2026-05-21T00:00:00Z",
        }
    )
    assert record["vuln_id"] == "CVE-2026-1111"
    assert len(record["summary"]) == 500
    assert record["published"].year == 2026
