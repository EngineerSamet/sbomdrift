# SPDX-License-Identifier: Apache-2.0
"""OSV.dev client — the vulnerability oracle.

Two endpoints do all the work:

``POST /v1/querybatch``
    Takes up to 1000 package queries at once and answers with vulnerability
    *identifiers only*. Cheap, and the reason a 2000-component SBOM costs two
    HTTP calls instead of two thousand.

``GET /v1/vulns/{id}``
    Hydrates one identifier into a full record (summary, severity, publication
    dates). Only ever called for the identifiers the batch actually returned,
    and the results are cached in SQLite, so a fleet that shares base layers
    hydrates each advisory once.

The first draft of this design queried one component at a time. On a fleet of
twenty images that is tens of thousands of round-trips for information the batch
endpoint returns in a handful — the kind of mistake that only shows up at scale,
which is exactly why it is worth writing down.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import httpx

from .cvss import severity_from_vector
from .store import from_iso

DEFAULT_BASE_URL = "https://api.osv.dev"
MAX_BATCH = 1000
"""OSV's documented ceiling for ``querybatch``."""


class OSVError(RuntimeError):
    """Raised when the oracle cannot be reached or answers unusably."""


@dataclass
class OSVStats:
    """Call counters, so the report can quote real numbers rather than estimates."""

    batch_requests: int = 0
    detail_requests: int = 0
    cache_hits: int = 0
    seconds: float = 0.0


class OSVClient:
    """Minimal, retrying HTTP client for the OSV.dev API."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        max_retries: int = 4,
        batch_size: int = MAX_BATCH,
    ):
        self.base_url = base_url.rstrip("/")
        self.batch_size = min(batch_size, MAX_BATCH)
        self.max_retries = max_retries
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)
        self.stats = OSVStats()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> OSVClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------ requests

    def _request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        """Issue one request, retrying transient failures with exponential backoff.

        429 and 5xx are retried; 4xx other than 429 are not, because retrying a
        malformed query just produces the same rejection more slowly.
        """
        delay = 1.0
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = self._client.request(method, url, **kwargs)  # type: ignore[arg-type]
                if response.status_code == 429 or response.status_code >= 500:
                    last_error = OSVError(f"{response.status_code} from {url}")
                else:
                    response.raise_for_status()
                    return response
            except httpx.HTTPStatusError as exc:
                raise OSVError(f"{exc.response.status_code} from {url}") from exc
            except httpx.HTTPError as exc:
                last_error = exc
            if attempt < self.max_retries - 1:
                time.sleep(delay)
                delay *= 2
        raise OSVError(f"giving up on {url} after {self.max_retries} attempts") from last_error

    # -------------------------------------------------------------------- query

    def query_batch(self, purls: Sequence[str]) -> dict[str, list[str]]:
        """Map every PURL to the vulnerability ids affecting it.

        PURLs with no vulnerabilities are present in the result with an empty
        list — "asked and clean" is different from "never asked", and the diff
        depends on being able to tell them apart.
        """
        results: dict[str, list[str]] = {purl: [] for purl in purls}
        started = time.monotonic()

        for chunk_start in range(0, len(purls), self.batch_size):
            chunk = purls[chunk_start : chunk_start + self.batch_size]
            payload = {"queries": [{"package": {"purl": purl}} for purl in chunk]}
            response = self._request("POST", f"{self.base_url}/v1/querybatch", json=payload)
            self.stats.batch_requests += 1

            body = response.json()
            for purl, result in zip(chunk, body.get("results", []), strict=False):
                vulns = result.get("vulns") or []
                results[purl] = [v["id"] for v in vulns if "id" in v]
                if result.get("next_page_token"):
                    results[purl] = self._query_all_pages(purl, result["next_page_token"])

        self.stats.seconds += time.monotonic() - started
        return results

    def _query_all_pages(self, purl: str, page_token: str) -> list[str]:
        """Follow pagination for the rare component with more vulns than one page.

        Left in deliberately: a base image with an ancient OpenSSL genuinely
        exceeds a page, and silently truncating there would understate drift.
        """
        ids: list[str] = []
        token: str | None = page_token
        while token:
            payload: dict[str, object] = {"package": {"purl": purl}, "page_token": token}
            response = self._request("POST", f"{self.base_url}/v1/query", json=payload)
            self.stats.batch_requests += 1
            body = response.json()
            ids.extend(v["id"] for v in body.get("vulns", []) if "id" in v)
            token = body.get("next_page_token")
        return ids

    # ------------------------------------------------------------------ hydrate

    def hydrate(self, vuln_ids: Iterable[str]) -> list[dict]:
        """Fetch full records for the given ids and normalise them."""
        started = time.monotonic()
        records = []
        for vuln_id in dict.fromkeys(vuln_ids):  # de-duplicate, keep order
            response = self._request("GET", f"{self.base_url}/v1/vulns/{vuln_id}")
            self.stats.detail_requests += 1
            records.append(normalise_record(response.json()))
        self.stats.seconds += time.monotonic() - started
        return records


def extract_severity(record: dict) -> str:
    """Derive a qualitative severity from an OSV record.

    Preference order, and why:

    1. a **CVSS v3 vector** — computed locally, so the number is reproducible and
       does not depend on which database happened to summarise it;
    2. ``database_specific.severity`` — what GitHub advisories carry;
    3. ``UNKNOWN`` — most Debian and Alpine advisories genuinely have no severity,
       and inventing one would put a fabricated number in a CI gate.
    """
    for entry in record.get("severity") or []:
        score = entry.get("score", "")
        if entry.get("type", "").startswith("CVSS_V3") and score.startswith("CVSS:3"):
            severity = severity_from_vector(score)
            if severity != "UNKNOWN":
                return severity

    database_specific = record.get("database_specific") or {}
    declared = database_specific.get("severity")
    if isinstance(declared, str) and declared.strip():
        return declared.strip().upper()

    for affected in record.get("affected") or []:
        specific = affected.get("database_specific") or {}
        declared = specific.get("severity")
        if isinstance(declared, str) and declared.strip():
            return declared.strip().upper()

    return "UNKNOWN"


def normalise_record(record: dict) -> dict:
    """Flatten an OSV record into the handful of fields the store keeps."""
    return {
        "vuln_id": record.get("id", ""),
        "severity": extract_severity(record),
        "summary": (record.get("summary") or record.get("details") or "")[:500],
        "published": from_iso(record.get("published")),
        "modified": from_iso(record.get("modified")),
    }
