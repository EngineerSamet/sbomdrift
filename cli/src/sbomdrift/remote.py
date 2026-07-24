# SPDX-License-Identifier: Apache-2.0
"""Carry the history between ephemeral CI runners, via S3.

This module answers the question the whole design depends on and that is easy to
miss: **where does the memory live?** A GitHub runner is destroyed after every
job, so a drift tool whose database lives on the runner has no history and no
product. The alternatives were weighed and rejected:

* commit the database to the repository — diffable, but a binary blob churning
  on every run;
* the Actions cache — evicted after 7 days, which is fatal for a tool whose
  entire value is remembering longer than that;
* build artifacts — retained 90 days, but awkward to read back mid-workflow.

An S3 object has none of those limits, costs pennies, and — importantly for the
"no server" positioning — a bucket is not a server. Credentials come from the
standard AWS chain, which in CI means short-lived OIDC credentials, never a
stored key.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


class RemoteError(RuntimeError):
    """Raised when the remote store cannot be used."""


def parse_s3_uri(uri: str) -> tuple[str, str]:
    """Split ``s3://bucket/key`` into its parts."""
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc:
        raise RemoteError(f"not an s3:// URI: {uri}")
    key = parsed.path.lstrip("/")
    if not key:
        raise RemoteError(f"missing object key in {uri}")
    return parsed.netloc, key


def _client():
    """Import boto3 lazily so the base install stays cloud-free."""
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - exercised by the extra
        raise RemoteError(
            "S3 support needs the optional dependency: pip install 'sbomdrift[s3]'"
        ) from exc
    return boto3.client("s3")


def pull(uri: str, destination: str | Path) -> bool:
    """Download the drift database, returning False when it does not exist yet.

    A missing object is the normal first run, not an error — the caller starts
    with an empty database and pushes it at the end.
    """
    bucket, key = parse_s3_uri(uri)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    client = _client()
    try:
        client.download_file(bucket, key, str(destination))
    except Exception as exc:  # boto3 raises ClientError; keep the import lazy
        if "404" in str(exc) or "Not Found" in str(exc) or "NoSuchKey" in str(exc):
            return False
        raise RemoteError(f"could not pull {uri}: {exc}") from exc
    return True


def push(source: str | Path, uri: str) -> None:
    """Upload the drift database back to S3."""
    bucket, key = parse_s3_uri(uri)
    source = Path(source)
    if not source.exists():
        raise RemoteError(f"nothing to push: {source} does not exist")

    client = _client()
    try:
        client.upload_file(str(source), bucket, key)
    except Exception as exc:
        raise RemoteError(f"could not push to {uri}: {exc}") from exc
