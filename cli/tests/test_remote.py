# SPDX-License-Identifier: Apache-2.0
"""S3 round-trip, with a stand-in for boto3.

The one behaviour worth protecting: a **missing** object is the normal first run,
not a failure. Getting that wrong makes every fresh pipeline red on day one.
"""

from __future__ import annotations

import pytest

from sbomdrift import remote
from sbomdrift.remote import RemoteError, parse_s3_uri


class FakeS3:
    def __init__(self, existing: dict[tuple[str, str], bytes] | None = None):
        self.objects = existing or {}
        self.uploads: list[tuple[str, str]] = []

    def download_file(self, bucket: str, key: str, destination: str) -> None:
        if (bucket, key) not in self.objects:
            raise RuntimeError("An error occurred (404) when calling HeadObject: Not Found")
        with open(destination, "wb") as handle:
            handle.write(self.objects[(bucket, key)])

    def upload_file(self, source: str, bucket: str, key: str) -> None:
        with open(source, "rb") as handle:
            self.objects[(bucket, key)] = handle.read()
        self.uploads.append((bucket, key))


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("s3://bucket/drift/history.db", ("bucket", "drift/history.db")),
        ("s3://bucket/nested/path/db.sqlite", ("bucket", "nested/path/db.sqlite")),
    ],
)
def test_parse_s3_uri(uri, expected):
    assert parse_s3_uri(uri) == expected


@pytest.mark.parametrize("uri", ["https://bucket/key", "s3://bucket", "s3:///key", "bucket/key"])
def test_bad_uris_are_rejected(uri):
    with pytest.raises(RemoteError):
        parse_s3_uri(uri)


def test_pull_returns_false_when_no_history_exists_yet(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_client", lambda: FakeS3())
    assert remote.pull("s3://bucket/drift/history.db", tmp_path / "drift.db") is False


def test_pull_writes_the_database(tmp_path, monkeypatch):
    fake = FakeS3({("bucket", "drift/history.db"): b"SQLite format 3\x00"})
    monkeypatch.setattr(remote, "_client", lambda: fake)

    destination = tmp_path / "nested" / "drift.db"
    assert remote.pull("s3://bucket/drift/history.db", destination) is True
    assert destination.read_bytes().startswith(b"SQLite format 3")


def test_push_uploads_and_round_trips(tmp_path, monkeypatch):
    fake = FakeS3()
    monkeypatch.setattr(remote, "_client", lambda: fake)

    source = tmp_path / "drift.db"
    source.write_bytes(b"payload")
    remote.push(source, "s3://bucket/drift/history.db")

    assert fake.uploads == [("bucket", "drift/history.db")]
    assert remote.pull("s3://bucket/drift/history.db", tmp_path / "back.db") is True


def test_pushing_a_missing_file_is_an_explicit_error(tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_client", lambda: FakeS3())
    with pytest.raises(RemoteError):
        remote.push(tmp_path / "absent.db", "s3://bucket/key")


def test_transport_failures_are_wrapped_not_leaked(tmp_path, monkeypatch):
    class Broken(FakeS3):
        def download_file(self, *args):
            raise RuntimeError("An error occurred (403) when calling HeadObject: Forbidden")

    monkeypatch.setattr(remote, "_client", lambda: Broken())
    with pytest.raises(RemoteError):
        remote.pull("s3://bucket/key", tmp_path / "drift.db")
