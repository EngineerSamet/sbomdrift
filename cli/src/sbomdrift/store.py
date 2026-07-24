# SPDX-License-Identifier: Apache-2.0
"""Persistence — a single SQLite file.

The memory *is* the product. A scanner without history cannot say what changed,
so the store is not an implementation detail here; it is the feature. SQLite was
chosen over a server because a drift tool that needs a database running beside it
is no longer CI-native, and because a single file is trivially shipped to S3
between ephemeral runners (see :mod:`sbomdrift.remote`).

One table deserves explanation: ``vuln_cache``. Vulnerability records are
immutable enough between runs that re-hydrating them on every evaluation is
wasted bandwidth — but more importantly, caching them is what makes
``eval --as-of`` reproducible offline and therefore unit-testable.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .models import Component, Evaluation, Finding, Snapshot

SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artefact        TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    digest          TEXT,
    sbom_format     TEXT,
    ingested_at     TEXT    NOT NULL,
    component_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_artefact ON snapshots (artefact);

CREATE TABLE IF NOT EXISTS components (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    purl        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    PRIMARY KEY (snapshot_id, purl)
);

CREATE TABLE IF NOT EXISTS evaluations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    evaluated_at TEXT    NOT NULL,
    as_of        TEXT,
    oracle       TEXT    NOT NULL,
    label        TEXT    UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_evaluations_snapshot ON evaluations (snapshot_id);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluation_id INTEGER NOT NULL REFERENCES evaluations (id) ON DELETE CASCADE,
    purl          TEXT    NOT NULL,
    vuln_id       TEXT    NOT NULL,
    severity      TEXT    NOT NULL DEFAULT 'UNKNOWN',
    summary       TEXT,
    published     TEXT,
    modified      TEXT,
    UNIQUE (evaluation_id, purl, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_evaluation ON findings (evaluation_id);

CREATE TABLE IF NOT EXISTS vuln_cache (
    vuln_id    TEXT PRIMARY KEY,
    severity   TEXT,
    summary    TEXT,
    published  TEXT,
    modified   TEXT,
    aliases    TEXT,
    fetched_at TEXT NOT NULL
);
"""


def utcnow() -> datetime:
    """Timezone-aware now, in UTC. Naive datetimes are never stored."""
    return datetime.now(UTC)


def to_iso(value: datetime | None) -> str | None:
    """Serialise a datetime for SQLite as ISO 8601 UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def from_iso(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp, tolerating the trailing ``Z`` OSV uses."""
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class Store:
    """Thin, explicit data-access layer over one SQLite file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    # ---------------------------------------------------------------- lifecycle

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)
            row = self._conn.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
                )
            elif row["version"] != SCHEMA_VERSION:
                raise RuntimeError(
                    f"database at {self.path} has schema version {row['version']}, "
                    f"this sbomdrift expects {SCHEMA_VERSION}"
                )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---------------------------------------------------------------- snapshots

    def add_snapshot(self, snapshot: Snapshot) -> int:
        """Persist a snapshot and its components; returns the new snapshot id."""
        with self._conn:
            cursor = self._conn.execute(
                """INSERT INTO snapshots
                       (artefact, source, digest, sbom_format, ingested_at, component_count)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    snapshot.artefact,
                    snapshot.source,
                    snapshot.digest,
                    snapshot.sbom_format,
                    to_iso(snapshot.ingested_at),
                    len(snapshot.components),
                ),
            )
            snapshot_id = int(cursor.lastrowid)
            self._conn.executemany(
                """INSERT OR IGNORE INTO components (snapshot_id, purl, name, version)
                   VALUES (?, ?, ?, ?)""",
                [(snapshot_id, c.purl, c.name, c.version) for c in snapshot.components],
            )
        snapshot.id = snapshot_id
        return snapshot_id

    def get_snapshot(self, snapshot_id: int) -> Snapshot | None:
        row = self._conn.execute(
            "SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
        return self._row_to_snapshot(row) if row else None

    def latest_snapshot(self, artefact: str) -> Snapshot | None:
        row = self._conn.execute(
            "SELECT * FROM snapshots WHERE artefact = ? ORDER BY ingested_at DESC, id DESC LIMIT 1",
            (artefact,),
        ).fetchone()
        return self._row_to_snapshot(row) if row else None

    def list_snapshots(self, artefact: str | None = None) -> list[Snapshot]:
        if artefact:
            rows = self._conn.execute(
                "SELECT * FROM snapshots WHERE artefact = ? ORDER BY id", (artefact,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM snapshots ORDER BY id").fetchall()
        return [self._row_to_snapshot(r) for r in rows]

    def components(self, snapshot_id: int) -> list[Component]:
        rows = self._conn.execute(
            "SELECT purl, name, version FROM components WHERE snapshot_id = ? ORDER BY purl",
            (snapshot_id,),
        ).fetchall()
        return [Component(purl=r["purl"], name=r["name"], version=r["version"]) for r in rows]

    def _row_to_snapshot(self, row: sqlite3.Row) -> Snapshot:
        snapshot = Snapshot(
            artefact=row["artefact"],
            source=row["source"],
            ingested_at=from_iso(row["ingested_at"]) or utcnow(),
            digest=row["digest"],
            sbom_format=row["sbom_format"],
            id=row["id"],
        )
        snapshot.components = self.components(row["id"])
        return snapshot

    # -------------------------------------------------------------- evaluations

    def add_evaluation(self, evaluation: Evaluation) -> int:
        """Persist an evaluation and its findings; returns the new evaluation id."""
        with self._conn:
            cursor = self._conn.execute(
                """INSERT INTO evaluations (snapshot_id, evaluated_at, as_of, oracle, label)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    evaluation.snapshot_id,
                    to_iso(evaluation.evaluated_at),
                    to_iso(evaluation.as_of),
                    evaluation.oracle,
                    evaluation.label,
                ),
            )
            evaluation_id = int(cursor.lastrowid)
            self._conn.executemany(
                """INSERT OR IGNORE INTO findings
                       (evaluation_id, purl, vuln_id, severity, summary, published, modified)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        evaluation_id,
                        f.purl,
                        f.vuln_id,
                        f.severity,
                        f.summary,
                        to_iso(f.published),
                        to_iso(f.modified),
                    )
                    for f in evaluation.findings
                ],
            )
        evaluation.id = evaluation_id
        return evaluation_id

    def get_evaluation(self, ref: int | str) -> Evaluation | None:
        """Look an evaluation up by numeric id or by its human label."""
        if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
            row = self._conn.execute(
                "SELECT * FROM evaluations WHERE id = ?", (int(ref),)
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM evaluations WHERE label = ?", (ref,)
            ).fetchone()
        return self._row_to_evaluation(row) if row else None

    def list_evaluations(self, snapshot_id: int | None = None) -> list[Evaluation]:
        if snapshot_id is None:
            rows = self._conn.execute("SELECT * FROM evaluations ORDER BY id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM evaluations WHERE snapshot_id = ? ORDER BY id", (snapshot_id,)
            ).fetchall()
        return [self._row_to_evaluation(r) for r in rows]

    def findings(self, evaluation_id: int) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE evaluation_id = ? ORDER BY purl, vuln_id",
            (evaluation_id,),
        ).fetchall()
        return [
            Finding(
                purl=r["purl"],
                vuln_id=r["vuln_id"],
                severity=r["severity"],
                summary=r["summary"] or "",
                published=from_iso(r["published"]),
                modified=from_iso(r["modified"]),
                id=r["id"],
            )
            for r in rows
        ]

    def _row_to_evaluation(self, row: sqlite3.Row) -> Evaluation:
        evaluation = Evaluation(
            snapshot_id=row["snapshot_id"],
            evaluated_at=from_iso(row["evaluated_at"]) or utcnow(),
            oracle=row["oracle"],
            as_of=from_iso(row["as_of"]),
            label=row["label"],
            id=row["id"],
        )
        evaluation.findings = self.findings(row["id"])
        return evaluation

    # -------------------------------------------------------------- vuln cache

    def cache_vulns(self, records: Iterable[dict]) -> None:
        """Store hydrated OSV records so later evaluations need no network."""
        now = to_iso(utcnow())
        rows = [
            (
                r["vuln_id"],
                r.get("severity", "UNKNOWN"),
                r.get("summary", ""),
                to_iso(r.get("published")),
                to_iso(r.get("modified")),
                json.dumps(r.get("aliases") or []),
                now,
            )
            for r in records
        ]
        with self._conn:
            self._conn.executemany(
                """INSERT INTO vuln_cache
                       (vuln_id, severity, summary, published, modified, aliases, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (vuln_id) DO UPDATE SET
                       severity   = excluded.severity,
                       summary    = excluded.summary,
                       published  = excluded.published,
                       modified   = excluded.modified,
                       aliases    = excluded.aliases,
                       fetched_at = excluded.fetched_at""",
                rows,
            )

    def cached_vulns(self, vuln_ids: Iterable[str]) -> dict[str, dict]:
        """Return the cached records for the ids that are already known."""
        ids = list(vuln_ids)
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        rows = self._conn.execute(
            f"SELECT * FROM vuln_cache WHERE vuln_id IN ({placeholders})", ids
        ).fetchall()
        return {
            r["vuln_id"]: {
                "vuln_id": r["vuln_id"],
                "severity": r["severity"],
                "summary": r["summary"],
                "published": from_iso(r["published"]),
                "modified": from_iso(r["modified"]),
                "aliases": json.loads(r["aliases"]) if r["aliases"] else [],
            }
            for r in rows
        }


@contextmanager
def open_store(path: str | Path) -> Iterator[Store]:
    """Context-managed :class:`Store`, so the connection always closes."""
    store = Store(path)
    try:
        yield store
    finally:
        store.close()
