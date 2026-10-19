from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS training_store_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO training_store_metadata (key, value)
VALUES ('schema_version', '1');

CREATE TABLE IF NOT EXISTS url_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    normalized_url TEXT,
    final_url TEXT,
    domain TEXT,
    source TEXT NOT NULL DEFAULT 'user_scan',
    scanned_at TEXT NOT NULL,
    final_verdict TEXT,
    risk_score REAL,
    confidence REAL,
    malicious_probability REAL,
    clean_probability REAL,
    url_features_json TEXT,
    html_features_json TEXT,
    scanner_results_json TEXT,
    html_hash TEXT,
    html_path TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_url_observations_scanned_at
ON url_observations (scanned_at);

CREATE INDEX IF NOT EXISTS idx_url_observations_domain
ON url_observations (domain);

CREATE INDEX IF NOT EXISTS idx_url_observations_final_verdict
ON url_observations (final_verdict);

CREATE TABLE IF NOT EXISTS training_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER REFERENCES url_observations(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    final_url TEXT,
    domain TEXT,
    label INTEGER NOT NULL CHECK (label IN (0, 1)),
    label_source TEXT NOT NULL,
    label_confidence REAL NOT NULL DEFAULT 0.0 CHECK (label_confidence >= 0.0 AND label_confidence <= 1.0),
    approved_for_training INTEGER NOT NULL DEFAULT 0 CHECK (approved_for_training IN (0, 1)),
    url_features_json TEXT,
    html_features_json TEXT,
    html_hash TEXT,
    html_path TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_training_samples_approved_label
ON training_samples (approved_for_training, label);

CREATE INDEX IF NOT EXISTS idx_training_samples_label_source
ON training_samples (label_source);

CREATE INDEX IF NOT EXISTS idx_training_samples_observation_id
ON training_samples (observation_id);
"""


class TrainingStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA_SQL)

    def add_observation(
        self,
        *,
        url: str,
        normalized_url: str | None = None,
        final_url: str | None = None,
        domain: str | None = None,
        source: str = "user_scan",
        scanned_at: str | None = None,
        final_verdict: str | None = None,
        risk_score: float | None = None,
        confidence: float | None = None,
        malicious_probability: float | None = None,
        clean_probability: float | None = None,
        url_features: dict[str, Any] | None = None,
        html_features: dict[str, Any] | None = None,
        scanner_results: dict[str, Any] | list[dict[str, Any]] | None = None,
        html_hash: str | None = None,
        html_path: str | None = None,
    ) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO url_observations (
                    url, normalized_url, final_url, domain, source, scanned_at,
                    final_verdict, risk_score, confidence, malicious_probability,
                    clean_probability, url_features_json, html_features_json,
                    scanner_results_json, html_hash, html_path
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url,
                    normalized_url,
                    final_url,
                    domain,
                    source,
                    scanned_at or _utc_now(),
                    final_verdict,
                    risk_score,
                    confidence,
                    malicious_probability,
                    clean_probability,
                    _dump_json(url_features),
                    _dump_json(html_features),
                    _dump_json(scanner_results),
                    html_hash,
                    html_path,
                ),
            )
            return int(cursor.lastrowid)

    def add_training_sample(
        self,
        *,
        url: str,
        label: int,
        label_source: str,
        observation_id: int | None = None,
        final_url: str | None = None,
        domain: str | None = None,
        label_confidence: float = 0.0,
        approved_for_training: bool = False,
        url_features: dict[str, Any] | None = None,
        html_features: dict[str, Any] | None = None,
        html_hash: str | None = None,
        html_path: str | None = None,
        notes: str | None = None,
        dedupe: bool = False,
    ) -> int:
        if label not in (0, 1):
            raise ValueError("label must be 0 (clean) or 1 (malicious)")
        if not 0.0 <= label_confidence <= 1.0:
            raise ValueError("label_confidence must be between 0.0 and 1.0")

        now = _utc_now()
        with self._connect() as connection:
            if dedupe:
                existing = connection.execute(
                    """
                    SELECT id
                    FROM training_samples
                    WHERE url = ? AND label = ?
                    ORDER BY label_confidence DESC, id ASC
                    LIMIT 1
                    """,
                    (url, label),
                ).fetchone()
                if existing:
                    return int(existing["id"])

            cursor = connection.execute(
                """
                INSERT INTO training_samples (
                    observation_id, url, final_url, domain, label, label_source,
                    label_confidence, approved_for_training, url_features_json,
                    html_features_json, html_hash, html_path, notes, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    url,
                    final_url,
                    domain,
                    label,
                    label_source,
                    label_confidence,
                    1 if approved_for_training else 0,
                    _dump_json(url_features),
                    _dump_json(html_features),
                    html_hash,
                    html_path,
                    notes,
                    now,
                    now,
                ),
            )
            return int(cursor.lastrowid)

    def latest_observation_for_url(self, url: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM url_observations
                WHERE url = ? OR normalized_url = ? OR final_url = ?
                ORDER BY scanned_at DESC, id DESC
                LIMIT 1
                """,
                (url, url, url),
            ).fetchone()

        if row is None:
            return None

        result = dict(row)
        result["url_features"] = _load_json(result.pop("url_features_json"))
        result["html_features"] = _load_json(result.pop("html_features_json"))
        result["scanner_results"] = _load_json(result.pop("scanner_results_json"))
        return result

    def observation_by_id(self, observation_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM url_observations WHERE id = ?",
                (observation_id,),
            ).fetchone()

        return self._observation_from_row(row) if row else None

    def observations(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        final_verdict: str | None = None,
        query: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        where, params = _observation_filters(final_verdict=final_verdict, query=query)
        limit = max(1, min(limit, 500))
        offset = max(0, offset)

        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM url_observations {where}",
                    params,
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""
                SELECT *
                FROM url_observations
                {where}
                ORDER BY scanned_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()

        return [self._observation_from_row(row) for row in rows], total

    def training_samples(self, *, approved_only: bool = True) -> list[dict[str, Any]]:
        where_clause = "WHERE approved_for_training = 1" if approved_only else ""
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT *
                FROM training_samples
                {where_clause}
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()

        return [self._training_sample_from_row(row) for row in rows]

    def training_samples_page(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        approved_only: bool = False,
    ) -> tuple[list[dict[str, Any]], int]:
        where_clause = "WHERE approved_for_training = 1" if approved_only else ""
        limit = max(1, min(limit, 500))
        offset = max(0, offset)

        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM training_samples {where_clause}"
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""
                SELECT *
                FROM training_samples
                {where_clause}
                ORDER BY created_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        return [self._training_sample_from_row(row) for row in rows], total

    def table_counts(self) -> dict[str, int]:
        tables = ("url_observations", "training_samples")
        with self._connect() as connection:
            return {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in tables
            }

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _training_sample_from_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["approved_for_training"] = bool(result["approved_for_training"])
        result["url_features"] = _load_json(result.pop("url_features_json"))
        result["html_features"] = _load_json(result.pop("html_features_json"))
        return result

    @staticmethod
    def _observation_from_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["url_features"] = _load_json(result.pop("url_features_json"))
        result["html_features"] = _load_json(result.pop("html_features_json"))
        result["scanner_results"] = _load_json(result.pop("scanner_results_json")) or []
        return result


def _dump_json(value: Any | None) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=_json_default)


def _load_json(value: str | None) -> Any | None:
    if value is None:
        return None
    return json.loads(value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _observation_filters(
    *,
    final_verdict: str | None,
    query: str | None,
) -> tuple[str, tuple[Any, ...]]:
    clauses: list[str] = []
    params: list[Any] = []

    if final_verdict:
        clauses.append("final_verdict = ?")
        params.append(final_verdict)

    if query:
        pattern = f"%{query.strip()}%"
        clauses.append("(url LIKE ? OR normalized_url LIKE ? OR final_url LIKE ? OR domain LIKE ?)")
        params.extend([pattern, pattern, pattern, pattern])

    if not clauses:
        return "", ()
    return f"WHERE {' AND '.join(clauses)}", tuple(params)
