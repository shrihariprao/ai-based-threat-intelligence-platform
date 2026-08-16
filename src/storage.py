"""
Storage layer - SQLite.

Every query is parameterized. The schema is created on first use, so a fresh
clone of the repository works without a migration step.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    record_id       TEXT PRIMARY KEY,
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    threat_type     TEXT,
    severity        TEXT,
    first_seen      TEXT,
    source          TEXT,
    description     TEXT,
    ingested_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(indicator);
CREATE INDEX IF NOT EXISTS idx_indicators_type  ON indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_indicators_sev   ON indicators(severity);

CREATE TABLE IF NOT EXISTS rejected_records (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator     TEXT,
    source        TEXT,
    reject_reason TEXT,
    ingested_at   TEXT
);

CREATE TABLE IF NOT EXISTS analysis (
    record_id            TEXT PRIMARY KEY,
    indicator            TEXT,
    indicator_type       TEXT,
    threat_type          TEXT,
    severity             TEXT,
    source               TEXT,
    first_seen           TEXT,
    predicted_label      TEXT,
    detection_confidence REAL,
    reputation_score     INTEGER,
    total_reports        INTEGER,
    country              TEXT,
    network_type         TEXT,
    enrichment_source    TEXT,
    correlation_id       TEXT,
    correlation_size     INTEGER,
    correlation_reason   TEXT,
    risk_score           REAL,
    risk_category        TEXT,
    risk_explanation     TEXT,
    risk_detection_points  REAL,
    risk_severity_points   REAL,
    risk_enrichment_points REAL,
    risk_correlation_points REAL,
    ttp_json             TEXT,
    ttp_summary          TEXT,
    analysis_json        TEXT,
    analysis_source      TEXT,
    analysed_at          TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_risk ON analysis(risk_score);
CREATE INDEX IF NOT EXISTS idx_analysis_cat  ON analysis(risk_category);

CREATE TABLE IF NOT EXISTS alerts (
    record_id      TEXT PRIMARY KEY,
    indicator      TEXT,
    indicator_type TEXT,
    threat_type    TEXT,
    risk_score     REAL,
    risk_category  TEXT,
    message        TEXT,
    created_at     TEXT
);

CREATE TABLE IF NOT EXISTS ingestion_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at      TEXT,
    stats_json  TEXT
);
"""


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def upsert_indicators(df: pd.DataFrame, conn: sqlite3.Connection | None = None) -> int:
    """Insert or replace indicator rows. Returns the number written."""
    if df.empty:
        return 0
    own = conn is None
    conn = conn or connect()
    try:
        rows = [
            (r["record_id"], r["indicator"], r["indicator_type"], r["threat_type"],
             r["severity"], r["first_seen"], r["source"], r["description"], r["ingested_at"])
            for r in df.to_dict("records")
        ]
        conn.executemany(
            """INSERT OR REPLACE INTO indicators
               (record_id, indicator, indicator_type, threat_type, severity,
                first_seen, source, description, ingested_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", rows)
        conn.commit()
        return len(rows)
    finally:
        if own:
            conn.close()


def save_rejects(df: pd.DataFrame, conn: sqlite3.Connection | None = None) -> int:
    if df.empty:
        return 0
    own = conn is None
    conn = conn or connect()
    try:
        rows = [
            (str(r.get("indicator", "")), str(r.get("source", "")),
             str(r.get("reject_reason", "")), str(r.get("ingested_at", "")))
            for r in df.to_dict("records")
        ]
        conn.executemany(
            """INSERT INTO rejected_records (indicator, source, reject_reason, ingested_at)
               VALUES (?, ?, ?, ?)""", rows)
        conn.commit()
        return len(rows)
    finally:
        if own:
            conn.close()


def record_run(stats: dict, conn: sqlite3.Connection | None = None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute(
            "INSERT INTO ingestion_runs (run_at, stats_json) VALUES (?, ?)",
            (stats.get("ingested_at", ""), json.dumps(stats)))
        conn.commit()
    finally:
        if own:
            conn.close()


ANALYSIS_COLUMNS = [
    "record_id", "indicator", "indicator_type", "threat_type", "severity", "source",
    "first_seen", "predicted_label", "detection_confidence", "reputation_score",
    "total_reports", "country", "network_type", "enrichment_source", "correlation_id",
    "correlation_size", "correlation_reason", "risk_score", "risk_category",
    "risk_explanation", "risk_detection_points", "risk_severity_points",
    "risk_enrichment_points", "risk_correlation_points", "ttp_json", "ttp_summary",
    "analysis_json", "analysis_source", "analysed_at",
]


def save_analysis(df: pd.DataFrame, conn: sqlite3.Connection | None = None) -> int:
    """Persist fully analysed records. Existing rows are replaced."""
    if df.empty:
        return 0
    own = conn is None
    conn = conn or connect()
    try:
        frame = df.copy()
        for col in ANALYSIS_COLUMNS:
            if col not in frame.columns:
                frame[col] = None
        rows = [tuple(r[c] for c in ANALYSIS_COLUMNS)
                for r in frame[ANALYSIS_COLUMNS].to_dict("records")]
        placeholders = ", ".join(["?"] * len(ANALYSIS_COLUMNS))
        conn.executemany(
            f"INSERT OR REPLACE INTO analysis ({', '.join(ANALYSIS_COLUMNS)}) "
            f"VALUES ({placeholders})", rows)
        conn.commit()
        return len(rows)
    finally:
        if own:
            conn.close()


def save_alerts(df: pd.DataFrame, conn: sqlite3.Connection | None = None) -> int:
    if df.empty:
        return 0
    own = conn is None
    conn = conn or connect()
    try:
        cols = ["record_id", "indicator", "indicator_type", "threat_type",
                "risk_score", "risk_category", "message", "created_at"]
        rows = [tuple(r[c] for c in cols) for r in df[cols].to_dict("records")]
        conn.executemany(
            f"INSERT OR REPLACE INTO alerts ({', '.join(cols)}) "
            f"VALUES ({', '.join(['?'] * len(cols))})", rows)
        conn.commit()
        return len(rows)
    finally:
        if own:
            conn.close()


def load_analysis(conn: sqlite3.Connection | None = None) -> pd.DataFrame:
    own = conn is None
    conn = conn or connect()
    try:
        return pd.read_sql_query("SELECT * FROM analysis", conn)
    finally:
        if own:
            conn.close()


def load_alerts(limit: int = 100, conn: sqlite3.Connection | None = None) -> pd.DataFrame:
    own = conn is None
    conn = conn or connect()
    try:
        return pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY risk_score DESC LIMIT ?", conn, params=(limit,))
    finally:
        if own:
            conn.close()


def search_analysis(term: str, conn: sqlite3.Connection | None = None) -> pd.DataFrame:
    """Parameterized search across analysed indicators."""
    own = conn is None
    conn = conn or connect()
    try:
        return pd.read_sql_query(
            "SELECT * FROM analysis WHERE indicator LIKE ? OR threat_type LIKE ? "
            "ORDER BY risk_score DESC", conn, params=(f"%{term}%", f"%{term}%"))
    finally:
        if own:
            conn.close()


def load_indicators(conn: sqlite3.Connection | None = None) -> pd.DataFrame:
    own = conn is None
    conn = conn or connect()
    try:
        return pd.read_sql_query("SELECT * FROM indicators", conn)
    finally:
        if own:
            conn.close()


def search_indicators(term: str, conn: sqlite3.Connection | None = None) -> pd.DataFrame:
    """Parameterized search - the term is never concatenated into the SQL."""
    own = conn is None
    conn = conn or connect()
    try:
        return pd.read_sql_query(
            "SELECT * FROM indicators WHERE indicator LIKE ? ORDER BY first_seen DESC",
            conn, params=(f"%{term}%",))
    finally:
        if own:
            conn.close()


def summary(conn: sqlite3.Connection | None = None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        cur = conn.cursor()
        out = {"total_indicators": cur.execute("SELECT COUNT(*) FROM indicators").fetchone()[0],
               "total_rejected": cur.execute("SELECT COUNT(*) FROM rejected_records").fetchone()[0],
               "total_analysed": cur.execute("SELECT COUNT(*) FROM analysis").fetchone()[0],
               "total_alerts": cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
               "by_type": {}, "by_severity": {}}
        for row in cur.execute(
                "SELECT indicator_type, COUNT(*) c FROM indicators GROUP BY indicator_type"):
            out["by_type"][row[0]] = row[1]
        for row in cur.execute(
                "SELECT severity, COUNT(*) c FROM indicators GROUP BY severity"):
            out["by_severity"][row[0]] = row[1]
        return out
    finally:
        if own:
            conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database ready at {config.DB_PATH}")
    print(summary())
