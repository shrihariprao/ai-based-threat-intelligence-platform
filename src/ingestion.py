"""
Stage 1 - Data Ingestion.

Reads threat data from the configured sources and returns a single raw
DataFrame with ingestion metadata attached. Each source has its own reader
because sources arrive in different shapes; adding a new source means adding
one reader function and one entry in SOURCE_READERS, with no change to any
later stage of the pipeline.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

RAW_COLUMNS = [
    "indicator", "threat_type", "severity", "first_seen",
    "source", "description", "ingested_at", "record_id",
]


def _record_id(indicator: str, source: str) -> str:
    """Stable identifier for an indicator from a given source."""
    return hashlib.sha256(f"{indicator}|{source}".encode()).hexdigest()[:16]


def _finalise(df: pd.DataFrame, source_label: str) -> pd.DataFrame:
    df = df.copy()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    df["ingested_at"] = now
    if "source" not in df.columns or df["source"].isna().all():
        df["source"] = source_label
    df["source"] = df["source"].fillna(source_label).replace("", source_label)
    df["record_id"] = [
        _record_id(str(i), str(s)) for i, s in zip(df["indicator"], df["source"])
    ]
    for col in RAW_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    return df[RAW_COLUMNS]


def read_ioc_csv(path: Path) -> pd.DataFrame:
    """Reader for feeds already shaped as indicator records."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    return _finalise(df, source_label=path.stem)


def read_security_events_csv(path: Path) -> pd.DataFrame:
    """
    Reader for security event exports, which carry a different schema.

    The source IP of each event becomes the indicator; the event category
    becomes the threat type. This is what makes the platform multi-source
    rather than a single-file reader.
    """
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    mapped = pd.DataFrame({
        "indicator": df.get("src_ip", ""),
        "threat_type": df.get("event_category", ""),
        "severity": df.get("risk_label", ""),
        "first_seen": df.get("event_time", ""),
        "source": "internal_security_events",
        "description": "Derived from security event export, sensor "
                       + df.get("sensor", pd.Series([""] * len(df))).astype(str),
    })
    return _finalise(mapped, source_label="internal_security_events")


SOURCE_READERS = {
    config.SAMPLE_IOC_CSV: read_ioc_csv,
    config.SAMPLE_LOG_CSV: read_security_events_csv,
}


def ingest_all(sources: dict | None = None) -> tuple[pd.DataFrame, dict]:
    """
    Run every configured reader and concatenate the results.

    Returns the combined raw DataFrame and a stats dictionary describing what
    was read, which the pipeline records as an ingestion run.
    """
    sources = SOURCE_READERS if sources is None else sources
    frames, per_source = [], {}

    for path, reader in sources.items():
        path = Path(path)
        if not path.exists():
            per_source[path.name] = {"status": "missing", "records": 0}
            continue
        try:
            frame = reader(path)
            frames.append(frame)
            per_source[path.name] = {"status": "ok", "records": len(frame)}
        except Exception as exc:  # a bad source must not stop the pipeline
            per_source[path.name] = {"status": f"error: {exc}", "records": 0}

    if not frames:
        return pd.DataFrame(columns=RAW_COLUMNS), {
            "total_records": 0, "sources": per_source,
            "ingested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    combined = pd.concat(frames, ignore_index=True)
    stats = {
        "total_records": len(combined),
        "sources": per_source,
        "ingested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return combined, stats


if __name__ == "__main__":
    raw, stats = ingest_all()
    print(f"Ingested {stats['total_records']} raw records")
    for name, info in stats["sources"].items():
        print(f"  {name:32s} {info['status']:10s} {info['records']:>5} records")
