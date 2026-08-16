"""
Stage 10 - Alert Generation.

Raises an alert for any finding whose risk score reaches the configured
threshold. Alerts are deduplicated by record_id, so re-running the pipeline
on unchanged data does not produce duplicate alerts.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

ALERT_COLUMNS = ["record_id", "indicator", "indicator_type", "threat_type",
                 "risk_score", "risk_category", "message", "created_at"]


def build_message(row: dict) -> str:
    return (f"{str(row.get('risk_category', 'unknown')).upper()} risk "
            f"{row.get('indicator_type', 'indicator')} "
            f"{row.get('indicator', '')} "
            f"({str(row.get('threat_type', 'unknown')).replace('_', ' ')}) "
            f"scored {row.get('risk_score', 0)}/100 and was classified "
            f"'{row.get('predicted_label', 'unknown')}'.")


def generate(df: pd.DataFrame, threshold: float | None = None) -> pd.DataFrame:
    """Return the alerts raised for a scored frame."""
    threshold = config.ALERT_RISK_THRESHOLD if threshold is None else threshold
    if df.empty or "risk_score" not in df.columns:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    hits = df[df["risk_score"] >= threshold]
    if hits.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = [{
        "record_id": r.get("record_id", ""),
        "indicator": r.get("indicator", ""),
        "indicator_type": r.get("indicator_type", ""),
        "threat_type": r.get("threat_type", ""),
        "risk_score": r.get("risk_score", 0),
        "risk_category": r.get("risk_category", ""),
        "message": build_message(r),
        "created_at": now,
    } for r in hits.to_dict("records")]

    alerts = pd.DataFrame(rows, columns=ALERT_COLUMNS)
    alerts = alerts.drop_duplicates(subset=["record_id"], keep="first")
    return alerts.sort_values("risk_score", ascending=False).reset_index(drop=True)


if __name__ == "__main__":
    print(f"Alert threshold: risk score >= {config.ALERT_RISK_THRESHOLD}")
