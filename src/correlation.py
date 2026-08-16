"""
Stage 6 - Threat Correlation.

Groups indicators that appear to belong to the same activity, so that an
analyst sees one incident instead of many isolated alerts.

Two indicators are correlated when they share a threat type and either
  - fall in the same /24 network (IPv4), or
  - share a registrable domain, or
  - were first seen within the same time window.

The rules are deliberately simple and inspectable. Each correlation group
records which rule produced it, so a grouping can always be explained.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

TIME_WINDOW_HOURS = 24


def _subnet(indicator: str) -> str | None:
    parts = indicator.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3]) + ".0/24"
    return None


def _registrable_domain(indicator: str) -> str | None:
    host = indicator
    if "://" in host:
        host = host.split("://", 1)[1].split("/", 1)[0]
    parts = host.split(".")
    if len(parts) >= 2 and not all(p.isdigit() for p in parts):
        return ".".join(parts[-2:])
    return None


def _group_key(row) -> tuple[str, str]:
    """Return (key, rule) describing why this record groups where it does."""
    indicator = str(row["indicator"])
    threat = str(row.get("threat_type", "unknown"))
    itype = str(row.get("indicator_type", ""))

    if itype == "ipv4":
        net = _subnet(indicator)
        if net:
            return f"{threat}|net:{net}", "same threat type and /24 network"

    if itype in ("domain", "url"):
        dom = _registrable_domain(indicator)
        if dom:
            return f"{threat}|dom:{dom}", "same threat type and registrable domain"

    bucket = ""
    if row.get("first_seen"):
        ts = pd.to_datetime(row["first_seen"], errors="coerce", utc=True)
        if not pd.isna(ts):
            bucket = str(int(ts.value // (TIME_WINDOW_HOURS * 3_600_000_000_000)))
    return f"{threat}|win:{bucket}", f"same threat type within {TIME_WINDOW_HOURS}h window"


def correlate(df: pd.DataFrame) -> pd.DataFrame:
    """Add correlation_id, correlation_size and correlation_reason columns."""
    if df.empty:
        out = df.copy()
        for col in ("correlation_id", "correlation_size", "correlation_reason"):
            out[col] = []
        return out

    keys, reasons = [], []
    for row in df.to_dict("records"):
        key, reason = _group_key(row)
        keys.append(key)
        reasons.append(reason)

    out = df.copy()
    out["correlation_id"] = keys
    out["correlation_reason"] = reasons
    out["correlation_size"] = out.groupby("correlation_id")["correlation_id"].transform("size")
    return out


def correlation_summary(df: pd.DataFrame, min_size: int = 2) -> pd.DataFrame:
    """Groups containing more than one indicator, largest first."""
    if df.empty or "correlation_id" not in df.columns:
        return pd.DataFrame(columns=["correlation_id", "size", "threat_type",
                                     "reason", "indicators"])
    grouped = (df[df["correlation_size"] >= min_size]
               .groupby("correlation_id")
               .agg(size=("indicator", "size"),
                    threat_type=("threat_type", "first"),
                    reason=("correlation_reason", "first"),
                    indicators=("indicator", lambda s: ", ".join(sorted(s)[:6])))
               .reset_index()
               .sort_values("size", ascending=False))
    return grouped


if __name__ == "__main__":
    from ingestion import ingest_all
    from normalization import validate_and_normalize

    raw, _ = ingest_all()
    clean, _, _ = validate_and_normalize(raw)
    correlated = correlate(clean)
    summary = correlation_summary(correlated)
    print(f"{len(summary)} correlation groups with more than one indicator")
    print(summary.head(10).to_string(index=False))
