"""
Stage 2 - Validation and Normalization, and Stage 3 - IOC type classification.

Rejected records are never silently dropped: every rejection is returned with
the reason, stored in the database, and surfaced on the dashboard. A pipeline
that quietly discards a third of its input looks identical to one that works.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

# --------------------------------------------------------------------------
# Indicator patterns
# --------------------------------------------------------------------------
URL_RE = re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

NORMALIZED_COLUMNS = [
    "record_id", "indicator", "indicator_type", "threat_type", "severity",
    "first_seen", "source", "description", "ingested_at",
]


def classify_indicator(value: str) -> str | None:
    """
    Return the indicator type, or None when the value matches nothing known.

    Order matters: hashes are checked before domains because a hex string
    contains no dot and would not match a domain anyway, but URLs must be
    checked before domains since a URL contains a domain inside it.
    """
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None

    if URL_RE.match(v):
        return "url"
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else None
    except ValueError:
        pass
    if SHA256_RE.match(v):
        return "sha256"
    if SHA1_RE.match(v):
        return "sha1"
    if MD5_RE.match(v):
        return "md5"
    if DOMAIN_RE.match(v):
        # A domain regex will happily accept "999.999.999.999", because each
        # label is valid. A real TLD is never all digits, so this check keeps
        # malformed IP addresses out of the domain bucket.
        if v.rsplit(".", 1)[-1].isdigit():
            return None
        return "domain"
    return None


def _normalize_severity(value: str) -> str | None:
    if not value:
        return None
    return config.SEVERITY_MAP.get(str(value).strip().lower())


def _normalize_timestamp(value: str) -> str | None:
    if not value or not str(value).strip():
        return None
    parsed = pd.to_datetime(str(value).strip(), errors="coerce", utc=True, format="mixed")
    if pd.isna(parsed):
        return None
    return parsed.isoformat()


def validate_and_normalize(raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """
    Validate, normalize and type every raw record.

    Returns (clean, rejected, stats). A record is rejected when its indicator
    is empty or unrecognisable. Missing severity or timestamp is repaired with
    a documented default rather than causing rejection, because losing a real
    indicator over a missing optional field would be the worse outcome.
    """
    if raw.empty:
        empty = pd.DataFrame(columns=NORMALIZED_COLUMNS)
        return empty, pd.DataFrame(columns=list(raw.columns) + ["reject_reason"]), {
            "input": 0, "rejected": 0, "duplicates_removed": 0, "clean": 0,
        }

    records, rejects = [], []

    for row in raw.to_dict("records"):
        indicator = str(row.get("indicator", "")).strip()

        if not indicator:
            rejects.append({**row, "reject_reason": "empty indicator"})
            continue

        indicator_type = classify_indicator(indicator)
        if indicator_type is None:
            rejects.append({**row, "reject_reason": "unrecognised indicator format"})
            continue

        severity = _normalize_severity(row.get("severity", ""))
        first_seen = _normalize_timestamp(row.get("first_seen", ""))
        threat_type = str(row.get("threat_type", "")).strip().lower() or "unknown"

        records.append({
            "record_id": row.get("record_id", ""),
            # URLs and domains are case-insensitive; hashes are lowercased for
            # comparison. IP addresses are already canonical.
            "indicator": indicator.lower() if indicator_type != "url" else indicator,
            "indicator_type": indicator_type,
            "threat_type": threat_type,
            "severity": severity or "unknown",
            "first_seen": first_seen or "",
            "source": str(row.get("source", "")).strip() or "unspecified",
            "description": str(row.get("description", "")).strip(),
            "ingested_at": row.get("ingested_at", ""),
        })

    clean = pd.DataFrame(records, columns=NORMALIZED_COLUMNS)
    before = len(clean)

    if not clean.empty:
        # Keep the most recently seen occurrence of each indicator per source.
        clean = (clean.sort_values("first_seen", ascending=False)
                      .drop_duplicates(subset=["indicator", "source"], keep="first")
                      .reset_index(drop=True))

    stats = {
        "input": len(raw),
        "rejected": len(rejects),
        "duplicates_removed": before - len(clean),
        "clean": len(clean),
    }
    rejected_df = pd.DataFrame(rejects) if rejects else pd.DataFrame(
        columns=list(raw.columns) + ["reject_reason"])
    return clean, rejected_df, stats


if __name__ == "__main__":
    from ingestion import ingest_all

    raw, _ = ingest_all()
    clean, rejected, stats = validate_and_normalize(raw)
    print(f"input {stats['input']}  rejected {stats['rejected']}  "
          f"duplicates removed {stats['duplicates_removed']}  clean {stats['clean']}")
    print("\nindicator types:")
    print(clean["indicator_type"].value_counts().to_string())
    if not rejected.empty:
        print("\nrejection reasons:")
        print(rejected["reject_reason"].value_counts().to_string())
