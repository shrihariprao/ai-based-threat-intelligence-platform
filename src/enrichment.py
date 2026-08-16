"""
Stage 5 - IOC Enrichment.

Adds reputation context to each indicator. When ABUSEIPDB_API_KEY is set the
AbuseIPDB API is queried for IP addresses; otherwise the platform runs in
offline mode.

The offline path is DETERMINISTIC, not random: the same indicator always
produces the same values, derived from a hash of the indicator string. This
makes demonstrations reproducible. Every enriched record carries an
`enrichment_source` field so that offline values can never be mistaken for
real reputation data, in the dashboard or in a report.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

COUNTRIES = ["NL", "RU", "US", "CN", "DE", "BR", "IN", "SG", "FR", "UA"]
NETWORK_TYPES = ["hosting_provider", "residential_isp", "cloud_provider",
                 "vpn_exit_node", "corporate_network"]


def _deterministic_enrichment(indicator: str, indicator_type: str) -> dict:
    """
    Offline enrichment. Values are derived from the indicator hash so they are
    stable across runs, and are clearly marked as demonstration data.
    """
    digest = hashlib.sha256(indicator.encode()).hexdigest()
    n = int(digest[:8], 16)

    reputation = n % 101                       # 0-100
    total_reports = (n >> 8) % 400
    country = COUNTRIES[(n >> 16) % len(COUNTRIES)]
    network = NETWORK_TYPES[(n >> 20) % len(NETWORK_TYPES)]
    age_days = (n >> 24) % 900

    return {
        "reputation_score": reputation,
        "total_reports": total_reports,
        "country": country if indicator_type == "ipv4" else "",
        "network_type": network if indicator_type == "ipv4" else "",
        "first_reported_days_ago": age_days,
        "enrichment_source": "offline_demo",
        "enrichment_note": (
            "Generated locally from a hash of the indicator. "
            "Not real reputation data."),
    }


def _abuseipdb_lookup(indicator: str, timeout: int = 8) -> dict | None:
    """Query AbuseIPDB. Returns None on any failure so the caller falls back."""
    try:
        import requests
    except ImportError:
        return None

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": indicator, "maxAgeInDays": 90},
            timeout=timeout,
        )
        if response.status_code != 200:
            return None
        data = response.json().get("data", {})
        return {
            "reputation_score": int(data.get("abuseConfidenceScore", 0)),
            "total_reports": int(data.get("totalReports", 0)),
            "country": data.get("countryCode") or "",
            "network_type": data.get("usageType") or "",
            "first_reported_days_ago": 0,
            "enrichment_source": "abuseipdb",
            "enrichment_note": "Live reputation data from AbuseIPDB.",
        }
    except Exception:
        return None


def enrich_one(indicator: str, indicator_type: str, allow_network: bool = True) -> dict:
    """Enrich a single indicator, preferring live data when it is available."""
    if (allow_network and not config.ENRICHMENT_DEMO_MODE
            and indicator_type == "ipv4"):
        live = _abuseipdb_lookup(indicator)
        if live is not None:
            return live
    return _deterministic_enrichment(indicator, indicator_type)


def enrich(df: pd.DataFrame, allow_network: bool = True) -> pd.DataFrame:
    """Add enrichment columns to a frame of normalized indicators."""
    if df.empty:
        out = df.copy()
        for col in ("reputation_score", "total_reports", "country", "network_type",
                    "first_reported_days_ago", "enrichment_source", "enrichment_note"):
            out[col] = []
        return out

    records = [
        enrich_one(str(r["indicator"]), str(r["indicator_type"]), allow_network)
        for r in df.to_dict("records")
    ]
    enrichment = pd.DataFrame(records, index=df.index)
    return pd.concat([df, enrichment], axis=1)


def mode_description() -> str:
    if config.ENRICHMENT_DEMO_MODE:
        return ("OFFLINE DEMO MODE - reputation values are generated locally and "
                "are not real threat intelligence.")
    return "LIVE MODE - IP reputation retrieved from AbuseIPDB."


if __name__ == "__main__":
    print(mode_description())
    for value, kind in [("192.0.2.44", "ipv4"), ("cdn1.example.com", "domain")]:
        print(f"\n{value}")
        for k, v in enrich_one(value, kind).items():
            print(f"   {k:28s} {v}")
