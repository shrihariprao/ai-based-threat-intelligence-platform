"""Tests for enrichment, including the offline fallback contract."""
import pandas as pd

from src import enrichment


def test_offline_enrichment_is_deterministic():
    a = enrichment.enrich_one("192.0.2.44", "ipv4", allow_network=False)
    b = enrichment.enrich_one("192.0.2.44", "ipv4", allow_network=False)
    assert a == b


def test_different_indicators_give_different_values():
    a = enrichment.enrich_one("192.0.2.44", "ipv4", allow_network=False)
    b = enrichment.enrich_one("192.0.2.45", "ipv4", allow_network=False)
    assert a != b


def test_offline_values_are_labelled_as_demo():
    result = enrichment.enrich_one("192.0.2.44", "ipv4", allow_network=False)
    assert result["enrichment_source"] == "offline_demo"
    assert "not real" in result["enrichment_note"].lower()


def test_reputation_stays_in_range():
    for i in range(1, 60):
        r = enrichment.enrich_one(f"192.0.2.{i}", "ipv4", allow_network=False)
        assert 0 <= r["reputation_score"] <= 100


def test_non_ip_indicators_have_no_country():
    r = enrichment.enrich_one("cdn1.example.com", "domain", allow_network=False)
    assert r["country"] == ""


def test_enrich_frame_adds_columns():
    df = pd.DataFrame([{"indicator": "192.0.2.44", "indicator_type": "ipv4"}])
    out = enrichment.enrich(df, allow_network=False)
    for col in ("reputation_score", "enrichment_source", "total_reports"):
        assert col in out.columns


def test_api_failure_falls_back_silently(monkeypatch):
    """A dead API must degrade to offline, never raise."""
    monkeypatch.setattr(enrichment.config, "ENRICHMENT_DEMO_MODE", False)
    monkeypatch.setattr(enrichment, "_abuseipdb_lookup", lambda *a, **k: None)
    result = enrichment.enrich_one("192.0.2.44", "ipv4", allow_network=True)
    assert result["enrichment_source"] == "offline_demo"


def test_empty_frame_is_handled():
    out = enrichment.enrich(pd.DataFrame(columns=["indicator", "indicator_type"]),
                            allow_network=False)
    assert out.empty
