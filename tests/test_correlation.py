"""Tests for the correlation stage."""
import pandas as pd

from src import correlation


def _frame(rows):
    return pd.DataFrame(rows)


def test_same_subnet_and_threat_are_grouped():
    df = _frame([
        {"indicator": "192.0.2.10", "indicator_type": "ipv4",
         "threat_type": "botnet", "first_seen": "2026-08-01T00:00:00"},
        {"indicator": "192.0.2.99", "indicator_type": "ipv4",
         "threat_type": "botnet", "first_seen": "2026-08-01T05:00:00"},
    ])
    out = correlation.correlate(df)
    assert out["correlation_id"].nunique() == 1
    assert set(out["correlation_size"]) == {2}


def test_different_subnets_are_not_grouped():
    df = _frame([
        {"indicator": "192.0.2.10", "indicator_type": "ipv4",
         "threat_type": "botnet", "first_seen": "2026-08-01T00:00:00"},
        {"indicator": "203.0.113.10", "indicator_type": "ipv4",
         "threat_type": "botnet", "first_seen": "2026-08-01T00:00:00"},
    ])
    out = correlation.correlate(df)
    assert out["correlation_id"].nunique() == 2


def test_different_threat_types_are_not_grouped():
    df = _frame([
        {"indicator": "192.0.2.10", "indicator_type": "ipv4",
         "threat_type": "botnet", "first_seen": "2026-08-01T00:00:00"},
        {"indicator": "192.0.2.11", "indicator_type": "ipv4",
         "threat_type": "phishing", "first_seen": "2026-08-01T00:00:00"},
    ])
    out = correlation.correlate(df)
    assert out["correlation_id"].nunique() == 2


def test_shared_registrable_domain_groups_url_and_domain():
    df = _frame([
        {"indicator": "login1.example.com", "indicator_type": "domain",
         "threat_type": "phishing", "first_seen": "2026-08-01T00:00:00"},
        {"indicator": "http://login2.example.com/a", "indicator_type": "url",
         "threat_type": "phishing", "first_seen": "2026-08-09T00:00:00"},
    ])
    out = correlation.correlate(df)
    assert out["correlation_id"].nunique() == 1


def test_every_group_carries_a_reason():
    df = _frame([{"indicator": "192.0.2.10", "indicator_type": "ipv4",
                  "threat_type": "botnet", "first_seen": "2026-08-01T00:00:00"}])
    out = correlation.correlate(df)
    assert out.iloc[0]["correlation_reason"]


def test_summary_excludes_singletons():
    df = _frame([
        {"indicator": "192.0.2.10", "indicator_type": "ipv4",
         "threat_type": "botnet", "first_seen": "2026-08-01T00:00:00"},
        {"indicator": "192.0.2.11", "indicator_type": "ipv4",
         "threat_type": "botnet", "first_seen": "2026-08-01T00:00:00"},
        {"indicator": "203.0.113.5", "indicator_type": "ipv4",
         "threat_type": "scanning", "first_seen": "2026-08-01T00:00:00"},
    ])
    out = correlation.correlate(df)
    summary = correlation.correlation_summary(out)
    assert len(summary) == 1
    assert summary.iloc[0]["size"] == 2


def test_empty_frame_is_handled():
    assert correlation.correlate(pd.DataFrame(columns=["indicator"])).empty
