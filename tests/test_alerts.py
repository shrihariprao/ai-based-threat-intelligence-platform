"""Tests for alert generation."""
import pandas as pd

from src import alerts


def _scored(scores):
    return pd.DataFrame([
        {"record_id": f"r{i}", "indicator": f"192.0.2.{i}", "indicator_type": "ipv4",
         "threat_type": "botnet", "predicted_label": "malicious",
         "risk_score": s, "risk_category": "high"}
        for i, s in enumerate(scores)
    ])


def test_only_scores_at_or_above_threshold_alert():
    out = alerts.generate(_scored([95, 71, 70, 69, 10]), threshold=70)
    assert len(out) == 3


def test_alerts_are_sorted_by_risk():
    out = alerts.generate(_scored([72, 95, 80]), threshold=70)
    assert list(out["risk_score"]) == [95, 80, 72]


def test_no_alerts_below_threshold():
    assert alerts.generate(_scored([10, 20]), threshold=70).empty


def test_duplicate_record_ids_are_collapsed():
    df = _scored([90, 90])
    df["record_id"] = "same"
    assert len(alerts.generate(df, threshold=70)) == 1


def test_message_names_the_indicator_and_score():
    out = alerts.generate(_scored([88]), threshold=70)
    message = out.iloc[0]["message"]
    assert "192.0.2.0" in message and "88" in message


def test_empty_input_returns_empty_frame():
    assert alerts.generate(pd.DataFrame(), threshold=70).empty


def test_missing_risk_column_does_not_crash():
    assert alerts.generate(pd.DataFrame([{"indicator": "x"}]), threshold=70).empty
