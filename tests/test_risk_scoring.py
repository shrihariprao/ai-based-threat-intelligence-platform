"""Tests for risk scoring."""
import pytest

from src import risk_scoring


BASE = {"predicted_label": "suspicious", "detection_confidence": 0.6,
        "severity": "medium", "reputation_score": 40, "correlation_size": 1}


def test_score_is_bounded():
    for label in ("malicious", "suspicious", "benign"):
        for sev in ("critical", "high", "medium", "low", "unknown"):
            r = risk_scoring.score_row({**BASE, "predicted_label": label,
                                        "severity": sev, "detection_confidence": 1.0,
                                        "reputation_score": 100})
            assert 0 <= r["risk_score"] <= 100


def test_malicious_scores_above_benign():
    high = risk_scoring.score_row({**BASE, "predicted_label": "malicious"})
    low = risk_scoring.score_row({**BASE, "predicted_label": "benign"})
    assert high["risk_score"] > low["risk_score"]


def test_higher_severity_raises_score():
    a = risk_scoring.score_row({**BASE, "severity": "critical"})
    b = risk_scoring.score_row({**BASE, "severity": "low"})
    assert a["risk_score"] > b["risk_score"]


def test_confidence_scales_the_detection_contribution():
    a = risk_scoring.score_row({**BASE, "detection_confidence": 0.95})
    b = risk_scoring.score_row({**BASE, "detection_confidence": 0.30})
    assert a["risk_detection_points"] > b["risk_detection_points"]


def test_correlation_bonus_is_capped():
    r = risk_scoring.score_row({**BASE, "correlation_size": 500})
    assert r["risk_correlation_points"] <= risk_scoring.MAX_CORRELATION_BONUS


def test_categories_follow_bands():
    assert risk_scoring.categorise(90) == "critical"
    assert risk_scoring.categorise(75) == "high"
    assert risk_scoring.categorise(50) == "medium"
    assert risk_scoring.categorise(10) == "low"


def test_explanation_mentions_every_factor():
    r = risk_scoring.score_row({**BASE, "correlation_size": 3})
    text = r["risk_explanation"].lower()
    for word in ("detection", "severity", "enrichment", "correlation", "total"):
        assert word in text


def test_components_sum_close_to_score():
    r = risk_scoring.score_row({**BASE, "correlation_size": 2})
    parts = (r["risk_detection_points"] + r["risk_severity_points"]
             + r["risk_enrichment_points"] + r["risk_correlation_points"])
    assert abs(parts - r["risk_score"]) < 0.5


def test_missing_fields_do_not_crash():
    r = risk_scoring.score_row({})
    assert 0 <= r["risk_score"] <= 100
