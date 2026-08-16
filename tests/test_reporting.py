"""Tests for report generation."""
import json
import pandas as pd

from src import reporting


RECORD = {
    "indicator": "http://verify3.example.org/login", "indicator_type": "url",
    "threat_type": "phishing", "severity": "high", "source": "feed_b",
    "first_seen": "2026-08-01T00:00:00", "predicted_label": "malicious",
    "detection_confidence": 0.88, "risk_score": 81.4, "risk_category": "high",
    "risk_explanation": "Detection contributed 39.6 points.",
    "risk_detection_points": 39.6, "risk_severity_points": 26.3,
    "risk_enrichment_points": 12.8, "risk_correlation_points": 4.0,
    "reputation_score": 64, "total_reports": 21, "country": "",
    "network_type": "", "enrichment_source": "offline_demo",
    "correlation_id": "phishing|dom:example.org", "correlation_size": 3,
    "correlation_reason": "same threat type and registrable domain",
    "ttp_json": json.dumps([{"technique_id": "T1566", "technique_name": "Phishing",
                             "tactic": "Initial Access", "description": "d"}]),
    "ttp_summary": "T1566 Phishing (Initial Access)",
}
ANALYSIS = {
    "summary": "A phishing URL classified as malicious.",
    "why_suspicious": "The model assigned malicious with 88% confidence.",
    "likely_behaviour": "Credential harvesting.",
    "mitigation": ["Block the URL", "Reset affected credentials"],
    "analysis_source": "offline_template",
}


def test_report_contains_every_required_section():
    md = reporting.build_markdown(RECORD, ANALYSIS)
    for heading in ("Summary", "Indicator", "Detection Result", "Risk Assessment",
                    "Enrichment", "Correlation", "Techniques", "Analysis",
                    "Recommended Mitigation"):
        assert heading in md


def test_report_includes_the_indicator_and_score():
    md = reporting.build_markdown(RECORD, ANALYSIS)
    assert RECORD["indicator"] in md
    assert "81.4" in md


def test_offline_report_declares_its_provenance():
    md = reporting.build_markdown(RECORD, ANALYSIS)
    assert "provenance" in md.lower()
    assert "not real" in md.lower() or "not usable" in md.lower()


def test_mitigation_steps_are_listed():
    md = reporting.build_markdown(RECORD, ANALYSIS)
    assert "Block the URL" in md


def test_missing_analysis_does_not_crash():
    md = reporting.build_markdown(RECORD, None)
    assert "Threat Intelligence Report" in md


def test_malformed_ttp_json_is_tolerated():
    md = reporting.build_markdown({**RECORD, "ttp_json": "{not json"}, ANALYSIS)
    assert "Threat Intelligence Report" in md


def test_report_is_written_to_disk(tmp_path):
    path = reporting.write_report(RECORD, ANALYSIS, out_dir=tmp_path)
    assert path.exists()
    assert path.read_text(encoding="utf-8").startswith("# Threat Intelligence Report")


def test_summary_report_reports_real_counts(tmp_path):
    df = pd.DataFrame([
        {"risk_score": 90, "risk_category": "critical", "predicted_label": "malicious"},
        {"risk_score": 20, "risk_category": "low", "predicted_label": "benign"},
    ])
    alerts_df = pd.DataFrame([{"indicator": "x", "indicator_type": "ipv4",
                               "risk_score": 90, "risk_category": "critical"}])
    path = reporting.write_summary_report(df, alerts_df, {"accuracy": 0.72,
                                                          "synthetic_training_data": True},
                                          out_dir=tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "Indicators analysed: **2**" in text
    assert "Alerts raised: **1**" in text
    assert "synthetic" in text.lower()
