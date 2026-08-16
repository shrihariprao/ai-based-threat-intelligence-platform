"""Tests for AI analysis, focusing on the offline fallback contract."""
import pytest

from src import ai_analysis


RECORD = {
    "indicator": "http://verify3.example.org/login", "indicator_type": "url",
    "threat_type": "phishing", "severity": "high", "predicted_label": "malicious",
    "detection_confidence": 0.88, "risk_score": 81.4, "risk_category": "high",
    "risk_explanation": "Detection contributed 39.6 points.",
    "reputation_score": 64, "enrichment_source": "offline_demo",
    "correlation_size": 3, "ttp_summary": "T1566 Phishing (Initial Access)",
}


def test_offline_analysis_has_all_sections():
    result = ai_analysis.offline_analysis(RECORD)
    for key in ("summary", "why_suspicious", "severity_explanation",
                "likely_behaviour", "mitigation", "analysis_source"):
        assert key in result


def test_offline_analysis_is_labelled_as_offline():
    assert ai_analysis.offline_analysis(RECORD)["analysis_source"] == "offline_template"


def test_offline_analysis_is_deterministic():
    assert ai_analysis.offline_analysis(RECORD) == ai_analysis.offline_analysis(RECORD)


def test_mitigation_is_a_non_empty_list():
    mitigation = ai_analysis.offline_analysis(RECORD)["mitigation"]
    assert isinstance(mitigation, list) and len(mitigation) >= 2


def test_summary_reflects_the_model_label_not_its_own_opinion():
    """The AI layer explains the classifier's decision; it must not override it."""
    benign = ai_analysis.offline_analysis({**RECORD, "predicted_label": "benign"})
    assert "benign" in benign["summary"].lower()


def test_unknown_threat_type_still_produces_mitigation():
    result = ai_analysis.offline_analysis({**RECORD, "threat_type": "not_a_real_type"})
    assert result["mitigation"]


def test_analyse_uses_offline_when_no_key(monkeypatch):
    monkeypatch.setattr(ai_analysis.config, "LLM_DEMO_MODE", True)
    assert ai_analysis.analyse(RECORD)["analysis_source"] == "offline_template"


def test_analyse_falls_back_when_provider_fails(monkeypatch):
    monkeypatch.setattr(ai_analysis.config, "LLM_DEMO_MODE", False)
    monkeypatch.setattr(ai_analysis.config, "LLM_PROVIDER", "anthropic")
    monkeypatch.setitem(ai_analysis.PROVIDERS, "anthropic", lambda p: None)
    assert ai_analysis.analyse(RECORD)["analysis_source"] == "offline_template"


def test_analyse_falls_back_on_malformed_llm_json(monkeypatch):
    monkeypatch.setattr(ai_analysis.config, "LLM_DEMO_MODE", False)
    monkeypatch.setattr(ai_analysis.config, "LLM_PROVIDER", "anthropic")
    monkeypatch.setitem(ai_analysis.PROVIDERS, "anthropic", lambda p: "not json at all")
    assert ai_analysis.analyse(RECORD)["analysis_source"] == "offline_template"


def test_valid_llm_json_is_used_and_labelled(monkeypatch):
    monkeypatch.setattr(ai_analysis.config, "LLM_DEMO_MODE", False)
    monkeypatch.setattr(ai_analysis.config, "LLM_PROVIDER", "anthropic")
    monkeypatch.setitem(
        ai_analysis.PROVIDERS, "anthropic",
        lambda p: '{"summary": "s", "why_suspicious": "w", '
                  '"severity_explanation": "e", "likely_behaviour": "b", '
                  '"mitigation": ["do a thing"]}')
    result = ai_analysis.analyse(RECORD)
    assert result["analysis_source"] == "llm:anthropic"
    assert result["summary"] == "s"


def test_fenced_json_is_parsed():
    parsed = ai_analysis._parse_llm_json('```json\n{"summary": "x"}\n```')
    assert parsed["summary"] == "x"
