"""
End-to-end test: the whole pipeline must run offline, with no API keys,
and produce coherent output. This is the test that would catch a broken
demonstration.
"""
import json
import pandas as pd
import pytest

from src import (ai_analysis, alerts, correlation, detection, enrichment,
                 ingestion, normalization, risk_scoring, ttp_mapping)


@pytest.fixture(scope="module")
def pipeline_output():
    raw, _ = ingestion.ingest_all()
    clean, _, _ = normalization.validate_and_normalize(raw)
    df = detection.predict(clean)
    df = enrichment.enrich(df, allow_network=False)
    df = correlation.correlate(df)
    df = risk_scoring.score(df)
    df = ttp_mapping.map_frame(df)
    analyses = [ai_analysis.analyse(r, allow_network=False)
                for r in df.to_dict("records")]
    df["analysis_json"] = [json.dumps(a) for a in analyses]
    return df


def test_pipeline_produces_records(pipeline_output):
    assert len(pipeline_output) > 0


def test_every_record_has_a_label_and_confidence(pipeline_output):
    assert pipeline_output["predicted_label"].notna().all()
    assert pipeline_output["detection_confidence"].between(0, 1).all()


def test_every_record_has_a_bounded_risk_score(pipeline_output):
    assert pipeline_output["risk_score"].between(0, 100).all()


def test_every_record_has_a_ttp_mapping(pipeline_output):
    for value in pipeline_output["ttp_json"]:
        assert json.loads(value)


def test_every_record_has_an_analysis(pipeline_output):
    for value in pipeline_output["analysis_json"]:
        parsed = json.loads(value)
        assert parsed["summary"]
        assert parsed["mitigation"]


def test_offline_run_is_labelled_offline_throughout(pipeline_output):
    assert (pipeline_output["enrichment_source"] == "offline_demo").all()
    sources = {json.loads(v)["analysis_source"] for v in pipeline_output["analysis_json"]}
    assert sources == {"offline_template"}


def test_alerts_are_a_subset_of_findings(pipeline_output):
    generated = alerts.generate(pipeline_output)
    assert len(generated) <= len(pipeline_output)
    if not generated.empty:
        assert generated["risk_score"].min() >= 70


def test_risk_ordering_is_sane(pipeline_output):
    """Malicious findings should on average outrank benign ones."""
    df = pipeline_output
    if {"malicious", "benign"}.issubset(set(df["predicted_label"])):
        mal = df[df["predicted_label"] == "malicious"]["risk_score"].mean()
        ben = df[df["predicted_label"] == "benign"]["risk_score"].mean()
        assert mal > ben


def test_no_indicator_is_lost_between_stages(pipeline_output):
    raw, _ = ingestion.ingest_all()
    clean, rejected, stats = normalization.validate_and_normalize(raw)
    assert len(pipeline_output) == len(clean)
    assert stats["input"] == stats["clean"] + stats["rejected"] + stats["duplicates_removed"]
