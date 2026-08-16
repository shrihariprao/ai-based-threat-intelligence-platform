"""Tests for the detection stage."""
import pandas as pd
import pytest

from src import detection


@pytest.fixture(scope="module")
def sample_records():
    return pd.DataFrame([
        {"indicator": "192.0.2.44", "indicator_type": "ipv4",
         "threat_type": "botnet", "severity": "high", "source": "feed_a"},
        {"indicator": "http://verify1.example.org/login", "indicator_type": "url",
         "threat_type": "phishing", "severity": "critical", "source": "feed_b"},
    ])


def test_feature_extraction_shape(sample_records):
    features = detection.extract_features(sample_records)
    for col in detection.CATEGORICAL + detection.NUMERIC:
        assert col in features.columns
    assert len(features) == len(sample_records)


def test_entropy_increases_with_randomness():
    assert detection._entropy("aaaaaaaa") < detection._entropy("a8f3k2p9")


def test_suspicious_token_flag(sample_records):
    features = detection.extract_features(sample_records)
    assert features.iloc[1]["suspicious_token"] == 1   # contains "verify"/"login"
    assert features.iloc[0]["suspicious_token"] == 0


def test_model_trains_and_reports_real_metrics():
    metrics = detection.train()
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["n_train"] > 0 and metrics["n_test"] > 0
    assert len(metrics["confusion_matrix"]) == len(metrics["labels"])
    # the synthetic flag must be present so no one quotes these as real
    assert metrics["synthetic_training_data"] is True


def test_prediction_adds_label_and_confidence(sample_records):
    out = detection.predict(sample_records)
    assert "predicted_label" in out.columns
    assert "detection_confidence" in out.columns
    for conf in out["detection_confidence"]:
        assert 0.0 <= conf <= 1.0


def test_confidence_matches_assigned_class(sample_records):
    """Confidence must be the probability of the class actually assigned."""
    model = detection.load_model()
    out = detection.predict(sample_records)
    proba = model.predict_proba(detection.extract_features(sample_records))
    classes = list(model.named_steps["classifier"].classes_)
    for i, row in out.reset_index(drop=True).iterrows():
        expected = proba[i][classes.index(row["predicted_label"])]
        assert abs(expected - row["detection_confidence"]) < 1e-3


def test_empty_frame_returns_empty():
    out = detection.predict(pd.DataFrame(columns=["indicator", "indicator_type",
                                                  "threat_type", "severity", "source"]))
    assert out.empty
