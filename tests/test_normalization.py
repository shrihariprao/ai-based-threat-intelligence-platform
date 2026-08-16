"""
Unit tests for indicator classification and the validation stage.

Run with:   python -m pytest tests/ -v
"""

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.normalization import classify_indicator, validate_and_normalize  # noqa: E402


@pytest.mark.parametrize("value,expected", [
    ("192.0.2.44", "ipv4"),
    ("203.0.113.7", "ipv4"),
    ("cdn1.example.com", "domain"),
    ("mail.example.org", "domain"),
    ("http://verify2.example.org/login", "url"),
    ("https://example.com/path?a=1", "url"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
])
def test_valid_indicators_are_typed(value, expected):
    assert classify_indicator(value) == expected


@pytest.mark.parametrize("value", [
    "", "   ", None,
    "999.999.999.999",      # invalid octets, must not become a domain
    "256.1.1.1",            # out of range
    "not a real indicator",  # contains spaces
    "justtext",             # no dot, not a hash length
    "zzzz8cd98f00b204e9800998ecf8427e",  # right length, not hex
])
def test_invalid_indicators_are_rejected(value):
    assert classify_indicator(value) is None


def test_url_is_not_misread_as_domain():
    assert classify_indicator("http://example.com") == "url"


def test_hash_case_is_ignored():
    upper = "D41D8CD98F00B204E9800998ECF8427E"
    assert classify_indicator(upper) == "md5"


def _frame(rows):
    cols = ["record_id", "indicator", "threat_type", "severity",
            "first_seen", "source", "description", "ingested_at"]
    return pd.DataFrame(rows, columns=cols)


def test_empty_indicator_is_rejected_with_reason():
    df = _frame([["a1", "", "phishing", "high", "2026-08-01T00:00:00", "feed", "", ""]])
    clean, rejected, stats = validate_and_normalize(df)
    assert stats["clean"] == 0
    assert stats["rejected"] == 1
    assert rejected.iloc[0]["reject_reason"] == "empty indicator"


def test_duplicates_are_removed_per_source():
    rows = [
        ["a1", "192.0.2.10", "botnet", "high", "2026-08-01T00:00:00", "feed_a", "", ""],
        ["a1", "192.0.2.10", "botnet", "high", "2026-08-02T00:00:00", "feed_a", "", ""],
        ["b1", "192.0.2.10", "botnet", "high", "2026-08-01T00:00:00", "feed_b", "", ""],
    ]
    clean, _, stats = validate_and_normalize(_frame(rows))
    # same indicator from two different sources is kept twice, on purpose
    assert stats["clean"] == 2
    assert stats["duplicates_removed"] == 1


def test_unknown_severity_becomes_unknown_not_rejected():
    rows = [["a1", "192.0.2.10", "botnet", "urgent", "2026-08-01T00:00:00", "feed", "", ""]]
    clean, _, stats = validate_and_normalize(_frame(rows))
    assert stats["clean"] == 1
    assert clean.iloc[0]["severity"] == "unknown"


def test_bad_timestamp_does_not_reject_the_record():
    rows = [["a1", "192.0.2.10", "botnet", "high", "not-a-timestamp", "feed", "", ""]]
    clean, _, stats = validate_and_normalize(_frame(rows))
    assert stats["clean"] == 1
    assert clean.iloc[0]["first_seen"] == ""


def test_empty_input_returns_empty_output():
    clean, rejected, stats = validate_and_normalize(_frame([]))
    assert clean.empty and rejected.empty
    assert stats["clean"] == 0
