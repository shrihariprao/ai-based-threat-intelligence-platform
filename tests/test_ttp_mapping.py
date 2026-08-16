"""Tests for TTP mapping."""
import pytest

from src import ttp_mapping


def test_known_category_maps_to_techniques():
    result = ttp_mapping.map_threat_type("phishing")
    assert result
    ids = [t["technique_id"] for t in result]
    assert "T1566" in ids


def test_every_technique_has_required_fields():
    for category in ttp_mapping.load_reference()["mappings"]:
        for technique in ttp_mapping.map_threat_type(category):
            for field in ("technique_id", "technique_name", "tactic", "description"):
                assert technique.get(field), f"{category} missing {field}"


def test_unknown_category_falls_back_not_crashes():
    result = ttp_mapping.map_threat_type("a_category_that_does_not_exist")
    assert result
    assert result == ttp_mapping.map_threat_type("unknown")


def test_case_and_whitespace_are_tolerated():
    assert ttp_mapping.map_threat_type("  PHISHING ") == ttp_mapping.map_threat_type("phishing")


def test_none_is_handled():
    assert ttp_mapping.map_threat_type(None)


def test_describe_produces_readable_text():
    text = ttp_mapping.describe(ttp_mapping.map_threat_type("botnet"))
    assert "T1583.005" in text and "(" in text


def test_coverage_reports_counts():
    cov = ttp_mapping.coverage()
    assert cov["categories"] >= 8 and cov["techniques"] >= 8
