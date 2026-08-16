"""Tests for the ingestion stage."""
import pandas as pd
import pytest

from src.ingestion import RAW_COLUMNS, ingest_all, read_ioc_csv, read_security_events_csv


def test_ioc_reader_returns_raw_schema(tmp_path):
    p = tmp_path / "feed.csv"
    p.write_text("indicator,threat_type,severity,first_seen,source,description\n"
                 "192.0.2.1,botnet,high,2026-08-01T00:00:00,feed_a,x\n")
    df = read_ioc_csv(p)
    assert list(df.columns) == RAW_COLUMNS
    assert len(df) == 1
    assert df.iloc[0]["indicator"] == "192.0.2.1"


def test_event_reader_maps_a_different_schema(tmp_path):
    p = tmp_path / "events.csv"
    p.write_text("event_time,src_ip,event_category,risk_label,sensor\n"
                 "2026-08-01 10:00:00,198.51.100.4,scanning,High,ids-01\n")
    df = read_security_events_csv(p)
    assert df.iloc[0]["indicator"] == "198.51.100.4"
    assert df.iloc[0]["threat_type"] == "scanning"
    assert df.iloc[0]["source"] == "internal_security_events"


def test_record_id_is_stable_and_source_scoped(tmp_path):
    p = tmp_path / "feed.csv"
    p.write_text("indicator,threat_type,severity,first_seen,source,description\n"
                 "192.0.2.1,botnet,high,2026-08-01T00:00:00,feed_a,x\n")
    first = read_ioc_csv(p).iloc[0]["record_id"]
    second = read_ioc_csv(p).iloc[0]["record_id"]
    assert first == second


def test_missing_source_file_does_not_raise(tmp_path):
    missing = tmp_path / "nope.csv"
    raw, stats = ingest_all({missing: read_ioc_csv})
    assert raw.empty
    assert stats["sources"]["nope.csv"]["status"] == "missing"


def test_broken_source_is_reported_not_fatal(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("indicator\n192.0.2.1\n")

    def exploding_reader(path):
        raise ValueError("simulated reader failure")

    raw, stats = ingest_all({p: exploding_reader})
    assert raw.empty
    assert "error" in stats["sources"]["bad.csv"]["status"]
