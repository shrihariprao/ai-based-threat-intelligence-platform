"""Tests for the storage layer."""
import pandas as pd
import pytest

from src import storage


@pytest.fixture
def conn(tmp_path):
    c = storage.connect(tmp_path / "test.db")
    storage.init_db(c)
    yield c
    c.close()


def _indicators():
    return pd.DataFrame([{
        "record_id": "r1", "indicator": "192.0.2.1", "indicator_type": "ipv4",
        "threat_type": "botnet", "severity": "high", "first_seen": "2026-08-01",
        "source": "feed_a", "description": "", "ingested_at": "2026-08-01",
    }])


def test_schema_is_created(conn):
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for expected in ("indicators", "rejected_records", "analysis", "alerts",
                     "ingestion_runs"):
        assert expected in tables


def test_upsert_then_load(conn):
    assert storage.upsert_indicators(_indicators(), conn) == 1
    assert len(storage.load_indicators(conn)) == 1


def test_upsert_is_idempotent(conn):
    storage.upsert_indicators(_indicators(), conn)
    storage.upsert_indicators(_indicators(), conn)
    assert len(storage.load_indicators(conn)) == 1


def test_search_is_parameterized_against_injection(conn):
    storage.upsert_indicators(_indicators(), conn)
    # if this were concatenated into SQL the table would be dropped
    result = storage.search_indicators("'; DROP TABLE indicators; --", conn)
    assert result.empty
    assert len(storage.load_indicators(conn)) == 1


def test_summary_counts(conn):
    storage.upsert_indicators(_indicators(), conn)
    s = storage.summary(conn)
    assert s["total_indicators"] == 1
    assert s["by_type"]["ipv4"] == 1


def test_empty_writes_return_zero(conn):
    assert storage.upsert_indicators(pd.DataFrame(), conn) == 0
    assert storage.save_alerts(pd.DataFrame(), conn) == 0
