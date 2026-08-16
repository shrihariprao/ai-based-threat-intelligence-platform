"""
Stage 8 - TTP Identification.

Maps each threat category to MITRE ATT&CK techniques using a curated local
reference file. Deliberately offline: a live ATT&CK API call would make the
demonstration dependent on network access, and the mapping itself does not
need one.

The mapping is deterministic, not inferred. It states which technique is
associated with a threat category; it does not claim to have identified the
technique from evidence in the data.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

REFERENCE_PATH = config.DATA_DIR / "mitre_attack_reference.json"

_CACHE: dict | None = None


def load_reference(path: Path | None = None) -> dict:
    global _CACHE
    if _CACHE is None or path is not None:
        p = Path(path or REFERENCE_PATH)
        if not p.exists():
            raise FileNotFoundError(f"TTP reference file not found at {p}")
        data = json.loads(p.read_text())
        if path is not None:
            return data
        _CACHE = data
    return _CACHE


def map_threat_type(threat_type: str) -> list[dict]:
    """Return the techniques associated with a threat category."""
    reference = load_reference()["mappings"]
    key = str(threat_type or "unknown").strip().lower()
    return reference.get(key, reference.get("unknown", []))


def describe(techniques: list[dict]) -> str:
    if not techniques:
        return "No technique mapping available."
    return "; ".join(f"{t['technique_id']} {t['technique_name']} ({t['tactic']})"
                     for t in techniques)


def map_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Add ttp_json and ttp_summary columns."""
    if df.empty:
        out = df.copy()
        out["ttp_json"] = []
        out["ttp_summary"] = []
        return out

    mapped = [map_threat_type(t) for t in df["threat_type"]]
    out = df.copy()
    out["ttp_json"] = [json.dumps(m) for m in mapped]
    out["ttp_summary"] = [describe(m) for m in mapped]
    return out


def coverage() -> dict:
    ref = load_reference()
    return {
        "categories": len(ref["mappings"]),
        "techniques": sum(len(v) for v in ref["mappings"].values()),
        "version": ref.get("_about", {}).get("version", "unknown"),
    }


if __name__ == "__main__":
    print("TTP reference coverage:", coverage())
    for category in ("phishing", "botnet", "made_up_category"):
        print(f"\n{category}")
        print("  ", describe(map_threat_type(category)))
