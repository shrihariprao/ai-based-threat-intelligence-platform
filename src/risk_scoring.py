"""
Stage 7 - Risk Assessment.

Produces a 0-100 risk score for every indicator, a severity category, and a
written explanation of how the score was reached. The explanation is not
decoration: an analyst who cannot see why something scored 82 has no reason
to trust the number, and neither does an examiner.

    risk = 100 * ( w1 * detection_component
                 + w2 * severity_component
                 + w3 * enrichment_component )
           + correlation_adjustment

Weights live in config.RISK_WEIGHTS so they can be changed in one place.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

LABEL_WEIGHT = {"malicious": 1.0, "suspicious": 0.55, "benign": 0.10}
SEVERITY_VALUE = {"critical": 1.0, "high": 0.75, "medium": 0.45,
                  "low": 0.20, "unknown": 0.35}

CATEGORY_BANDS = [(85, "critical"), (70, "high"), (40, "medium"), (0, "low")]
MAX_CORRELATION_BONUS = 8.0


def categorise(score: float) -> str:
    for threshold, name in CATEGORY_BANDS:
        if score >= threshold:
            return name
    return "low"


def score_row(row: dict) -> dict:
    """Score a single record and explain every contribution."""
    w = config.RISK_WEIGHTS

    label = str(row.get("predicted_label", "suspicious")).lower()
    confidence = float(row.get("detection_confidence", 0.5) or 0.5)
    severity = str(row.get("severity", "unknown")).lower()
    reputation = float(row.get("reputation_score", 0) or 0)
    corr_size = int(row.get("correlation_size", 1) or 1)

    # 1. detection: class weight scaled by how confident the model is
    detection_component = LABEL_WEIGHT.get(label, 0.5) * confidence
    # 2. severity as reported by the source feed
    severity_component = SEVERITY_VALUE.get(severity, 0.35)
    # 3. external or offline reputation, already 0-100
    enrichment_component = min(reputation, 100.0) / 100.0

    base = 100.0 * (
        w["detection_confidence"] * detection_component
        + w["source_severity"] * severity_component
        + w["enrichment_reputation"] * enrichment_component
    )

    # 4. an indicator seen alongside others in the same activity is worth more
    #    attention than one seen alone, capped so it cannot dominate.
    correlation_bonus = min(MAX_CORRELATION_BONUS, max(0, corr_size - 1) * 2.0)

    total = round(min(100.0, base + correlation_bonus), 1)
    category = categorise(total)

    explanation = [
        f"Detection: model labelled this '{label}' with confidence "
        f"{confidence:.2f}, contributing "
        f"{100 * w['detection_confidence'] * detection_component:.1f} points.",
        f"Source severity: reported as '{severity}', contributing "
        f"{100 * w['source_severity'] * severity_component:.1f} points.",
        f"Enrichment: reputation score {reputation:.0f}/100, contributing "
        f"{100 * w['enrichment_reputation'] * enrichment_component:.1f} points.",
    ]
    if correlation_bonus:
        explanation.append(
            f"Correlation: seen with {corr_size - 1} related indicator(s), "
            f"adding {correlation_bonus:.1f} points.")
    explanation.append(f"Total risk score {total}/100, categorised as {category}.")

    return {
        "risk_score": total,
        "risk_category": category,
        "risk_explanation": " ".join(explanation),
        "risk_detection_points": round(100 * w["detection_confidence"] * detection_component, 1),
        "risk_severity_points": round(100 * w["source_severity"] * severity_component, 1),
        "risk_enrichment_points": round(100 * w["enrichment_reputation"] * enrichment_component, 1),
        "risk_correlation_points": round(correlation_bonus, 1),
    }


def score(df: pd.DataFrame) -> pd.DataFrame:
    """Add risk columns to a frame that has been detected, enriched and correlated."""
    if df.empty:
        out = df.copy()
        for col in ("risk_score", "risk_category", "risk_explanation",
                    "risk_detection_points", "risk_severity_points",
                    "risk_enrichment_points", "risk_correlation_points"):
            out[col] = []
        return out

    scored = pd.DataFrame([score_row(r) for r in df.to_dict("records")], index=df.index)
    return pd.concat([df, scored], axis=1)


def weights_description() -> str:
    w = config.RISK_WEIGHTS
    return (f"detection {w['detection_confidence']:.0%}, "
            f"source severity {w['source_severity']:.0%}, "
            f"enrichment {w['enrichment_reputation']:.0%}, "
            f"plus up to {MAX_CORRELATION_BONUS:.0f} points for correlation")


if __name__ == "__main__":
    print("Risk model:", weights_description())
    demo = {"predicted_label": "malicious", "detection_confidence": 0.91,
            "severity": "high", "reputation_score": 76, "correlation_size": 4}
    result = score_row(demo)
    print(f"\nExample -> {result['risk_score']} ({result['risk_category']})")
    print(result["risk_explanation"])
