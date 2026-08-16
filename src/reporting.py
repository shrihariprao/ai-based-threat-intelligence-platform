"""
Stage 11 - Threat Report Generation.

Builds a Markdown report for a single finding and writes it to reports/.
Markdown was chosen over PDF because it renders directly on GitHub, needs no
extra dependency, and can be converted to PDF later if required.

Every report carries the data-provenance banner. A report that does not say
its underlying data is synthetic is a report that misrepresents itself.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402


def _provenance_banner(record: dict) -> str:
    parts = []
    if str(record.get("enrichment_source", "")) == "offline_demo":
        parts.append("enrichment values were generated locally and are not real "
                     "reputation data")
    if str(record.get("analysis_source", "")) == "offline_template":
        parts.append("the analysis section was composed deterministically without "
                     "a language model")
    if not parts:
        return ("> **Data provenance.** Enrichment and analysis used live external "
                "services. Review before acting.\n")
    return ("> **Data provenance.** This report was produced in offline demonstration "
            "mode: " + "; ".join(parts) + ". It is not usable as operational "
            "threat intelligence.\n")


def build_markdown(record: dict, analysis: dict | None = None) -> str:
    analysis = analysis or {}
    ttps = record.get("ttp_json", "[]")
    if isinstance(ttps, str):
        try:
            ttps = json.loads(ttps)
        except json.JSONDecodeError:
            ttps = []

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    mitigation = analysis.get("mitigation", []) or []

    lines = [
        f"# Threat Intelligence Report — {record.get('indicator', 'unknown')}",
        "",
        f"*Generated {generated} by the AI-Based Threat Intelligence Platform*",
        "",
        _provenance_banner({**record, **analysis}),
        "## 1. Summary",
        "",
        analysis.get("summary", "No analysis available."),
        "",
        "## 2. Indicator",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Indicator | `{record.get('indicator', '')}` |",
        f"| Type | {record.get('indicator_type', '')} |",
        f"| Reported threat type | {str(record.get('threat_type', '')).replace('_', ' ')} |",
        f"| Source | {record.get('source', '')} |",
        f"| Source severity | {record.get('severity', '')} |",
        f"| First seen | {record.get('first_seen', 'not recorded')} |",
        "",
        "## 3. Detection Result",
        "",
        f"- **Model classification:** {record.get('predicted_label', 'unknown')}",
        f"- **Model confidence:** {float(record.get('detection_confidence', 0) or 0):.2%}",
        "- **Method:** Random Forest classifier (scikit-learn)",
        "",
        "## 4. Risk Assessment",
        "",
        f"**Risk score {record.get('risk_score', 0)}/100 — "
        f"{str(record.get('risk_category', 'unknown')).upper()}**",
        "",
        record.get("risk_explanation", ""),
        "",
        "| Contribution | Points |",
        "|---|---|",
        f"| Detection | {record.get('risk_detection_points', 0)} |",
        f"| Source severity | {record.get('risk_severity_points', 0)} |",
        f"| Enrichment | {record.get('risk_enrichment_points', 0)} |",
        f"| Correlation | {record.get('risk_correlation_points', 0)} |",
        "",
        "## 5. Enrichment",
        "",
        f"- **Reputation score:** {record.get('reputation_score', 'n/a')}/100",
        f"- **Total reports:** {record.get('total_reports', 'n/a')}",
        f"- **Country:** {record.get('country') or 'n/a'}",
        f"- **Network type:** {record.get('network_type') or 'n/a'}",
        f"- **Source:** {record.get('enrichment_source', 'n/a')}",
        "",
        "## 6. Correlation",
        "",
        f"- **Group:** `{record.get('correlation_id', 'n/a')}`",
        f"- **Indicators in group:** {record.get('correlation_size', 1)}",
        f"- **Grouping rule:** {record.get('correlation_reason', 'n/a')}",
        "",
        "## 7. Techniques (MITRE ATT&CK)",
        "",
    ]

    if ttps:
        lines += ["| ID | Technique | Tactic | Description |", "|---|---|---|---|"]
        for t in ttps:
            lines.append(f"| {t.get('technique_id', '')} | {t.get('technique_name', '')} "
                         f"| {t.get('tactic', '')} | {t.get('description', '')} |")
        lines.append("")
        lines.append("*Mapped from the reported threat category using a curated local "
                     "ATT&CK subset. This is an association, not an evidence-based "
                     "attribution.*")
    else:
        lines.append("No technique mapping available.")

    lines += [
        "",
        "## 8. Analysis",
        "",
        f"*Source: {analysis.get('analysis_source', 'unknown')}*",
        "",
        "**Why this was flagged**",
        "",
        analysis.get("why_suspicious", "n/a"),
        "",
        "**Likely behaviour**",
        "",
        analysis.get("likely_behaviour", "n/a"),
        "",
        "## 9. Recommended Mitigation",
        "",
    ]
    lines += [f"{i}. {m}" for i, m in enumerate(mitigation, 1)] or ["No recommendations."]
    lines += [
        "",
        "---",
        "",
        "*Academic prototype produced for a SmartInternz guided project. "
        "Not an operational security product.*",
    ]
    return "\n".join(lines)


def write_report(record: dict, analysis: dict | None = None,
                 out_dir: Path | None = None) -> Path:
    out_dir = Path(out_dir or config.REPORT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() else "_" for c in str(record.get("indicator", "report")))[:60]
    path = out_dir / f"report_{safe}.md"
    path.write_text(build_markdown(record, analysis), encoding="utf-8")
    return path


def write_summary_report(df: pd.DataFrame, alerts: pd.DataFrame,
                         metrics: dict | None = None,
                         out_dir: Path | None = None) -> Path:
    """One overview report covering the whole run."""
    out_dir = Path(out_dir or config.REPORT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# Threat Intelligence Summary Report",
        "",
        f"*Generated {generated}*",
        "",
        "> **Data provenance.** Built from synthetic demonstration data. "
        "Not operational threat intelligence.",
        "",
        "## Overview",
        "",
        f"- Indicators analysed: **{len(df)}**",
        f"- Alerts raised: **{len(alerts)}**",
    ]
    if not df.empty:
        lines.append(f"- Mean risk score: **{df['risk_score'].mean():.1f}/100**")
        lines += ["", "### By risk category", "", "| Category | Count |", "|---|---|"]
        for cat, count in df["risk_category"].value_counts().items():
            lines.append(f"| {cat} | {count} |")
        lines += ["", "### By classification", "", "| Label | Count |", "|---|---|"]
        for label, count in df["predicted_label"].value_counts().items():
            lines.append(f"| {label} | {count} |")

    if not alerts.empty:
        lines += ["", "## Highest risk findings", "",
                  "| Indicator | Type | Risk | Category |", "|---|---|---|---|"]
        for r in alerts.head(10).to_dict("records"):
            lines.append(f"| `{r['indicator']}` | {r['indicator_type']} "
                         f"| {r['risk_score']} | {r['risk_category']} |")

    if metrics:
        lines += ["", "## Detection model", "",
                  f"- Accuracy: **{metrics.get('accuracy', 'n/a')}**",
                  f"- F1 (macro): **{metrics.get('f1_macro', 'n/a')}**",
                  f"- Training records: {metrics.get('n_total', 'n/a')}"]
        if metrics.get("synthetic_training_data"):
            lines.append("")
            lines.append("*Trained on synthetic data. These figures demonstrate that "
                         "the training pipeline works and are not real-world "
                         "detection performance.*")

    path = out_dir / "summary_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


if __name__ == "__main__":
    print(f"Reports are written to {config.REPORT_DIR}")
