"""
Runs the complete threat intelligence pipeline end to end.

    python run_pipeline.py                 run with existing data and model
    python run_pipeline.py --regenerate    regenerate sample data first
    python run_pipeline.py --train         train the model before running
    python run_pipeline.py --offline       force offline mode for all stages

Stages: ingestion -> validation and normalization -> IOC classification ->
deduplication -> storage -> detection -> enrichment -> correlation ->
risk scoring -> TTP mapping -> AI analysis -> alerts -> reports.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import config                                          # noqa: E402
from src import (ai_analysis, alerts, correlation, detection, enrichment,  # noqa: E402
                 ingestion, normalization, reporting, risk_scoring,
                 storage, ttp_mapping)
from src.make_sample_data import write_sample_files, write_training_dataset  # noqa: E402


def line(char="-", n=74):
    print(char * n)


def stage(number, title):
    print(f"\n[{number}] {title}")


def main(regenerate=False, do_train=False, offline=False, top_reports=5):
    line("=")
    print("AI-BASED THREAT INTELLIGENCE PLATFORM")
    print("Complete pipeline run")
    line("=")

    allow_network = not offline
    print(f"Enrichment : {enrichment.mode_description()}")
    print(f"AI analysis: {ai_analysis.mode_description()}")

    if regenerate or not config.SAMPLE_IOC_CSV.exists():
        n_ioc, n_log = write_sample_files()
        n_train, _ = write_training_dataset()
        print(f"\nGenerated sample data: {n_ioc} IOC rows, {n_log} event rows, "
              f"{n_train} training rows")

    storage.init_db()

    # ---------------- 1. ingestion ----------------
    stage(1, "Data ingestion")
    raw, ingest_stats = ingestion.ingest_all()
    for name, info in ingest_stats["sources"].items():
        print(f"    {name:34s} {info['status']:8s} {info['records']:>5}")
    print(f"    total raw records: {ingest_stats['total_records']}")

    # ---------------- 2/3. validation, normalization, typing ----------------
    stage(2, "Validation, normalization and IOC classification")
    clean, rejected, norm_stats = normalization.validate_and_normalize(raw)
    print(f"    rejected {norm_stats['rejected']}, "
          f"duplicates removed {norm_stats['duplicates_removed']}, "
          f"clean {norm_stats['clean']}")
    print("    types: " + ", ".join(
        f"{k}={v}" for k, v in clean["indicator_type"].value_counts().items()))
    storage.upsert_indicators(clean)
    storage.save_rejects(rejected)
    storage.record_run({**ingest_stats, **norm_stats})

    # ---------------- 4. detection ----------------
    stage(4, "Threat detection")
    if do_train or not detection.MODEL_PATH.exists():
        print("    training model...")
        metrics = detection.train()
        print(f"    accuracy {metrics['accuracy']}, f1_macro {metrics['f1_macro']}")
    else:
        metrics = detection.load_metrics()
        print(f"    using saved model (accuracy {metrics.get('accuracy', 'n/a')})")
    df = detection.predict(clean)
    print("    predictions: " + ", ".join(
        f"{k}={v}" for k, v in df["predicted_label"].value_counts().items()))
    print(f"    mean confidence: {df['detection_confidence'].mean():.3f}")

    # ---------------- 5. enrichment ----------------
    stage(5, "IOC enrichment")
    df = enrichment.enrich(df, allow_network=allow_network)
    print(f"    enriched {len(df)} indicators "
          f"(source: {df['enrichment_source'].iloc[0] if len(df) else 'n/a'})")
    print(f"    mean reputation score: {df['reputation_score'].mean():.1f}/100")

    # ---------------- 6. correlation ----------------
    stage(6, "Threat correlation")
    df = correlation.correlate(df)
    groups = correlation.correlation_summary(df)
    print(f"    {len(groups)} groups containing more than one indicator")
    if not groups.empty:
        top = groups.iloc[0]
        print(f"    largest group: {top['size']} indicators "
              f"({top['threat_type']}, {top['reason']})")

    # ---------------- 7. risk scoring ----------------
    stage(7, "Risk assessment")
    df = risk_scoring.score(df)
    print(f"    weights: {risk_scoring.weights_description()}")
    print(f"    mean risk {df['risk_score'].mean():.1f}, max {df['risk_score'].max():.1f}")
    print("    categories: " + ", ".join(
        f"{k}={v}" for k, v in df["risk_category"].value_counts().items()))

    # ---------------- 8. TTP mapping ----------------
    stage(8, "TTP identification")
    df = ttp_mapping.map_frame(df)
    print(f"    reference: {ttp_mapping.coverage()}")

    # ---------------- 9. AI analysis ----------------
    stage(9, "AI-assisted analysis")
    analyses = [ai_analysis.analyse(r, allow_network=allow_network)
                for r in df.to_dict("records")]
    df["analysis_json"] = [json.dumps(a) for a in analyses]
    df["analysis_source"] = [a.get("analysis_source", "unknown") for a in analyses]
    df["analysed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"    generated {len(analyses)} analyses "
          f"({df['analysis_source'].iloc[0] if len(df) else 'n/a'})")

    written = storage.save_analysis(df)
    print(f"    stored {written} analysed records")

    # ---------------- 10. alerts ----------------
    stage(10, "Alert generation")
    alert_df = alerts.generate(df)
    storage.save_alerts(alert_df)
    print(f"    {len(alert_df)} alerts at threshold "
          f"risk >= {config.ALERT_RISK_THRESHOLD}")
    for r in alert_df.head(3).to_dict("records"):
        print(f"      {r['risk_score']:>5} {r['risk_category']:<8} {r['indicator']}")

    # ---------------- 11. reports ----------------
    stage(11, "Report generation")
    top = df.sort_values("risk_score", ascending=False).head(top_reports)
    paths = []
    for record, analysis in zip(top.to_dict("records"),
                                [json.loads(x) for x in top["analysis_json"]]):
        paths.append(reporting.write_report(record, analysis))
    summary_path = reporting.write_summary_report(df, alert_df, metrics)
    print(f"    wrote {len(paths)} individual reports and 1 summary")
    print(f"    summary: {summary_path}")

    line("=")
    s = storage.summary()
    print(f"DONE  indicators={s['total_indicators']}  analysed={s['total_analysed']}  "
          f"alerts={s['total_alerts']}  rejected={s['total_rejected']}")
    print("Launch the dashboard with:  streamlit run app.py")
    line("=")
    return df, alert_df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--regenerate", action="store_true", help="regenerate sample data")
    ap.add_argument("--train", action="store_true", help="retrain the detection model")
    ap.add_argument("--offline", action="store_true", help="force offline mode")
    ap.add_argument("--reports", type=int, default=5, help="number of individual reports")
    args = ap.parse_args()
    main(regenerate=args.regenerate, do_train=args.train,
         offline=args.offline, top_reports=args.reports)
