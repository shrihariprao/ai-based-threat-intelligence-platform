"""
Analyst dashboard.

    streamlit run app.py

Reads whatever the pipeline last wrote to SQLite. If the database is empty it
says so and tells you what to run, rather than showing an empty console.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

import config                                              # noqa: E402
from src import ai_analysis, detection, enrichment, reporting, storage  # noqa: E402

st.set_page_config(page_title="Threat Intelligence Platform",
                   page_icon="🛡", layout="wide")

RISK_COLOURS = {"critical": "#B3261E", "high": "#E8710A",
                "medium": "#F2B705", "low": "#3A7D44"}


@st.cache_data(ttl=30)
def load_data():
    storage.init_db()
    return storage.load_analysis(), storage.load_alerts(500), storage.summary()


def risk_badge(category: str) -> str:
    colour = RISK_COLOURS.get(str(category).lower(), "#6B7683")
    return (f"<span style='background:{colour};color:white;padding:2px 10px;"
            f"border-radius:10px;font-size:0.8rem;font-weight:600'>"
            f"{str(category).upper()}</span>")


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------
st.sidebar.title("🛡 Threat Intelligence")
st.sidebar.caption("AI-Based Threat Intelligence Platform")

offline_bits = []
if config.ENRICHMENT_DEMO_MODE:
    offline_bits.append("enrichment")
if config.LLM_DEMO_MODE:
    offline_bits.append("AI analysis")

if offline_bits:
    st.sidebar.warning(
        f"**Offline demo mode** ({', '.join(offline_bits)}).\n\n"
        "Values are generated locally and are not real threat intelligence.")
else:
    st.sidebar.success("Live mode: external services configured.")

df, alerts_df, summary = load_data()

if df.empty:
    st.title("Threat Intelligence Platform")
    st.info("No analysed data yet. Run the pipeline first:\n\n"
            "```\npython run_pipeline.py --regenerate --train\n```")
    st.stop()

st.sidebar.metric("Indicators analysed", len(df))
st.sidebar.metric("Active alerts", len(alerts_df))
metrics = detection.load_metrics()
if metrics:
    st.sidebar.metric("Model accuracy", metrics.get("accuracy", "n/a"))
    if metrics.get("synthetic_training_data"):
        st.sidebar.caption("Model trained on synthetic data. Accuracy shows that "
                           "the training pipeline works, not real-world performance.")

tab_overview, tab_investigate, tab_alerts, tab_model = st.tabs(
    ["Overview", "Investigate", "Alerts", "Detection model"])

# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------
with tab_overview:
    st.subheader("Executive threat overview")

    counts = df["risk_category"].value_counts()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total indicators", len(df))
    c2.metric("Critical", int(counts.get("critical", 0)))
    c3.metric("High", int(counts.get("high", 0)))
    c4.metric("Medium", int(counts.get("medium", 0)))
    c5.metric("Low", int(counts.get("low", 0)))

    left, right = st.columns(2)

    with left:
        st.markdown("**Risk distribution**")
        order = ["critical", "high", "medium", "low"]
        data = (df["risk_category"].value_counts()
                .reindex(order).fillna(0).reset_index())
        data.columns = ["risk_category", "count"]
        fig = px.bar(data, x="risk_category", y="count",
                     color="risk_category", color_discrete_map=RISK_COLOURS)
        fig.update_layout(showlegend=False, height=320,
                          xaxis_title="", yaxis_title="indicators")
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown("**Threat categories**")
        data = df["threat_type"].value_counts().reset_index()
        data.columns = ["threat_type", "count"]
        fig = px.bar(data, x="count", y="threat_type", orientation="h")
        fig.update_layout(height=320, xaxis_title="indicators", yaxis_title="")
        fig.update_traces(marker_color="#1F4E79")
        st.plotly_chart(fig, use_container_width=True)

    left2, right2 = st.columns(2)
    with left2:
        st.markdown("**Indicator types**")
        data = df["indicator_type"].value_counts().reset_index()
        data.columns = ["indicator_type", "count"]
        fig = px.pie(data, names="indicator_type", values="count", hole=0.45)
        fig.update_layout(height=320)
        st.plotly_chart(fig, use_container_width=True)

    with right2:
        st.markdown("**Model classification**")
        data = df["predicted_label"].value_counts().reset_index()
        data.columns = ["predicted_label", "count"]
        fig = px.bar(data, x="predicted_label", y="count")
        fig.update_traces(marker_color="#3A6EA5")
        fig.update_layout(height=320, xaxis_title="", yaxis_title="indicators")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("**Highest risk indicators**")
    st.dataframe(
        df.sort_values("risk_score", ascending=False)
          [["indicator", "indicator_type", "threat_type", "predicted_label",
            "detection_confidence", "risk_score", "risk_category"]].head(15),
        use_container_width=True, hide_index=True)

# --------------------------------------------------------------------------
# Investigate
# --------------------------------------------------------------------------
with tab_investigate:
    st.subheader("IOC search and investigation")

    query = st.text_input("Search indicator or threat type",
                          placeholder="e.g. 192.0.2  or  phishing")
    results = storage.search_analysis(query) if query else df.sort_values(
        "risk_score", ascending=False)

    if results.empty:
        st.warning("No matching indicators.")
    else:
        st.caption(f"{len(results)} matching indicator(s)")
        choice = st.selectbox(
            "Select an indicator",
            results["indicator"].tolist()[:200],
            format_func=lambda v: v[:90])

        record = results[results["indicator"] == choice].iloc[0].to_dict()

        head_l, head_r = st.columns([3, 1])
        with head_l:
            st.markdown(f"### `{record['indicator']}`")
            st.markdown(risk_badge(record["risk_category"]) +
                        f" &nbsp; risk **{record['risk_score']}/100**",
                        unsafe_allow_html=True)
        with head_r:
            st.metric("Model label", record["predicted_label"])
            st.caption(f"confidence {float(record['detection_confidence']):.0%}")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Type", record["indicator_type"])
        m2.metric("Threat type", str(record["threat_type"]).replace("_", " "))
        m3.metric("Reputation", f"{record.get('reputation_score', 0)}/100")
        m4.metric("Correlated", int(record.get("correlation_size", 1)))

        st.markdown("#### Risk breakdown")
        breakdown = pd.DataFrame({
            "factor": ["Detection", "Source severity", "Enrichment", "Correlation"],
            "points": [record.get("risk_detection_points", 0),
                       record.get("risk_severity_points", 0),
                       record.get("risk_enrichment_points", 0),
                       record.get("risk_correlation_points", 0)],
        })
        fig = px.bar(breakdown, x="points", y="factor", orientation="h")
        fig.update_traces(marker_color="#1F4E79")
        fig.update_layout(height=220, xaxis_title="points contributed", yaxis_title="")
        st.plotly_chart(fig, use_container_width=True)
        st.caption(record.get("risk_explanation", ""))

        analysis = {}
        if record.get("analysis_json"):
            try:
                analysis = json.loads(record["analysis_json"])
            except json.JSONDecodeError:
                analysis = {}

        st.markdown("#### Analysis")
        st.caption(f"Source: {analysis.get('analysis_source', 'unknown')} — "
                   f"{analysis.get('analysis_note', '')}")
        st.info(analysis.get("summary", "No analysis available."))
        with st.expander("Why this was flagged", expanded=True):
            st.write(analysis.get("why_suspicious", "n/a"))
        with st.expander("Likely behaviour"):
            st.write(analysis.get("likely_behaviour", "n/a"))

        st.markdown("#### Techniques (MITRE ATT&CK)")
        try:
            ttps = json.loads(record.get("ttp_json") or "[]")
        except json.JSONDecodeError:
            ttps = []
        if ttps:
            st.table(pd.DataFrame(ttps)[["technique_id", "technique_name",
                                         "tactic", "description"]])
            st.caption("Mapped from the reported threat category using a curated "
                       "local ATT&CK subset. An association, not an evidence-based "
                       "attribution.")
        else:
            st.write("No technique mapping available.")

        st.markdown("#### Recommended mitigation")
        for i, step in enumerate(analysis.get("mitigation", []), 1):
            st.markdown(f"{i}. {step}")

        st.markdown("#### Report")
        markdown = reporting.build_markdown(record, analysis)
        st.download_button("Download report (Markdown)", markdown,
                           file_name=f"report_{record['indicator'][:40]}.md",
                           mime="text/markdown")
        with st.expander("Preview report"):
            st.markdown(markdown)

# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
with tab_alerts:
    st.subheader(f"Alerts (risk >= {config.ALERT_RISK_THRESHOLD})")
    if alerts_df.empty:
        st.success("No alerts above the threshold.")
    else:
        pick = st.multiselect("Filter by category",
                              sorted(alerts_df["risk_category"].unique()),
                              default=sorted(alerts_df["risk_category"].unique()))
        shown = alerts_df[alerts_df["risk_category"].isin(pick)]
        st.caption(f"{len(shown)} alert(s)")
        for r in shown.to_dict("records"):
            with st.container(border=True):
                a, b = st.columns([5, 1])
                a.markdown(f"**`{r['indicator']}`**  \n{r['message']}")
                b.markdown(risk_badge(r["risk_category"]), unsafe_allow_html=True)
                b.caption(f"{r['risk_score']}/100")

# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------
with tab_model:
    st.subheader("Detection model")
    if not metrics:
        st.info("No metrics yet. Run: python -m src.detection --train")
    else:
        if metrics.get("synthetic_training_data"):
            st.error(
                "**These metrics come from synthetic training data.** Labels were "
                "generated by a documented rule in `make_sample_data.py` plus random "
                "noise. The figures show that the training and evaluation pipeline "
                "works. They are **not** real-world detection performance and must "
                "not be presented as such.")

        a, b, c, d = st.columns(4)
        a.metric("Accuracy", metrics.get("accuracy"))
        b.metric("F1 (macro)", metrics.get("f1_macro"))
        c.metric("CV F1 (5-fold)", metrics.get("cv_f1_macro_mean"))
        d.metric("Training records", metrics.get("n_total"))

        st.markdown("**Confusion matrix** (rows = actual, columns = predicted)")
        labels = metrics.get("labels", [])
        cm = pd.DataFrame(metrics.get("confusion_matrix", []),
                          index=labels, columns=labels)
        fig = px.imshow(cm, text_auto=True, color_continuous_scale="Blues",
                        labels=dict(x="predicted", y="actual"))
        fig.update_layout(height=380)
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("**Classification report**")
        report = metrics.get("classification_report", {})
        rows = [{"class": k, **{m: round(v[m], 3) for m in
                                ("precision", "recall", "f1-score")},
                 "support": int(v["support"])}
                for k, v in report.items() if isinstance(v, dict)]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        st.markdown("**Pipeline modes**")
        st.write(f"- Enrichment: {enrichment.mode_description()}")
        st.write(f"- AI analysis: {ai_analysis.mode_description()}")
