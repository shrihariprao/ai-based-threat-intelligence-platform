# AI-Based Threat Intelligence Platform

An academic prototype that ingests threat intelligence data, classifies indicators
with a machine learning model, enriches and correlates them, scores their risk,
explains each finding in analyst language, maps it to MITRE ATT&CK techniques,
raises alerts and generates reports — all presented through a Streamlit dashboard.

**It runs completely offline. No API keys are required.**

---

## ⚠️ Read this first — data provenance

The sample data in this repository is **synthetic**, and so is the data the
detection model is trained on.

- Every IP address comes from the ranges reserved for documentation by
  [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737); every domain uses the
  [RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606) reserved names. No real
  host, organisation or threat actor is referenced.
- The training labels are produced by a **documented rule plus random noise** in
  `src/make_sample_data.py`. The model therefore learns to recover a rule this
  repository invented.
- **The reported accuracy shows that the training and evaluation pipeline works.
  It is not real-world detection performance and must not be presented as such.**
- In offline mode, enrichment values are derived from a hash of the indicator and
  the analysis text is composed from templates. Both are labelled as such in the
  database, on the dashboard and in every generated report.

To use real data, drop a CSV with the columns
`indicator, indicator_type, threat_type, severity, source, first_seen, label` at
`data/labelled_training_data.csv` and retrain. No code changes are needed.

---

## Problem statement

Security analysts handle large volumes of alerts and threat intelligence from
multiple sources. Collecting, correlating, analysing and prioritising this
information manually is slow, and makes it difficult to identify high-priority
threats quickly. This platform centralises those steps and returns prioritised,
explained findings instead of raw indicators.

## Features

| # | Capability | Status |
|---|---|---|
| 1 | Multi-source threat data ingestion | Implemented |
| 2 | Input validation with recorded rejection reasons | Implemented |
| 3 | Normalization to a common schema | Implemented |
| 4 | IOC classification (IPv4, domain, URL, MD5, SHA1, SHA256) | Implemented |
| 5 | Deduplication per indicator and source | Implemented |
| 6 | Persistent SQLite storage | Implemented |
| 7 | ML threat classification with confidence | Implemented |
| 8 | Model training, evaluation, confusion matrix, CV | Implemented |
| 9 | IOC enrichment (AbuseIPDB) | Implemented, optional |
| 10 | Deterministic offline enrichment fallback | Implemented |
| 11 | Threat correlation with stated grouping rules | Implemented |
| 12 | Transparent risk scoring with per-factor breakdown | Implemented |
| 13 | MITRE ATT&CK TTP mapping from a curated local file | Implemented |
| 14 | AI-assisted explanation (Claude / GPT / Gemini) | Implemented, optional |
| 15 | Deterministic offline analysis fallback | Implemented |
| 16 | Mitigation recommendations | Implemented |
| 17 | Alert generation above a risk threshold | Implemented |
| 18 | Markdown threat report generation | Implemented |
| 19 | Streamlit analyst dashboard | Implemented |
| 20 | IOC search and detailed investigation view | Implemented |
| 21 | Live feed streaming ingestion | Not implemented — see Limitations |
| 22 | SIEM / firewall / endpoint integration | Not implemented — see Limitations |

## Architecture

```
Threat intelligence sources  (CSV feeds, security event exports)
        │
        ▼
1. Data ingestion               src/ingestion.py        pandas
        ▼
2. Validation & normalization   src/normalization.py    regex + ipaddress
        ▼
3. IOC classification           src/normalization.py
        ▼                                               ┌─ D1 SQLite: indicators
4. Threat detection             src/detection.py        └─ D2 trained_model.pkl
        ▼                                               scikit-learn Random Forest
5. IOC enrichment               src/enrichment.py       AbuseIPDB API │ offline
        ▼
6. Threat correlation           src/correlation.py
        ▼
7. Risk assessment              src/risk_scoring.py
        ▼
8. TTP identification           src/ttp_mapping.py      local ATT&CK subset
        ▼
9. AI-assisted analysis         src/ai_analysis.py      LLM API │ offline template
        ▼
10. Alert generation            src/alerts.py
11. Report generation           src/reporting.py        Markdown → reports/
        ▼
12. Analyst dashboard           app.py                  Streamlit + Plotly
```

## Technology stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Data processing | pandas |
| Machine learning | scikit-learn (Random Forest) |
| Storage | SQLite |
| Dashboard | Streamlit + Plotly |
| Enrichment | AbuseIPDB REST API (optional) |
| AI analysis | Anthropic / OpenAI / Gemini API (optional) |
| Testing | pytest |

## Project structure

```
.
├── app.py                          Streamlit dashboard
├── run_pipeline.py                 end-to-end pipeline runner
├── config.py                       paths, weights, thresholds, credentials
├── requirements.txt
├── .env.example
├── data/
│   ├── sample_iocs.csv             synthetic indicator feed
│   ├── sample_security_events.csv  synthetic event export (different schema)
│   ├── labelled_training_data.csv  synthetic labelled training set
│   ├── mitre_attack_reference.json curated local ATT&CK subset
│   └── threat_intel.db             created on first run
├── models/
│   ├── trained_model.pkl           created by training
│   └── evaluation_metrics.json
├── reports/                        generated Markdown reports
├── src/
│   ├── ingestion.py       normalization.py    storage.py
│   ├── detection.py       enrichment.py       correlation.py
│   ├── risk_scoring.py    ttp_mapping.py      ai_analysis.py
│   ├── alerts.py          reporting.py        make_sample_data.py
└── tests/                          108 tests across 10 files
```

## Installation

```bash
git clone https://github.com/<your-username>/ai-based-threat-intelligence-platform.git
cd ai-based-threat-intelligence-platform
pip install -r requirements.txt
```

Python 3.10 or later.

## Running it

```bash
# generate sample data, train the model, run all stages
python run_pipeline.py --regenerate --train

# launch the dashboard
streamlit run app.py
```

Other options:

```bash
python run_pipeline.py                  # reuse existing data and model
python run_pipeline.py --offline        # force offline mode for every stage
python run_pipeline.py --reports 10     # write more individual reports
python -m src.detection --train         # train and evaluate only
python -m src.detection                 # print the saved evaluation report
```

### Google Colab

```python
!git clone https://github.com/<your-username>/ai-based-threat-intelligence-platform.git
%cd ai-based-threat-intelligence-platform
!pip install -q -r requirements.txt
!python run_pipeline.py --regenerate --train
```

For the dashboard in Colab, expose port 8501 with a tunnel
(`!npx localtunnel --port 8501` alongside `!streamlit run app.py &`).

## Environment variables

Both are **optional**. With neither set, the platform runs fully in offline mode.

```bash
cp .env.example .env
```

| Variable | Purpose |
|---|---|
| `ABUSEIPDB_API_KEY` | Live IP reputation enrichment |
| `LLM_PROVIDER` | `anthropic`, `openai`, `gemini` or `none` |
| `LLM_API_KEY` | Key for the chosen provider |

`.env` is git-ignored. No key is ever written into source.

## Offline / demo mode

Offline mode is the default and is a first-class path, not a degraded one:

- **Enrichment** returns values derived deterministically from a hash of the
  indicator — the same indicator always yields the same values, so demonstrations
  are reproducible.
- **Analysis** is composed from the pipeline's own outputs (label, confidence,
  risk breakdown, enrichment, TTP mapping) into full sentences.
- Every record carries `enrichment_source` and `analysis_source` so offline values
  can never be mistaken for live intelligence.

If a key *is* configured but the API fails, times out or returns malformed data,
the platform falls back to offline automatically rather than raising. This is
covered by tests.

## Running the tests

```bash
python -m pytest tests/ -v
```

108 tests covering ingestion, normalization, detection, enrichment, correlation,
risk scoring, TTP mapping, AI fallback, alerts, reporting, storage, and one
end-to-end integration suite.

## Risk scoring

```
risk = 100 × (0.45 × detection_component
            + 0.35 × severity_component
            + 0.20 × enrichment_component)
       + correlation_bonus        (capped at 8 points)
```

where `detection_component` is the class weight scaled by model confidence.
Bands: critical ≥ 85, high ≥ 70, medium ≥ 40, low below that. Every score carries
a written explanation naming each factor's contribution. Weights are in
`config.py`.

## Sample workflow

1. Pipeline ingests 147 raw records from two differently shaped sources.
2. Validation rejects 3 malformed records (reasons recorded) and removes 13 duplicates.
3. 131 indicators are typed, stored and classified by the model.
4. Enrichment, correlation and risk scoring run; 32 correlation groups form.
5. 24 findings exceed the alert threshold.
6. Reports are written to `reports/`.
7. The dashboard shows the overview, alerts, per-indicator investigation and model metrics.

## Screenshots

Add screenshots to a `screenshots/` folder and link them here:

- `screenshots/01_overview.png` — executive overview
- `screenshots/02_investigate.png` — indicator investigation with risk breakdown
- `screenshots/03_alerts.png` — alerts view
- `screenshots/04_model.png` — model metrics and confusion matrix

## Limitations

Stated plainly, because a prototype that overclaims is worse than one that is
honest about scope.

1. **Synthetic data throughout.** Accuracy figures demonstrate a working training
   pipeline, not detection capability.
2. **No live feed ingestion.** Sources are files read on demand. "Near real time"
   here means the pipeline can be re-run on demand, not that it streams.
3. **No SIEM, firewall or endpoint integration.**
4. **TTP mapping is category-based**, not evidence-based: it states which
   techniques are associated with a threat category, not which technique was
   observed.
5. **Correlation uses simple deterministic rules** (shared subnet, shared domain,
   time window), not graph analysis or clustering.
6. **Single user, no authentication.** There is no access control.
7. **Not load tested.** No throughput or latency claims are made.
8. **The AI layer explains; it does not decide.** The classifier assigns the label.

## Future scope

Live feed and dark web ingestion · SIEM/EDR integration · managed cloud database ·
multi-user access control · graph-based correlation · continuous model retraining ·
anomaly detection for unknown threats · collaborative analyst annotations.

## Academic disclaimer

Built as a guided academic project for SmartInternz. It is a demonstration
prototype, not an operational security product, and must not be used to make real
security decisions. MITRE ATT&CK is a registered trademark of The MITRE
Corporation; technique identifiers are used here for educational reference under
their public knowledge base.
