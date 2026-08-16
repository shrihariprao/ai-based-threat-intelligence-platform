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
