"""
Stage 9 - AI-Assisted Threat Analysis.

Produces the analyst-facing explanation of a finding: what it is, why it was
flagged, what the attacker is likely doing, and what to do about it.

Two paths, and the output always says which one produced it:

  llm:<provider>   an LLM API was called (requires LLM_API_KEY)
  offline_template a deterministic explanation assembled from the pipeline's
                   own outputs, with no model involved

The offline path is not a degraded placeholder. It composes real sentences
from the detection label, confidence, risk breakdown, enrichment and TTP
mapping, so a demonstration with no API key still shows a complete workflow.

The distinction that matters for the report: the ML classifier decides the
LABEL. This module only EXPLAINS a decision already made. It never overrides
the classifier.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

SYSTEM_PROMPT = (
    "You are assisting a security analyst. You will be given the output of an "
    "automated threat intelligence pipeline for a single indicator. Explain the "
    "finding clearly and concisely for an analyst who must decide what to do "
    "next. Do not invent facts that are not in the supplied data. Do not claim "
    "to know the identity of any threat actor. Reply as JSON with keys: "
    "summary, why_suspicious, severity_explanation, likely_behaviour, "
    "mitigation (a list of short action strings)."
)


def _build_prompt(record: dict) -> str:
    return json.dumps({
        "indicator": record.get("indicator"),
        "indicator_type": record.get("indicator_type"),
        "threat_type": record.get("threat_type"),
        "source_severity": record.get("severity"),
        "model_label": record.get("predicted_label"),
        "model_confidence": record.get("detection_confidence"),
        "risk_score": record.get("risk_score"),
        "risk_category": record.get("risk_category"),
        "risk_explanation": record.get("risk_explanation"),
        "reputation_score": record.get("reputation_score"),
        "enrichment_source": record.get("enrichment_source"),
        "correlated_indicators": record.get("correlation_size"),
        "ttp": record.get("ttp_summary"),
    }, indent=2)


# --------------------------------------------------------------------------
# Offline deterministic analysis
# --------------------------------------------------------------------------
BEHAVIOUR = {
    "command_and_control": "maintaining a channel between a compromised host and attacker infrastructure",
    "phishing": "attempting to obtain credentials or induce a user to run something",
    "malware_delivery": "delivering an executable payload to a target host",
    "scanning": "probing the environment to find reachable services",
    "brute_force": "repeatedly attempting authentication to guess credentials",
    "data_exfiltration": "moving collected data out of the environment",
    "botnet": "operating as part of a network of compromised hosts",
    "unknown": "activity that has not yet been attributed to a specific behaviour",
}

MITIGATION = {
    "command_and_control": [
        "Block the indicator at the egress firewall and proxy",
        "Hunt for internal hosts that contacted this destination",
        "Isolate any host with confirmed outbound contact",
    ],
    "phishing": [
        "Block the URL or domain at the mail gateway and web proxy",
        "Identify recipients and check whether credentials were submitted",
        "Force password reset for any user who interacted with it",
    ],
    "malware_delivery": [
        "Block the indicator and quarantine any matching file hash",
        "Run endpoint scans across hosts that contacted the source",
        "Preserve a sample for further analysis before removal",
    ],
    "scanning": [
        "Confirm which services responded to the scanning source",
        "Rate limit or block the source at the perimeter",
        "Verify that exposed services are patched and required",
    ],
    "brute_force": [
        "Block the source address and review authentication logs",
        "Confirm account lockout thresholds are enforced",
        "Enable multi-factor authentication on targeted accounts",
    ],
    "data_exfiltration": [
        "Block the destination and capture traffic for review",
        "Identify what data left the environment and over what period",
        "Escalate to incident response immediately",
    ],
    "botnet": [
        "Block the indicator and locate internal hosts communicating with it",
        "Reimage confirmed compromised hosts rather than cleaning in place",
        "Review egress filtering rules",
    ],
    "unknown": [
        "Retain the indicator on a watchlist",
        "Correlate against future activity before acting",
        "Confirm the source feed's reliability for this record",
    ],
}


def offline_analysis(record: dict) -> dict:
    threat = str(record.get("threat_type", "unknown")).lower()
    label = str(record.get("predicted_label", "suspicious")).lower()
    confidence = float(record.get("detection_confidence", 0) or 0)
    risk = record.get("risk_score", 0)
    category = record.get("risk_category", "low")
    indicator = record.get("indicator", "the indicator")
    itype = record.get("indicator_type", "indicator")
    reputation = record.get("reputation_score", 0)
    enrich_src = record.get("enrichment_source", "offline_demo")
    corr = int(record.get("correlation_size", 1) or 1)

    summary = (
        f"The {itype} {indicator} was reported as {threat.replace('_', ' ')} activity "
        f"and classified as {label} by the detection model with "
        f"{confidence:.0%} confidence. Overall risk is {risk}/100 ({category})."
    )

    why = [
        f"The source feed categorised this indicator as {threat.replace('_', ' ')}.",
        f"The trained classifier assigned the label '{label}' with {confidence:.0%} confidence.",
        f"Reputation data returned a score of {reputation}/100 (source: {enrich_src}).",
    ]
    if corr > 1:
        why.append(f"It was seen alongside {corr - 1} related indicator(s) in the same activity.")

    return {
        "summary": summary,
        "why_suspicious": " ".join(why),
        "severity_explanation": record.get("risk_explanation", ""),
        "likely_behaviour": (
            f"Consistent with {BEHAVIOUR.get(threat, BEHAVIOUR['unknown'])}. "
            f"Associated techniques: {record.get('ttp_summary', 'none mapped')}."
        ),
        "mitigation": MITIGATION.get(threat, MITIGATION["unknown"]),
        "analysis_source": "offline_template",
        "analysis_note": (
            "Generated locally from pipeline output without an AI model. "
            "Deterministic and reproducible."),
    }


# --------------------------------------------------------------------------
# LLM providers
# --------------------------------------------------------------------------
def _call_anthropic(prompt: str) -> str | None:
    try:
        import requests
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": config.LLM_API_KEY,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": "claude-sonnet-4-6", "max_tokens": 1000,
                  "system": SYSTEM_PROMPT,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        if r.status_code != 200:
            return None
        return "".join(b.get("text", "") for b in r.json().get("content", []))
    except Exception:
        return None


def _call_openai(prompt: str) -> str | None:
    try:
        import requests
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {config.LLM_API_KEY}",
                     "Content-Type": "application/json"},
            json={"model": "gpt-4o-mini", "max_tokens": 1000,
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": prompt}]},
            timeout=30)
        if r.status_code != 200:
            return None
        return r.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def _call_gemini(prompt: str) -> str | None:
    try:
        import requests
        r = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.0-flash:generateContent?key={config.LLM_API_KEY}",
            headers={"Content-Type": "application/json"},
            json={"system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                  "contents": [{"parts": [{"text": prompt}]}]},
            timeout=30)
        if r.status_code != 200:
            return None
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return None


PROVIDERS = {"anthropic": _call_anthropic, "openai": _call_openai, "gemini": _call_gemini}


def _parse_llm_json(text: str) -> dict | None:
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        cleaned = cleaned[4:] if cleaned.startswith("json") else cleaned
    try:
        data = json.loads(cleaned.strip())
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "summary" not in data:
        return None
    return data


def analyse(record: dict, allow_network: bool = True) -> dict:
    """
    Analyse one finding. Falls back to the offline path on any failure, so a
    missing key, a network error or a malformed response can never break a run.
    """
    if allow_network and not config.LLM_DEMO_MODE:
        caller = PROVIDERS.get(config.LLM_PROVIDER.lower())
        if caller is not None:
            raw = caller(_build_prompt(record))
            parsed = _parse_llm_json(raw) if raw else None
            if parsed:
                parsed.setdefault("mitigation", [])
                parsed["analysis_source"] = f"llm:{config.LLM_PROVIDER.lower()}"
                parsed["analysis_note"] = (
                    "Generated by a language model from pipeline output. "
                    "Review before acting.")
                return parsed
    return offline_analysis(record)


def mode_description() -> str:
    if config.LLM_DEMO_MODE:
        return ("OFFLINE MODE - explanations are generated deterministically from "
                "pipeline output; no language model is called.")
    return f"LIVE MODE - explanations generated via {config.LLM_PROVIDER}."


if __name__ == "__main__":
    print(mode_description())
    demo = {
        "indicator": "http://verify3.example.org/login", "indicator_type": "url",
        "threat_type": "phishing", "severity": "high", "predicted_label": "malicious",
        "detection_confidence": 0.88, "risk_score": 81.4, "risk_category": "high",
        "risk_explanation": "Detection contributed 39.6 points...",
        "reputation_score": 64, "enrichment_source": "offline_demo",
        "correlation_size": 3,
        "ttp_summary": "T1566 Phishing (Initial Access); T1204 User Execution (Execution)",
    }
    result = analyse(demo)
    for key, value in result.items():
        print(f"\n{key}:\n  {value}")
