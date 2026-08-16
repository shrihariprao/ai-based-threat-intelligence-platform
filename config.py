"""
Central configuration for the AI-Based Threat Intelligence Platform.

All paths are resolved relative to this file so the project runs identically
from a local checkout, from Google Colab, or from any working directory.
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional; environment variables still work
    pass

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
REPORT_DIR = BASE_DIR / "reports"

for _d in (DATA_DIR, MODEL_DIR, REPORT_DIR):
    _d.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "threat_intel.db"
SAMPLE_IOC_CSV = DATA_DIR / "sample_iocs.csv"
SAMPLE_LOG_CSV = DATA_DIR / "sample_security_events.csv"

# --------------------------------------------------------------------------
# Credentials (never hard-coded; read from environment / .env)
# --------------------------------------------------------------------------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none")  # anthropic | openai | gemini | none

# When a key is absent the platform runs in demo mode: cached enrichment
# responses and template-generated explanations. Nothing silently fails.
ENRICHMENT_DEMO_MODE = not bool(ABUSEIPDB_API_KEY)
LLM_DEMO_MODE = not bool(LLM_API_KEY)

# --------------------------------------------------------------------------
# Pipeline settings
# --------------------------------------------------------------------------
VALID_INDICATOR_TYPES = ("ipv4", "domain", "url", "md5", "sha1", "sha256")

# Severity labels accepted from source data, normalized to lower case.
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
}

RISK_WEIGHTS = {
    "detection_confidence": 0.45,
    "source_severity": 0.35,
    "enrichment_reputation": 0.20,
}

ALERT_RISK_THRESHOLD = 70  # risk score at or above which an alert is raised
