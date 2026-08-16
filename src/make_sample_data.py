"""
Generates the synthetic sample data used to demonstrate the pipeline.

IMPORTANT — these records are synthetic. Every address is drawn from the
IPv4 ranges reserved for documentation by RFC 5737 (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and every domain uses the RFC 2606
reserved names (example.com / example.org / .invalid). No real host,
organisation or threat actor is referenced, and no claim is made that any
of these indicators is genuinely malicious.

The file deliberately contains malformed and duplicate rows so that the
validation and deduplication stages have something real to remove.
"""

import csv
import hashlib
import random
from datetime import datetime, timedelta

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

RNG = random.Random(20260817)  # fixed seed: regenerating gives identical data

THREAT_TYPES = [
    "command_and_control", "phishing", "malware_delivery", "scanning",
    "brute_force", "data_exfiltration", "botnet", "unknown",
]
SEVERITIES = ["critical", "high", "medium", "low"]
SOURCES = ["opensource_feed_a", "opensource_feed_b", "internal_soc_export"]


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _rows():
    rows = []
    base = datetime(2026, 8, 1, 9, 0, 0)

    # --- IPv4 indicators (RFC 5737 documentation ranges) ---
    for i in range(40):
        block = RNG.choice(["192.0.2", "198.51.100", "203.0.113"])
        rows.append({
            "indicator": f"{block}.{RNG.randint(1, 254)}",
            "threat_type": RNG.choice(THREAT_TYPES),
            "severity": RNG.choice(SEVERITIES),
            "first_seen": (base + timedelta(hours=i * 3)).isoformat(),
            "source": RNG.choice(SOURCES),
            "description": "Synthetic sample record for pipeline demonstration",
        })

    # --- domains and URLs (RFC 2606 reserved names) ---
    for i in range(20):
        host = f"{RNG.choice(['cdn', 'mail', 'login', 'update', 'api'])}{i}.example.com"
        rows.append({
            "indicator": host,
            "threat_type": RNG.choice(THREAT_TYPES),
            "severity": RNG.choice(SEVERITIES),
            "first_seen": (base + timedelta(hours=i * 5)).isoformat(),
            "source": RNG.choice(SOURCES),
            "description": "Synthetic sample record for pipeline demonstration",
        })
    for i in range(15):
        rows.append({
            "indicator": f"http://{RNG.choice(['secure', 'account', 'verify'])}{i}.example.org/login",
            "threat_type": "phishing",
            "severity": RNG.choice(["critical", "high", "medium"]),
            "first_seen": (base + timedelta(hours=i * 7)).isoformat(),
            "source": RNG.choice(SOURCES),
            "description": "Synthetic sample record for pipeline demonstration",
        })

    # --- file hashes (synthetic digests) ---
    for i in range(25):
        digest = _hash(f"sample-artifact-{i}")
        value = {0: digest, 1: digest[:40], 2: digest[:32]}[i % 3]
        rows.append({
            "indicator": value,
            "threat_type": RNG.choice(["malware_delivery", "botnet", "unknown"]),
            "severity": RNG.choice(SEVERITIES),
            "first_seen": (base + timedelta(hours=i * 2)).isoformat(),
            "source": RNG.choice(SOURCES),
            "description": "Synthetic sample record for pipeline demonstration",
        })

    # --- deliberate duplicates (same indicator, same source) ---
    rows.extend([dict(r) for r in RNG.sample(rows, 12)])

    # --- deliberate malformed rows for the validation stage to reject ---
    rows.extend([
        {"indicator": "", "threat_type": "phishing", "severity": "high",
         "first_seen": base.isoformat(), "source": "opensource_feed_a",
         "description": "empty indicator"},
        {"indicator": "999.999.999.999", "threat_type": "scanning", "severity": "medium",
         "first_seen": base.isoformat(), "source": "opensource_feed_a",
         "description": "invalid octets"},
        {"indicator": "not a real indicator", "threat_type": "unknown", "severity": "low",
         "first_seen": base.isoformat(), "source": "opensource_feed_b",
         "description": "unrecognised format"},
        {"indicator": "192.0.2.55", "threat_type": "botnet", "severity": "urgent",
         "first_seen": "not-a-timestamp", "source": "opensource_feed_b",
         "description": "bad severity and bad timestamp"},
        {"indicator": "cdn3.example.com", "threat_type": "", "severity": "",
         "first_seen": "", "source": "", "description": "missing fields"},
    ])

    RNG.shuffle(rows)
    return rows


def write_sample_files():
    rows = _rows()
    fields = ["indicator", "threat_type", "severity", "first_seen", "source", "description"]
    with open(config.SAMPLE_IOC_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    # a second source in a different shape, to prove normalization does work
    log_fields = ["event_time", "src_ip", "event_category", "risk_label", "sensor"]
    log_rows = []
    base = datetime(2026, 8, 5, 0, 0, 0)
    for i in range(30):
        block = RNG.choice(["192.0.2", "198.51.100", "203.0.113"])
        log_rows.append({
            "event_time": (base + timedelta(minutes=i * 37)).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": f"{block}.{RNG.randint(1, 254)}",
            "event_category": RNG.choice(["scanning", "brute_force", "data_exfiltration"]),
            "risk_label": RNG.choice(["High", "Medium", "Low"]),
            "sensor": RNG.choice(["ids-01", "ids-02", "fw-edge"]),
        })
    with open(config.SAMPLE_LOG_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=log_fields)
        writer.writeheader()
        writer.writerows(log_rows)

    return len(rows), len(log_rows)




# --------------------------------------------------------------------------
# Labelled training data
# --------------------------------------------------------------------------
# HONESTY NOTE — READ THIS BEFORE QUOTING ANY ACCURACY FIGURE.
#
# The labels below are generated from a documented scoring rule plus random
# noise. A model trained on this data is therefore learning to recover a rule
# that this file invented. The resulting metrics measure whether the training
# pipeline works; they say NOTHING about real-world detection performance.
#
# To train on real data instead, drop a CSV with the columns
#   indicator, indicator_type, threat_type, severity, source, first_seen, label
# at data/labelled_training_data.csv and re-run training. No code changes.

THREAT_WEIGHT = {
    "command_and_control": 0.90, "data_exfiltration": 0.85, "malware_delivery": 0.80,
    "botnet": 0.75, "phishing": 0.70, "brute_force": 0.50, "scanning": 0.35,
    "unknown": 0.30,
}
SEVERITY_WEIGHT = {"critical": 0.95, "high": 0.75, "medium": 0.45, "low": 0.20}
TYPE_WEIGHT = {
    "url": 0.70, "domain": 0.60, "ipv4": 0.50,
    "sha256": 0.65, "sha1": 0.60, "md5": 0.55,
}
SUSPICIOUS_TOKENS = ("login", "verify", "secure", "account", "update", "confirm")


def _label_for(threat_type, severity, indicator_type, indicator, rng):
    """Documented labelling rule: weighted score + gaussian noise -> class."""
    score = (0.40 * THREAT_WEIGHT.get(threat_type, 0.3)
             + 0.35 * SEVERITY_WEIGHT.get(severity, 0.3)
             + 0.15 * TYPE_WEIGHT.get(indicator_type, 0.5)
             + 0.10 * (1.0 if any(t in indicator.lower() for t in SUSPICIOUS_TOKENS) else 0.0))
    score += rng.gauss(0, 0.05)          # noise: the model cannot reach 100%
    if score >= 0.68:
        return "malicious"
    if score >= 0.47:
        return "suspicious"
    return "benign"


def write_training_dataset(n_rows: int = 1400):
    rng = random.Random(4242)
    base = datetime(2026, 6, 1)
    rows = []
    for i in range(n_rows):
        itype = rng.choices(
            ["ipv4", "domain", "url", "md5", "sha1", "sha256"],
            weights=[38, 20, 16, 9, 8, 9])[0]
        if itype == "ipv4":
            indicator = f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(1, 254)}"
        elif itype == "domain":
            indicator = f"{rng.choice(['cdn', 'mail', 'login', 'update', 'api', 'static'])}{i}.example.com"
        elif itype == "url":
            indicator = (f"http://{rng.choice(['secure', 'account', 'verify', 'files', 'img'])}"
                         f"{i}.example.org/{rng.choice(['login', 'index', 'download', 'a'])}")
        else:
            digest = _hash(f"training-artifact-{i}")
            indicator = {"md5": digest[:32], "sha1": digest[:40], "sha256": digest}[itype]

        threat_type = rng.choice(THREAT_TYPES)
        severity = rng.choices(SEVERITIES, weights=[15, 30, 35, 20])[0]
        rows.append({
            "indicator": indicator,
            "indicator_type": itype,
            "threat_type": threat_type,
            "severity": severity,
            "source": rng.choice(SOURCES),
            "first_seen": (base + timedelta(hours=rng.randint(0, 1700))).isoformat(),
            "label": _label_for(threat_type, severity, itype, indicator, rng),
        })

    path = config.DATA_DIR / "labelled_training_data.csv"
    fields = ["indicator", "indicator_type", "threat_type", "severity",
              "source", "first_seen", "label"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return len(rows), path


if __name__ == "__main__":
    n_ioc, n_log = write_sample_files()
    print(f"Wrote {n_ioc} IOC rows  -> {config.SAMPLE_IOC_CSV}")
    print(f"Wrote {n_log} event rows -> {config.SAMPLE_LOG_CSV}")
    n_train, train_path = write_training_dataset()
    print(f"Wrote {n_train} labelled training rows -> {train_path}")
