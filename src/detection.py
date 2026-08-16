"""
Stage 4 - Threat Detection and Classification.

A Random Forest classifier assigns each indicator one of three labels
(malicious / suspicious / benign) together with a confidence value. The
confidence feeds directly into risk scoring, so it must be a real predicted
probability rather than a fixed number.

    python -m src.detection --train      train and evaluate, save the model
    python -m src.detection              show the saved evaluation report

READ THIS BEFORE QUOTING ACCURACY
---------------------------------
By default the model trains on data/labelled_training_data.csv, which is
SYNTHETIC. Its labels come from a documented rule in make_sample_data.py plus
random noise, so the metrics measure whether the training pipeline works, not
whether the platform detects real threats. Replace that CSV with a real
labelled dataset (same columns) to obtain meaningful figures.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

MODEL_PATH = config.MODEL_DIR / "trained_model.pkl"
METRICS_PATH = config.MODEL_DIR / "evaluation_metrics.json"
TRAINING_CSV = config.DATA_DIR / "labelled_training_data.csv"

CATEGORICAL = ["indicator_type", "threat_type", "severity", "source"]
NUMERIC = ["indicator_length", "digit_ratio", "entropy", "suspicious_token", "dot_count"]
CLASSES = ["benign", "suspicious", "malicious"]

SUSPICIOUS_TOKENS = ("login", "verify", "secure", "account", "update", "confirm",
                     "download", "invoice", "reset")


def _entropy(text: str) -> float:
    """Shannon entropy of the indicator string. Random-looking hostnames and
    generated domains score higher than human-readable ones."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build the model input from normalized indicator records.

    Used for both training and prediction, so the two can never drift apart.
    """
    out = pd.DataFrame(index=df.index)
    indicators = df["indicator"].astype(str)

    for col in CATEGORICAL:
        out[col] = df[col].astype(str).fillna("unknown").replace("", "unknown")

    out["indicator_length"] = indicators.str.len()
    out["digit_ratio"] = indicators.apply(
        lambda s: sum(ch.isdigit() for ch in s) / len(s) if s else 0.0)
    out["entropy"] = indicators.apply(_entropy)
    out["suspicious_token"] = indicators.str.lower().apply(
        lambda s: int(any(t in s for t in SUSPICIOUS_TOKENS)))
    out["dot_count"] = indicators.str.count(r"\.")
    return out


def build_pipeline() -> Pipeline:
    pre = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
        ("num", StandardScaler(), NUMERIC),
    ])
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1)
    return Pipeline([("preprocess", pre), ("classifier", clf)])


def train(csv_path: Path | None = None, test_size: float = 0.25) -> dict:
    csv_path = Path(csv_path or TRAINING_CSV)
    if not csv_path.exists():
        raise FileNotFoundError(
            f"Training data not found at {csv_path}. Run: python src/make_sample_data.py")

    df = pd.read_csv(csv_path)
    missing = {"indicator", "label"} - set(df.columns)
    if missing:
        raise ValueError(f"Training data is missing required columns: {missing}")

    X = extract_features(df)
    y = df["label"].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y)

    pipe = build_pipeline()
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)

    labels = sorted(y.unique())
    cv = cross_val_score(build_pipeline(), X, y, cv=5, scoring="f1_macro")

    metrics = {
        "training_data": str(csv_path.name),
        "synthetic_training_data": csv_path.name == "labelled_training_data.csv",
        "n_total": int(len(df)),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "class_distribution": {k: int(v) for k, v in y.value_counts().items()},
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "f1_macro": round(float(f1_score(y_test, y_pred, average="macro")), 4),
        "cv_f1_macro_mean": round(float(cv.mean()), 4),
        "cv_f1_macro_std": round(float(cv.std()), 4),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_test, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(
            y_test, y_pred, labels=labels, output_dict=True, zero_division=0),
    }

    joblib.dump(pipe, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    return metrics


_MODEL_CACHE = None


def load_model(force_reload: bool = False):
    """Load the saved model once and reuse it."""
    global _MODEL_CACHE
    if _MODEL_CACHE is None or force_reload:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"No trained model at {MODEL_PATH}. Run: python -m src.detection --train")
        _MODEL_CACHE = joblib.load(MODEL_PATH)
    return _MODEL_CACHE


def load_metrics() -> dict:
    if METRICS_PATH.exists():
        return json.loads(METRICS_PATH.read_text())
    return {}


def predict(df: pd.DataFrame) -> pd.DataFrame:
    """
    Classify normalized indicator records.

    Returns the input with predicted_label and detection_confidence added.
    Confidence is the predicted probability of the assigned class.
    """
    if df.empty:
        out = df.copy()
        out["predicted_label"] = []
        out["detection_confidence"] = []
        return out

    model = load_model()
    X = extract_features(df)
    labels = model.predict(X)
    probabilities = model.predict_proba(X)
    class_order = list(model.named_steps["classifier"].classes_)

    confidences = [
        float(row[class_order.index(label)])
        for row, label in zip(probabilities, labels)
    ]

    out = df.copy()
    out["predicted_label"] = labels
    out["detection_confidence"] = [round(c, 4) for c in confidences]
    return out


def format_metrics(metrics: dict) -> str:
    if not metrics:
        return "No evaluation metrics found. Run: python -m src.detection --train"
    lines = [
        f"Training data      : {metrics['training_data']}",
        f"Records            : {metrics['n_total']} "
        f"({metrics['n_train']} train / {metrics['n_test']} test)",
        f"Class distribution : {metrics['class_distribution']}",
        "",
        f"Accuracy           : {metrics['accuracy']}",
        f"F1 (macro)         : {metrics['f1_macro']}",
        f"5-fold CV F1       : {metrics['cv_f1_macro_mean']} "
        f"(+/- {metrics['cv_f1_macro_std']})",
        "",
        "Confusion matrix (rows = actual, columns = predicted)",
        "                " + "".join(f"{c:>12}" for c in metrics["labels"]),
    ]
    for label, row in zip(metrics["labels"], metrics["confusion_matrix"]):
        lines.append(f"{label:>15} " + "".join(f"{v:>12}" for v in row))

    if metrics.get("synthetic_training_data"):
        lines += [
            "",
            "!! These figures come from SYNTHETIC training data whose labels were",
            "!! generated by a rule in make_sample_data.py. They demonstrate that the",
            "!! training pipeline works. They are NOT real-world detection performance",
            "!! and must not be presented as such.",
        ]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true", help="train and evaluate the model")
    ap.add_argument("--data", default=None, help="path to a labelled CSV")
    args = ap.parse_args()

    if args.train:
        m = train(args.data)
        print(format_metrics(m))
    else:
        print(format_metrics(load_metrics()))
