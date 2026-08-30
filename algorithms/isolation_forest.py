"""Unsupervised Isolation Forest detector for SaaS activity."""

from __future__ import annotations

from typing import Iterable, Tuple

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


DEFAULT_FEATURES: Tuple[str, ...] = ("requests", "data_uploaded_mb", "activity_hour")


def _prepare_features(data: pd.DataFrame, features: Iterable[str]) -> pd.DataFrame:
    """Return temporary numeric SaaS features without modifying the input data."""
    required = {"timestamp", "requests", "data_uploaded_mb"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")

    temporary = data.copy(deep=True)
    temporary["activity_hour"] = pd.to_datetime(temporary["timestamp"], errors="raise").dt.hour
    selected = list(features)
    if not selected or set(selected) - set(temporary.columns):
        raise ValueError("Selected Isolation Forest features are invalid or unavailable.")
    numeric = temporary[selected].apply(pd.to_numeric, errors="raise")
    if numeric.isna().any().any():
        raise ValueError("Isolation Forest features cannot contain missing values.")
    return numeric


def detect_isolation_forest_anomalies(
    data: pd.DataFrame,
    features: Iterable[str] = DEFAULT_FEATURES,
    contamination: float = 0.20,
    random_state: int = 42,
) -> tuple[pd.Series, dict]:
    """Fit Isolation Forest without labels and return binary anomaly predictions.

    ``contamination`` is an operating assumption: the expected fraction of
    unusual SaaS activity. It is deliberately fixed before evaluation and does
    not use the ground-truth labels.  Isolation Forest returns -1 for anomalies
    and 1 for normal observations; this function converts it to 1 and 0.
    """
    if not 0 < contamination < 0.5:
        raise ValueError("contamination must be greater than 0 and less than 0.5.")

    detector, details = fit_isolation_forest(data, features, contamination, random_state)
    return predict_isolation_forest_anomalies(data, detector), details


def fit_isolation_forest(
    training_data: pd.DataFrame,
    features: Iterable[str] = DEFAULT_FEATURES,
    contamination: float = 0.20,
    random_state: int = 42,
) -> tuple[dict, dict]:
    """Fit Isolation Forest on unlabeled training records only."""
    if not 0 < contamination < 0.5:
        raise ValueError("contamination must be greater than 0 and less than 0.5.")
    numeric = _prepare_features(training_data, features)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(numeric)
    model = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=200)
    model.fit(scaled)
    detector = {"features": list(numeric.columns), "scaler": scaler, "model": model}
    training_predictions = (model.predict(scaled) == -1).astype(int)
    details = {
        "features": list(numeric.columns),
        "contamination": contamination,
        "random_state": random_state,
        "predicted_anomalies": int(training_predictions.sum()),
        "predicted_normal": int((training_predictions == 0).sum()),
    }
    return detector, details


def predict_isolation_forest_anomalies(data: pd.DataFrame, detector: dict) -> pd.Series:
    """Convert predictions from an already fitted Isolation Forest to 0/1 labels."""
    numeric = _prepare_features(data, detector["features"])
    raw_predictions = detector["model"].predict(detector["scaler"].transform(numeric))
    return pd.Series((raw_predictions == -1).astype(int), index=data.index, name="isolation_forest_prediction")
