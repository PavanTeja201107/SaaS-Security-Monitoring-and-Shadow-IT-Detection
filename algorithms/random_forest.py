"""Supervised Random Forest classifier for labelled SaaS anomalies."""

from __future__ import annotations

from typing import Iterable, Tuple

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


DEFAULT_FEATURES: Tuple[str, ...] = ("requests", "data_uploaded_mb", "activity_hour")


def _prepare_features(data: pd.DataFrame, features: Iterable[str]) -> pd.DataFrame:
    """Build model features from activity data, excluding the target label."""
    required = {"timestamp", "requests", "data_uploaded_mb"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")

    temporary = data.copy(deep=True)
    temporary["activity_hour"] = pd.to_datetime(temporary["timestamp"], errors="raise").dt.hour
    selected = list(features)
    if not selected or set(selected) - set(temporary.columns):
        raise ValueError("Selected Random Forest features are invalid or unavailable.")
    numeric = temporary[selected].apply(pd.to_numeric, errors="raise")
    if numeric.isna().any().any():
        raise ValueError("Random Forest features cannot contain missing values.")
    return numeric


def train_random_forest(
    data: pd.DataFrame,
    features: Iterable[str] = DEFAULT_FEATURES,
    test_size: float = 0.25,
    random_state: int = 42,
) -> tuple[RandomForestClassifier, pd.Series, pd.Series, dict]:
    """Train on a stratified split and return predictions for the unseen test set.

    The label is used only after feature preparation to split and train the
    supervised model. Metrics must be calculated only from the returned test
    labels and predictions, avoiding train/test leakage.
    """
    if "ground_truth" not in data.columns:
        raise ValueError("Random Forest requires the ground_truth column for supervised training.")
    if not 0 < test_size < 0.5:
        raise ValueError("test_size must be greater than 0 and less than 0.5.")

    X = _prepare_features(data, features)
    y = pd.to_numeric(data["ground_truth"], errors="raise").astype(int)
    if not set(y.unique()).issubset({0, 1}) or y.nunique() < 2:
        raise ValueError("ground_truth must contain both binary classes 0 and 1.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=random_state,
        class_weight="balanced",
        # One worker avoids platform-specific worker/core discovery warnings.
        n_jobs=1,
    )
    model.fit(X_train, y_train)
    predictions = pd.Series(model.predict(X_test), index=y_test.index, name="random_forest_prediction")
    details = {
        "features": list(X.columns),
        "train_records": int(len(X_train)),
        "test_records": int(len(X_test)),
        "test_size": test_size,
        "random_state": random_state,
        "feature_importance": {
            feature: round(float(importance), 4)
            for feature, importance in zip(X.columns, model.feature_importances_)
        },
    }
    return model, y_test, predictions, details
