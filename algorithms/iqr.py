"""Explainable IQR baseline for SaaS activity anomaly detection."""

from __future__ import annotations

from typing import Iterable, Tuple

import pandas as pd


DEFAULT_FEATURES: Tuple[str, ...] = ("requests", "data_uploaded_mb", "activity_hour")


def _prepare_features(data: pd.DataFrame, features: Iterable[str]) -> pd.DataFrame:
    """Return a temporary numeric feature frame without changing the source data."""
    required = {"timestamp", "requests", "data_uploaded_mb"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")

    feature_frame = data.copy(deep=True)
    feature_frame["activity_hour"] = pd.to_datetime(feature_frame["timestamp"], errors="raise").dt.hour
    selected = list(features)
    if not selected:
        raise ValueError("At least one IQR feature must be selected.")
    if set(selected) - set(feature_frame.columns):
        raise ValueError("One or more selected IQR features are unavailable.")

    numeric = feature_frame[selected].apply(pd.to_numeric, errors="raise")
    if numeric.isna().any().any():
        raise ValueError("IQR features cannot contain missing values.")
    return numeric


def calculate_iqr_bounds(data: pd.DataFrame, features: Iterable[str] = DEFAULT_FEATURES) -> pd.DataFrame:
    """Calculate lower and upper IQR limits for each selected activity feature."""
    numeric = _prepare_features(data, features)
    q1 = numeric.quantile(0.25)
    q3 = numeric.quantile(0.75)
    iqr = q3 - q1
    return pd.DataFrame({"q1": q1, "q3": q3, "iqr": iqr, "lower_bound": q1 - 1.5 * iqr, "upper_bound": q3 + 1.5 * iqr})


def predict_iqr_outliers(data: pd.DataFrame, bounds: pd.DataFrame, features: Iterable[str] = DEFAULT_FEATURES) -> pd.Series:
    """Apply previously fitted IQR bounds to new data without refitting them."""
    numeric = _prepare_features(data, features)
    required_bounds = {"lower_bound", "upper_bound"}
    if not required_bounds.issubset(bounds.columns) or not set(numeric.columns).issubset(bounds.index):
        raise ValueError("IQR bounds do not match the selected features.")
    outlier_by_feature = numeric.lt(bounds.loc[numeric.columns, "lower_bound"], axis="columns") | numeric.gt(
        bounds.loc[numeric.columns, "upper_bound"], axis="columns"
    )
    return outlier_by_feature.any(axis="columns").astype(int).rename("iqr_prediction")


def detect_iqr_outliers(data: pd.DataFrame, features: Iterable[str] = DEFAULT_FEATURES) -> pd.Series:
    """Return 1 when any selected feature is outside its IQR bounds, otherwise 0.

    Features are requests, data uploaded, and a derived hour-of-day value.  The
    hour is calculated in a temporary frame, so the original DataFrame remains
    unchanged.
    """
    bounds = calculate_iqr_bounds(data, features)
    return predict_iqr_outliers(data, bounds, features)
