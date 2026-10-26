"""User-specific historical activity baselines for SaaS behaviour deviations."""

from __future__ import annotations

import pandas as pd

from config import BEHAVIORAL_MINIMUM_HISTORY, BEHAVIORAL_RATIO_THRESHOLD
from detection.shadow_it import ALERT_COLUMNS


ANALYSIS_COLUMNS = [
    "event_id",
    "user_id",
    "timestamp",
    "requests",
    "data_uploaded_mb",
    "historical_request_baseline",
    "historical_upload_baseline_mb",
    "request_deviation_ratio",
    "upload_deviation_ratio",
    "behavioral_alert",
    "behavioral_explanation",
]


def calculate_user_baselines(
    data: pd.DataFrame,
    minimum_history: int = BEHAVIORAL_MINIMUM_HISTORY,
    request_ratio_threshold: float = BEHAVIORAL_RATIO_THRESHOLD,
    upload_ratio_threshold: float = BEHAVIORAL_RATIO_THRESHOLD,
) -> pd.DataFrame:
    """Compare every activity with only the same user's earlier activity.

    Historical medians are used as the typical request count and upload volume.
    The ``shift(1)`` operation is critical: it removes the current event before
    calculating its baseline, preventing current-row data leakage.
    """
    required = {"event_id", "user_id", "timestamp", "requests", "data_uploaded_mb"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")
    if minimum_history < 1:
        raise ValueError("minimum_history must be at least 1.")
    if request_ratio_threshold <= 1 or upload_ratio_threshold <= 1:
        raise ValueError("Deviation thresholds must be greater than 1.")

    work = data.copy(deep=True)
    work["parsed_timestamp"] = pd.to_datetime(work["timestamp"], errors="raise")
    work["requests"] = pd.to_numeric(work["requests"], errors="raise")
    work["data_uploaded_mb"] = pd.to_numeric(work["data_uploaded_mb"], errors="raise")
    work = work.sort_values(["user_id", "parsed_timestamp", "event_id"]).copy()

    by_user = work.groupby("user_id", sort=False)
    work["historical_request_baseline"] = by_user["requests"].transform(
        lambda values: values.expanding(min_periods=minimum_history).median().shift(1)
    )
    work["historical_upload_baseline_mb"] = by_user["data_uploaded_mb"].transform(
        lambda values: values.expanding(min_periods=minimum_history).median().shift(1)
    )
    work["request_deviation_ratio"] = work["requests"] / work["historical_request_baseline"].clip(lower=0.1)
    work["upload_deviation_ratio"] = work["data_uploaded_mb"] / work["historical_upload_baseline_mb"].clip(lower=0.1)

    has_history = work["historical_request_baseline"].notna() & work["historical_upload_baseline_mb"].notna()
    request_deviation = has_history & work["request_deviation_ratio"].ge(request_ratio_threshold)
    upload_deviation = has_history & work["upload_deviation_ratio"].ge(upload_ratio_threshold)
    work["behavioral_alert"] = request_deviation | upload_deviation

    explanations = []
    for _, row in work.iterrows():
        details = []
        if row["behavioral_alert"] and request_deviation.loc[row.name]:
            details.append(
                f"Requests {int(row['requests'])} vs historical median {row['historical_request_baseline']:.2f} "
                f"({row['request_deviation_ratio']:.2f}x)."
            )
        if row["behavioral_alert"] and upload_deviation.loc[row.name]:
            details.append(
                f"Upload {row['data_uploaded_mb']:.2f} MB vs historical median {row['historical_upload_baseline_mb']:.2f} MB "
                f"({row['upload_deviation_ratio']:.2f}x)."
            )
        if not details:
            details.append("No significant deviation or insufficient prior history for this user.")
        explanations.append(" ".join(details))
    work["behavioral_explanation"] = explanations

    return work.reindex(columns=ANALYSIS_COLUMNS).sort_values("timestamp").reset_index(drop=True)


def detect_behavioral_deviations(data: pd.DataFrame, **settings: object) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return full baseline analysis and structured alerts for significant deviations."""
    analysis = calculate_user_baselines(data, **settings)
    matches = analysis.loc[analysis["behavioral_alert"]].copy()
    alerts = pd.DataFrame(
        {
            "event_id": matches["event_id"],
            "user_id": matches["user_id"],
            "timestamp": matches["timestamp"],
            "alert_type": "Behavioral Deviation",
            "severity": "Medium",
            "reason": matches["behavioral_explanation"],
        }
    )
    return analysis, alerts.reindex(columns=ALERT_COLUMNS).reset_index(drop=True)


def calculate_baselines_from_history(
    activity: pd.DataFrame,
    historical_data: pd.DataFrame,
    minimum_history: int = BEHAVIORAL_MINIMUM_HISTORY,
    request_ratio_threshold: float = BEHAVIORAL_RATIO_THRESHOLD,
    upload_ratio_threshold: float = BEHAVIORAL_RATIO_THRESHOLD,
) -> pd.DataFrame:
    """Evaluate activity using only earlier records from a separate history set.

    This is used for holdout evaluation: no other heldout event can influence a
    baseline, and records at or after the current timestamp are excluded.
    """
    required = {"event_id", "user_id", "timestamp", "requests", "data_uploaded_mb"}
    for name, frame in {"activity": activity, "historical_data": historical_data}.items():
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(f"{name} is missing required columns: {sorted(missing)}")
    if minimum_history < 1 or request_ratio_threshold <= 1 or upload_ratio_threshold <= 1:
        raise ValueError("minimum_history must be positive and thresholds must be greater than 1.")

    history = historical_data.copy(deep=True)
    history["parsed_timestamp"] = pd.to_datetime(history["timestamp"], errors="raise")
    rows = []
    for event in activity.copy(deep=True).assign(parsed_timestamp=pd.to_datetime(activity["timestamp"], errors="raise")).sort_values(["user_id", "parsed_timestamp", "event_id"]).itertuples(index=False):
        earlier = history.loc[(history["user_id"] == event.user_id) & (history["parsed_timestamp"] < event.parsed_timestamp)]
        request_baseline = earlier["requests"].median() if len(earlier) >= minimum_history else float("nan")
        upload_baseline = earlier["data_uploaded_mb"].median() if len(earlier) >= minimum_history else float("nan")
        request_ratio = event.requests / max(request_baseline, 0.1) if pd.notna(request_baseline) else float("nan")
        upload_ratio = event.data_uploaded_mb / max(upload_baseline, 0.1) if pd.notna(upload_baseline) else float("nan")
        request_alert = pd.notna(request_ratio) and request_ratio >= request_ratio_threshold
        upload_alert = pd.notna(upload_ratio) and upload_ratio >= upload_ratio_threshold
        explanation = "No significant deviation or insufficient historical training data for this user."
        if request_alert or upload_alert:
            parts = []
            if request_alert:
                parts.append(f"Requests {int(event.requests)} vs training-history median {request_baseline:.2f} ({request_ratio:.2f}x).")
            if upload_alert:
                parts.append(f"Upload {event.data_uploaded_mb:.2f} MB vs training-history median {upload_baseline:.2f} MB ({upload_ratio:.2f}x).")
            explanation = " ".join(parts)
        rows.append({
            "event_id": event.event_id, "user_id": event.user_id, "timestamp": event.timestamp,
            "requests": event.requests, "data_uploaded_mb": event.data_uploaded_mb,
            "historical_request_baseline": request_baseline, "historical_upload_baseline_mb": upload_baseline,
            "request_deviation_ratio": request_ratio, "upload_deviation_ratio": upload_ratio,
            "behavioral_alert": request_alert or upload_alert, "behavioral_explanation": explanation,
        })
    return pd.DataFrame(rows, columns=ANALYSIS_COLUMNS)
