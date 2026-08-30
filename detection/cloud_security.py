"""Simple, explainable rule-based detections for CloudTrail-style audit logs."""

from __future__ import annotations

from typing import Iterable

import pandas as pd

from detection.shadow_it import ALERT_COLUMNS


DEFAULT_KNOWN_IP_PREFIXES = ("10.10.",)
DEFAULT_SENSITIVE_RESOURCES = ("s3://finance-backups", "s3://customer-exports")


def _validate_cloud_data(data: pd.DataFrame) -> pd.DataFrame:
    required = {"event_id", "user_id", "timestamp", "event_name", "resource", "source_ip"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"Cloud audit data is missing required columns: {sorted(missing)}")
    prepared = data.copy(deep=True)
    prepared["parsed_timestamp"] = pd.to_datetime(prepared["timestamp"], errors="raise")
    return prepared


def _make_alerts(matches: pd.DataFrame, alert_type: str, severity: str, reasons: pd.Series | str) -> pd.DataFrame:
    if isinstance(reasons, str):
        reasons = pd.Series(reasons, index=matches.index)
    alerts = pd.DataFrame(
        {
            "event_id": matches["event_id"],
            "user_id": matches["user_id"],
            "timestamp": matches["timestamp"],
            "alert_type": alert_type,
            "severity": severity,
            "reason": reasons,
        }
    )
    return alerts.reindex(columns=ALERT_COLUMNS)


def detect_cloud_security_alerts(
    data: pd.DataFrame,
    known_ip_prefixes: Iterable[str] = DEFAULT_KNOWN_IP_PREFIXES,
    sensitive_resources: Iterable[str] = DEFAULT_SENSITIVE_RESOURCES,
    api_window: str = "5min",
    api_event_threshold: int = 3,
) -> pd.DataFrame:
    """Return structured alerts from five readable cloud-security rules.

    Rules identify external/unknown IPs, activity from 22:00--05:59,
    CreateAccessKey actions, three or more user API calls in one five-minute
    window, and accesses to configured sensitive resources. One audit event may
    legitimately generate more than one alert when it breaks several rules.
    """
    if api_event_threshold < 2:
        raise ValueError("api_event_threshold must be at least 2.")
    prepared = _validate_cloud_data(data)
    known_prefixes = tuple(str(prefix) for prefix in known_ip_prefixes)
    if not known_prefixes:
        raise ValueError("At least one known IP prefix is required.")
    sensitive = {str(resource) for resource in sensitive_resources}

    alerts: list[pd.DataFrame] = []
    known_ip = prepared["source_ip"].astype(str).str.startswith(known_prefixes)
    unknown_ip_rows = prepared.loc[~known_ip]
    alerts.append(_make_alerts(unknown_ip_rows, "Unknown IP", "Medium", "Source IP is outside configured internal IP ranges."))

    unusual_time = prepared["parsed_timestamp"].dt.hour.isin([0, 1, 2, 3, 4, 5, 22, 23])
    unusual_time_rows = prepared.loc[unusual_time]
    alerts.append(_make_alerts(unusual_time_rows, "Unusual Access Time", "Medium", "Cloud activity occurred outside normal working hours."))

    access_key_rows = prepared.loc[prepared["event_name"].eq("CreateAccessKey")]
    alerts.append(_make_alerts(access_key_rows, "Create Access Key", "High", "CreateAccessKey can create persistent programmatic access."))

    prepared["api_window"] = prepared["parsed_timestamp"].dt.floor(api_window)
    api_counts = prepared.groupby(["user_id", "api_window"])["event_id"].transform("count")
    api_rows = prepared.loc[api_counts >= api_event_threshold].copy()
    api_reasons = api_counts.loc[api_rows.index].astype(int).map(
        lambda count: f"{count} API events by this user within a {api_window} window."
    )
    alerts.append(_make_alerts(api_rows, "Abnormal API Activity", "Medium", api_reasons))

    resource_rows = prepared.loc[prepared["resource"].astype(str).isin(sensitive)]
    resource_reasons = "Access to configured sensitive resource: " + resource_rows["resource"].astype(str)
    alerts.append(_make_alerts(resource_rows, "Unusual Resource Access", "High", resource_reasons))

    non_empty = [alert for alert in alerts if not alert.empty]
    if not non_empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    return pd.concat(non_empty, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
