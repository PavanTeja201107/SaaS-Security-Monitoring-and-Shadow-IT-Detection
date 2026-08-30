"""Simple user and time-window correlation of SaaS and cloud security alerts."""

from __future__ import annotations

import json
from typing import Iterable

import pandas as pd

from risk.risk_score import calculate_risk_score


INCIDENT_COLUMNS = ["incident_id", "user_id", "events", "risk_score", "risk_level", "reason"]
ALERT_COLUMNS = ["event_id", "user_id", "timestamp", "alert_type", "severity", "reason"]


def _validate_alerts(alerts: pd.DataFrame, name: str) -> None:
    missing = set(ALERT_COLUMNS) - set(alerts.columns)
    if missing:
        raise ValueError(f"{name} alerts are missing columns: {sorted(missing)}")


def _build_security_events(
    shadow_it_alerts: pd.DataFrame,
    shadow_ai_alerts: pd.DataFrame,
    cloud_alerts: pd.DataFrame,
    saas_data: pd.DataFrame,
    cloud_data: pd.DataFrame,
    large_upload_threshold_mb: float,
) -> pd.DataFrame:
    """Combine alert outputs and attach cloud IP/resource context by event ID."""
    for name, alerts in {
        "Shadow IT": shadow_it_alerts,
        "Shadow AI": shadow_ai_alerts,
        "Cloud security": cloud_alerts,
    }.items():
        _validate_alerts(alerts, name)
    required_saas = {"event_id", "user_id", "timestamp", "data_uploaded_mb"}
    required_cloud = {"event_id", "source_ip", "resource"}
    if required_saas - set(saas_data.columns):
        raise ValueError("SaaS data is missing fields required for correlation.")
    if required_cloud - set(cloud_data.columns):
        raise ValueError("Cloud data is missing fields required for correlation.")
    if large_upload_threshold_mb <= 0:
        raise ValueError("large_upload_threshold_mb must be positive.")

    alert_events = pd.concat([shadow_it_alerts, shadow_ai_alerts, cloud_alerts], ignore_index=True)
    cloud_context = cloud_data[["event_id", "source_ip", "resource"]].copy()
    events = alert_events.merge(cloud_context, on="event_id", how="left")

    large_uploads = saas_data.loc[saas_data["data_uploaded_mb"] >= large_upload_threshold_mb].copy()
    upload_events = pd.DataFrame(
        {
            "event_id": large_uploads["event_id"],
            "user_id": large_uploads["user_id"],
            "timestamp": large_uploads["timestamp"],
            "alert_type": "Large Data Upload",
            "severity": "High",
            "reason": "SaaS upload of " + large_uploads["data_uploaded_mb"].round(2).astype(str) + f" MB exceeds {large_upload_threshold_mb} MB.",
            "source_ip": pd.NA,
            "resource": pd.NA,
        }
    )
    events = pd.concat([events, upload_events], ignore_index=True)
    events["parsed_timestamp"] = pd.to_datetime(events["timestamp"], errors="raise")
    return events.sort_values(["user_id", "parsed_timestamp", "event_id"]).reset_index(drop=True)


def _split_time_groups(events: pd.DataFrame, time_window: pd.Timedelta) -> Iterable[pd.DataFrame]:
    """Yield groups per user, starting a new incident after a time gap."""
    for _, user_events in events.groupby("user_id", sort=True):
        user_events = user_events.sort_values("parsed_timestamp")
        group_start = 0
        previous_time = user_events.iloc[0]["parsed_timestamp"]
        for position in range(1, len(user_events)):
            current_time = user_events.iloc[position]["parsed_timestamp"]
            if current_time - previous_time > time_window:
                yield user_events.iloc[group_start:position]
                group_start = position
            previous_time = current_time
        yield user_events.iloc[group_start:]


def _incident_reason(group: pd.DataFrame, contributions: dict[str, int]) -> str:
    indicators = ", ".join(f"{indicator} (+{weight})" for indicator, weight in contributions.items()) or "unweighted security alerts"
    start = group["parsed_timestamp"].min().strftime("%Y-%m-%d %H:%M")
    end = group["parsed_timestamp"].max().strftime("%Y-%m-%d %H:%M")
    reason = f"{len(group)} related alerts from {start} to {end}; indicators: {indicators}."
    external_ips = group["source_ip"].dropna().astype(str)
    external_ips = external_ips[~external_ips.str.startswith("10.10.")].unique().tolist()
    resources = group["resource"].dropna().astype(str).unique().tolist()
    if external_ips:
        reason += " External IP context: " + ", ".join(external_ips[:3]) + "."
    if resources:
        reason += " Resource context: " + ", ".join(resources[:3]) + "."
    return reason


def correlate_events(
    shadow_it_alerts: pd.DataFrame,
    shadow_ai_alerts: pd.DataFrame,
    cloud_alerts: pd.DataFrame,
    saas_data: pd.DataFrame,
    cloud_data: pd.DataFrame,
    time_window_hours: int = 12,
    large_upload_threshold_mb: float = 150.0,
) -> pd.DataFrame:
    """Return simple incidents correlated by user and a 12-hour default window.

    Events belonging to one user stay in one incident while consecutive events
    are no more than the selected time window apart. IP and resource fields are
    used to enrich the incident reason when cloud alerts are present.
    """
    if time_window_hours <= 0:
        raise ValueError("time_window_hours must be positive.")
    events = _build_security_events(
        shadow_it_alerts, shadow_ai_alerts, cloud_alerts, saas_data, cloud_data, large_upload_threshold_mb
    )
    if events.empty:
        return pd.DataFrame(columns=INCIDENT_COLUMNS)

    records = []
    for number, group in enumerate(_split_time_groups(events, pd.Timedelta(hours=time_window_hours)), start=1):
        score, level, contributions = calculate_risk_score(group["alert_type"])
        event_details = [
            {
                "event_id": row.event_id,
                "timestamp": row.timestamp,
                "alert_type": row.alert_type,
                "severity": row.severity,
                "source_ip": None if pd.isna(row.source_ip) else row.source_ip,
                "resource": None if pd.isna(row.resource) else row.resource,
            }
            for row in group.itertuples(index=False)
        ]
        records.append(
            {
                "incident_id": f"INC-{number:04d}",
                "user_id": group.iloc[0]["user_id"],
                "events": json.dumps(event_details),
                "risk_score": score,
                "risk_level": level,
                "reason": _incident_reason(group, contributions),
            }
        )
    return pd.DataFrame(records, columns=INCIDENT_COLUMNS)
