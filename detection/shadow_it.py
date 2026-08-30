"""Rule-based detection of unauthorized non-AI SaaS applications."""

from __future__ import annotations

import pandas as pd


ALERT_COLUMNS = ["event_id", "user_id", "timestamp", "alert_type", "severity", "reason"]


def detect_shadow_it(data: pd.DataFrame, ai_applications: tuple[str, ...] = ("ChatGPT", "Gemini", "Claude", "DeepSeek")) -> pd.DataFrame:
    """Return alerts for unapproved applications that are not configured AI apps."""
    required = {"event_id", "user_id", "timestamp", "application", "approved"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")

    ai_names = {app.casefold() for app in ai_applications}
    is_unapproved = data["approved"].astype(str).str.strip().str.casefold().eq("false")
    is_ai_application = data["application"].astype(str).str.casefold().isin(ai_names)
    matches = data.loc[is_unapproved & ~is_ai_application].copy()
    alerts = pd.DataFrame(
        {
            "event_id": matches["event_id"],
            "user_id": matches["user_id"],
            "timestamp": matches["timestamp"],
            "alert_type": "Shadow IT",
            "severity": "Medium",
            "reason": "Unauthorized non-AI SaaS application: " + matches["application"].astype(str),
        }
    )
    return alerts.reindex(columns=ALERT_COLUMNS).reset_index(drop=True)
