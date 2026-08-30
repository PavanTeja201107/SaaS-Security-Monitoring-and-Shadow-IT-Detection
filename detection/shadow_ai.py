"""Rule-based detection of unauthorized AI SaaS applications."""

from __future__ import annotations

from typing import Iterable

import pandas as pd

from detection.shadow_it import ALERT_COLUMNS


DEFAULT_AI_APPLICATIONS = ("ChatGPT", "Gemini", "Claude", "DeepSeek")


def detect_shadow_ai(data: pd.DataFrame, ai_applications: Iterable[str] = DEFAULT_AI_APPLICATIONS) -> pd.DataFrame:
    """Return alerts where an application is both configured as AI and unapproved."""
    required = {"event_id", "user_id", "timestamp", "application", "approved"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")

    ai_names = {str(app).casefold() for app in ai_applications}
    if not ai_names:
        raise ValueError("The configurable AI application list cannot be empty.")
    is_unapproved = data["approved"].astype(str).str.strip().str.casefold().eq("false")
    is_ai_application = data["application"].astype(str).str.casefold().isin(ai_names)
    matches = data.loc[is_unapproved & is_ai_application].copy()
    alerts = pd.DataFrame(
        {
            "event_id": matches["event_id"],
            "user_id": matches["user_id"],
            "timestamp": matches["timestamp"],
            "alert_type": "Shadow AI",
            "severity": "High",
            "reason": "Unauthorized AI SaaS application: " + matches["application"].astype(str),
        }
    )
    return alerts.reindex(columns=ALERT_COLUMNS).reset_index(drop=True)
