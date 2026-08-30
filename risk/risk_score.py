"""Configurable, transparent risk scoring for security indicators."""

from __future__ import annotations

from typing import Iterable, Mapping


DEFAULT_RISK_WEIGHTS = {
    "Shadow IT": 30,
    "Shadow AI": 30,
    "Unknown IP": 20,
    "Unusual Access Time": 10,
    "Create Access Key": 25,
    "Abnormal API Activity": 10,
    "Unusual Resource Access": 15,
    "Large Data Upload": 20,
}


def get_risk_level(score: int) -> str:
    """Map a capped score to the course-project risk levels."""
    if score < 0 or score > 100:
        raise ValueError("risk score must be between 0 and 100.")
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    return "High"


def calculate_risk_score(
    indicators: Iterable[str],
    weights: Mapping[str, int] | None = None,
    deduplicate_indicators: bool = True,
) -> tuple[int, str, dict[str, int]]:
    """Calculate a capped risk score and show exactly which weights contributed.

    By default, repeated instances of one indicator type are counted once per
    incident. This avoids inflating a score merely because one rule generated
    several alerts in the same time window.
    """
    active_weights = dict(DEFAULT_RISK_WEIGHTS if weights is None else weights)
    indicator_list = list(dict.fromkeys(indicators)) if deduplicate_indicators else list(indicators)
    contributions: dict[str, int] = {}
    for indicator in indicator_list:
        if indicator in active_weights:
            value = int(active_weights[indicator])
            if value < 0:
                raise ValueError(f"Risk weight for '{indicator}' cannot be negative.")
            contributions[indicator] = contributions.get(indicator, 0) + value
    score = min(sum(contributions.values()), 100)
    return score, get_risk_level(score), contributions
