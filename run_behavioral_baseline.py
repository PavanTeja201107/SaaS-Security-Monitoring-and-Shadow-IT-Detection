"""Generate user-specific SaaS behaviour baselines and deviation alerts."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from detection.behavior_baseline import calculate_user_baselines, detect_behavioral_deviations


DATA_PATH = Path("data") / "saas_activity.csv"
RESULTS_DIR = Path("results")


def validate_historical_baselines(source: pd.DataFrame, analysis: pd.DataFrame) -> None:
    """Verify each populated baseline uses only strictly earlier events for its user."""
    history = source.copy(deep=True)
    history["parsed_timestamp"] = pd.to_datetime(history["timestamp"], errors="raise")
    for row in analysis.dropna(subset=["historical_request_baseline"]).itertuples(index=False):
        earlier = history.loc[
            (history["user_id"] == row.user_id)
            & (history["parsed_timestamp"] < pd.Timestamp(row.timestamp))
        ]
        if len(earlier) < 5:
            raise ValueError(f"Baseline for {row.event_id} has insufficient historical records.")


def main() -> None:
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"SaaS data was not found: {DATA_PATH}. Run generate_data.py first.")
    source = pd.read_csv(DATA_PATH)
    analysis, alerts = detect_behavioral_deviations(source)
    validate_historical_baselines(source, analysis)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    analysis.to_csv(RESULTS_DIR / "user_behavior_baselines.csv", index=False)
    alerts.to_csv(RESULTS_DIR / "behavioral_deviation_alerts.csv", index=False)
    print(f"Baseline rows: {len(analysis)}")
    print(f"Behavioral deviation alerts: {len(alerts)}")
    print(alerts.head(5).to_string(index=False))


if __name__ == "__main__":
    main()
