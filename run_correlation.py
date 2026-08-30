"""Run Stage 8 risk scoring and event correlation using generated alert files."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from correlation.event_correlation import correlate_events


DATA_DIR = Path("data")
RESULTS_DIR = Path("results")


def main() -> None:
    required_paths = {
        "shadow_it": RESULTS_DIR / "shadow_it_alerts.csv",
        "shadow_ai": RESULTS_DIR / "shadow_ai_alerts.csv",
        "cloud": RESULTS_DIR / "cloud_security_alerts.csv",
        "saas": DATA_DIR / "saas_activity.csv",
        "cloud_data": DATA_DIR / "cloudtrail_logs.csv",
    }
    missing = [str(path) for path in required_paths.values() if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing required files. Run generate_data.py and run_detections.py first: " + ", ".join(missing))

    incidents = correlate_events(
        pd.read_csv(required_paths["shadow_it"]),
        pd.read_csv(required_paths["shadow_ai"]),
        pd.read_csv(required_paths["cloud"]),
        pd.read_csv(required_paths["saas"]),
        pd.read_csv(required_paths["cloud_data"]),
    )
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    incidents.to_csv(RESULTS_DIR / "correlated_incidents.csv", index=False)
    summary = incidents.groupby("risk_level").size().reindex(["Low", "Medium", "High"], fill_value=0).rename("incident_count")
    summary.to_csv(RESULTS_DIR / "incident_summary.csv", header=True)
    print(f"Correlated incidents: {len(incidents)}")
    print(summary.to_string())
    print("\nHighest-risk incidents:")
    print(incidents.sort_values("risk_score", ascending=False).head(5).drop(columns="events").to_string(index=False))


if __name__ == "__main__":
    main()
