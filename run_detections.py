"""Run and validate the Stage 6 and 7 rule-based detectors.

Run from the project root:
    python run_detections.py
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from detection.cloud_security import detect_cloud_security_alerts
from detection.shadow_ai import detect_shadow_ai
from detection.shadow_it import detect_shadow_it


DATA_DIR = Path("data")
RESULTS_DIR = Path("results")
REQUIRED_ALERT_COLUMNS = ["event_id", "user_id", "timestamp", "alert_type", "severity", "reason"]


def validate_alerts(alerts: pd.DataFrame, detector_name: str) -> None:
    """Check that each detector returned the documented, usable alert schema."""
    if list(alerts.columns) != REQUIRED_ALERT_COLUMNS:
        raise ValueError(f"{detector_name} returned an invalid alert schema.")
    if alerts[REQUIRED_ALERT_COLUMNS].isna().any().any():
        raise ValueError(f"{detector_name} returned alerts with missing required fields.")


def main() -> None:
    saas_path = DATA_DIR / "saas_activity.csv"
    cloud_path = DATA_DIR / "cloudtrail_logs.csv"
    if not saas_path.exists() or not cloud_path.exists():
        raise FileNotFoundError("Generated datasets are missing. Run generate_data.py first.")

    saas_data = pd.read_csv(saas_path)
    cloud_data = pd.read_csv(cloud_path)
    detector_outputs = {
        "shadow_it": detect_shadow_it(saas_data),
        "shadow_ai": detect_shadow_ai(saas_data),
        "cloud_security": detect_cloud_security_alerts(cloud_data),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary_rows = []
    for name, alerts in detector_outputs.items():
        validate_alerts(alerts, name)
        alerts.to_csv(RESULTS_DIR / f"{name}_alerts.csv", index=False)
        summary_rows.append({"detector": name, "alert_count": len(alerts)})
        print(f"{name}: {len(alerts)} alerts")
        print(alerts.head(3).to_string(index=False))

    summary = pd.DataFrame(summary_rows)
    summary.to_csv(RESULTS_DIR / "detection_summary.csv", index=False)
    print(f"\nDetection results saved to: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
