"""Compare behavioural thresholds and risk contributions on fixed holdout data."""

from pathlib import Path

import pandas as pd

from correlation.event_correlation import correlate_events
from detection.behavior_baseline import calculate_baselines_from_history
from evaluate import calculate_metrics
from risk.risk_score import DEFAULT_RISK_WEIGHTS


RESULTS_DIR = Path("results")
DATA_DIR = Path("data")


def main() -> None:
    data = pd.read_csv(DATA_DIR / "saas_activity.csv")
    hybrid = pd.read_csv(RESULTS_DIR / "hybrid_holdout_predictions.csv")
    holdout_index = hybrid["source_row_index"].astype(int)
    holdout = data.loc[holdout_index]
    training = data.drop(index=holdout_index)
    y_true = hybrid["ground_truth"].astype(int)
    original = hybrid["hybrid_prediction"].astype(int)

    metric_rows = []
    threshold_analyses = {}
    original_metrics, _ = calculate_metrics(y_true, original, "Original Hybrid")
    original_metrics["threshold"] = pd.NA
    original_metrics["behavioral_alerts"] = 0
    metric_rows.append(original_metrics)
    for threshold in (2.5, 3.0, 3.5, 4.0):
        analysis = calculate_baselines_from_history(
            holdout, training, request_ratio_threshold=threshold, upload_ratio_threshold=threshold
        )
        behavioural_by_event = analysis.set_index("event_id")["behavioral_alert"].astype(int)
        behavioural = pd.Series(behavioural_by_event.loc[holdout["event_id"]].to_numpy(), index=original.index)
        improved = (original.eq(1) | behavioural.eq(1)).astype(int)
        metrics, _ = calculate_metrics(y_true, improved, f"Hybrid + Behavioural ({threshold:.1f}x)")
        metrics["threshold"] = threshold
        metrics["behavioral_alerts"] = int(behavioural.sum())
        metric_rows.append(metrics)
        threshold_analyses[threshold] = analysis
    pd.DataFrame(metric_rows).to_csv(RESULTS_DIR / "behavioral_threshold_comparison.csv", index=False)

    # Risk points do not change alert classification. They are compared through
    # the resulting Low/Medium/High incident distribution instead.
    shadow_it = pd.read_csv(RESULTS_DIR / "shadow_it_alerts.csv")
    shadow_ai = pd.read_csv(RESULTS_DIR / "shadow_ai_alerts.csv")
    cloud_alerts = pd.read_csv(RESULTS_DIR / "cloud_security_alerts.csv")
    cloud_data = pd.read_csv(DATA_DIR / "cloudtrail_logs.csv")
    current_behavioral = pd.read_csv(RESULTS_DIR / "behavioral_deviation_alerts.csv")
    risk_rows = []
    for points in (5, 10, 15):
        weights = dict(DEFAULT_RISK_WEIGHTS)
        weights["Behavioral Deviation"] = points
        incidents = correlate_events(shadow_it, shadow_ai, cloud_alerts, data, cloud_data, behavioral_alerts=current_behavioral, risk_weights=weights)
        counts = incidents["risk_level"].value_counts()
        risk_rows.append({"behavioral_risk_points": points, "low_incidents": int(counts.get("Low", 0)), "medium_incidents": int(counts.get("Medium", 0)), "high_incidents": int(counts.get("High", 0))})
    pd.DataFrame(risk_rows).to_csv(RESULTS_DIR / "behavioral_risk_weight_comparison.csv", index=False)
    print(pd.DataFrame(metric_rows).round(4).to_string(index=False))
    print("\nRisk-weight comparison:")
    print(pd.DataFrame(risk_rows).to_string(index=False))


if __name__ == "__main__":
    main()
