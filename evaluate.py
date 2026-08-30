"""Evaluation runner for SaaS anomaly detection stages 2 through 5.

Run from the project root after generating data:
    python evaluate.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Prevent a Windows-specific joblib core-discovery warning in terminal runs.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
import joblib
import matplotlib
# The Agg backend writes PNG files without needing a desktop/Tk installation.
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from algorithms.iqr import calculate_iqr_bounds, detect_iqr_outliers, predict_iqr_outliers
from algorithms.hybrid import combine_predictions
from algorithms.isolation_forest import detect_isolation_forest_anomalies, fit_isolation_forest, predict_isolation_forest_anomalies
from algorithms.kmeans import detect_kmeans_anomalies, fit_kmeans_detector, predict_kmeans_anomalies
from algorithms.random_forest import train_random_forest


DATA_PATH = Path("data") / "saas_activity.csv"
RESULTS_DIR = Path("results")
MODELS_DIR = Path("models")


def load_saas_data(path: Path = DATA_PATH) -> pd.DataFrame:
    """Load and validate the Stage 1 SaaS data needed for evaluation."""
    if not path.exists():
        raise FileNotFoundError(f"SaaS data was not found: {path}. Run generate_data.py first.")
    data = pd.read_csv(path)
    required = {"timestamp", "requests", "data_uploaded_mb", "ground_truth"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")
    if not set(data["ground_truth"].dropna().unique()).issubset({0, 1}):
        raise ValueError("ground_truth must contain only 0 and 1.")
    return data


def calculate_metrics(y_true: pd.Series, y_pred: pd.Series, method: str) -> tuple[dict, pd.DataFrame]:
    """Calculate the requested classification metrics from real predictions."""
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    metrics = {
        "method": method,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": false_positive_rate,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }
    matrix = pd.DataFrame([[tn, fp], [fn, tp]], index=["actual_normal", "actual_anomalous"], columns=["predicted_normal", "predicted_anomalous"])
    return metrics, matrix


def save_performance_chart(metrics: pd.DataFrame, path: Path) -> None:
    """Save a compact grouped-bar chart that the future dashboard can display."""
    chart_data = metrics.set_index("method")[["precision", "recall", "f1_score"]]
    ax = chart_data.plot(kind="bar", figsize=(10, 5), ylim=(0, 1.05), color=["#4C78A8", "#F58518", "#54A24B"])
    ax.set_title("SaaS Anomaly Detection Performance (Common Holdout Set)")
    ax.set_xlabel("Detection method")
    ax.set_ylabel("Score")
    ax.legend(["Precision", "Recall", "F1-score"], loc="lower right")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()


def main() -> None:
    data = load_saas_data()
    y_true = data["ground_truth"].astype(int)
    iqr_predictions = detect_iqr_outliers(data)
    kmeans_predictions, kmeans_details = detect_kmeans_anomalies(data)
    isolation_predictions, isolation_details = detect_isolation_forest_anomalies(data)
    random_forest_model, random_forest_y_test, random_forest_predictions, random_forest_details = train_random_forest(data)

    iqr_metrics, iqr_matrix = calculate_metrics(y_true, iqr_predictions, "IQR")
    kmeans_metrics, kmeans_matrix = calculate_metrics(y_true, kmeans_predictions, "K-Means")
    isolation_metrics, isolation_matrix = calculate_metrics(y_true, isolation_predictions, "Isolation Forest")
    random_forest_metrics, random_forest_matrix = calculate_metrics(random_forest_y_test, random_forest_predictions, "Random Forest")

    # Use one stratified holdout set for every method. The unsupervised methods
    # are fitted only on the training partition; labels are never used by them.
    holdout_index = random_forest_y_test.index
    training_data = data.drop(index=holdout_index)
    holdout_data = data.loc[holdout_index]
    common_truth = y_true.loc[holdout_index]
    holdout_iqr_bounds = calculate_iqr_bounds(training_data)
    holdout_kmeans_detector, _ = fit_kmeans_detector(training_data)
    holdout_isolation_detector, _ = fit_isolation_forest(training_data)
    common_predictions = {
        "IQR": predict_iqr_outliers(holdout_data, holdout_iqr_bounds),
        "K-Means": predict_kmeans_anomalies(holdout_data, holdout_kmeans_detector),
        "Isolation Forest": predict_isolation_forest_anomalies(holdout_data, holdout_isolation_detector),
        "Random Forest": random_forest_predictions,
    }
    comparison_records = []
    comparison_matrices = {}
    for method, prediction in common_predictions.items():
        metrics, matrix = calculate_metrics(common_truth, prediction, method)
        comparison_records.append(metrics)
        comparison_matrices[method] = matrix
    hybrid_output = combine_predictions(common_predictions, minimum_votes=2)
    hybrid_metrics, hybrid_matrix = calculate_metrics(common_truth, hybrid_output["hybrid_prediction"], "Hybrid")
    comparison_records.append(hybrid_metrics)
    comparison_matrices["Hybrid"] = hybrid_matrix
    comparison_metrics = pd.DataFrame(comparison_records)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([iqr_metrics, kmeans_metrics]).to_csv(RESULTS_DIR / "stage2_algorithm_metrics.csv", index=False)
    pd.DataFrame([isolation_metrics, random_forest_metrics]).to_csv(RESULTS_DIR / "stage3_4_algorithm_metrics.csv", index=False)
    comparison_metrics.to_csv(RESULTS_DIR / "algorithm_comparison.csv", index=False)
    iqr_matrix.to_csv(RESULTS_DIR / "iqr_confusion_matrix.csv")
    kmeans_matrix.to_csv(RESULTS_DIR / "kmeans_confusion_matrix.csv")
    isolation_matrix.to_csv(RESULTS_DIR / "isolation_forest_confusion_matrix.csv")
    random_forest_matrix.to_csv(RESULTS_DIR / "random_forest_confusion_matrix.csv")
    hybrid_matrix.to_csv(RESULTS_DIR / "hybrid_confusion_matrix.csv")
    calculate_iqr_bounds(data).round(4).to_csv(RESULTS_DIR / "iqr_bounds.csv")
    (RESULTS_DIR / "kmeans_details.json").write_text(json.dumps(kmeans_details, indent=2), encoding="utf-8")
    (RESULTS_DIR / "isolation_forest_details.json").write_text(json.dumps(isolation_details, indent=2), encoding="utf-8")
    (RESULTS_DIR / "random_forest_details.json").write_text(json.dumps(random_forest_details, indent=2), encoding="utf-8")
    hybrid_output.insert(0, "ground_truth", common_truth)
    hybrid_output.to_csv(RESULTS_DIR / "hybrid_holdout_predictions.csv", index_label="source_row_index")
    save_performance_chart(comparison_metrics, RESULTS_DIR / "algorithm_performance.png")
    joblib.dump(random_forest_model, MODELS_DIR / "random_forest_saas_model.joblib")

    print("Stages 2 to 5 evaluation completed.")
    print(pd.DataFrame([iqr_metrics, kmeans_metrics, isolation_metrics, random_forest_metrics]).round(4).to_string(index=False))
    print("\nIsolation Forest details:")
    print(json.dumps(isolation_details, indent=2))
    print("\nRandom Forest holdout-test details:")
    print(json.dumps(random_forest_details, indent=2))
    print("\nCommon-holdout algorithm comparison:")
    print(comparison_metrics.round(4).to_string(index=False))
    print(f"\nResults saved to: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
