"""K-Means based SaaS activity anomaly detector."""

from __future__ import annotations

from typing import Dict, Iterable, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler


DEFAULT_FEATURES: Tuple[str, ...] = ("requests", "data_uploaded_mb", "activity_hour")


def _prepare_features(data: pd.DataFrame, features: Iterable[str]) -> pd.DataFrame:
    """Create a numeric, temporary feature frame; never alter caller data."""
    required = {"timestamp", "requests", "data_uploaded_mb"}
    missing = required - set(data.columns)
    if missing:
        raise ValueError(f"SaaS data is missing required columns: {sorted(missing)}")

    feature_frame = data.copy(deep=True)
    feature_frame["activity_hour"] = pd.to_datetime(feature_frame["timestamp"], errors="raise").dt.hour
    selected = list(features)
    if not selected or set(selected) - set(feature_frame.columns):
        raise ValueError("Selected K-Means features are invalid or unavailable.")
    numeric = feature_frame[selected].apply(pd.to_numeric, errors="raise")
    if numeric.isna().any().any():
        raise ValueError("K-Means features cannot contain missing values.")
    return numeric


def choose_cluster_count(scaled_features: np.ndarray, candidates: Sequence[int] = (2, 3, 4, 5)) -> tuple[int, Dict[int, float]]:
    """Choose k using the highest silhouette score across a small, explainable range."""
    valid_candidates = [k for k in candidates if 1 < k < len(scaled_features)]
    if not valid_candidates:
        raise ValueError("Not enough rows to choose a K-Means cluster count.")

    scores: Dict[int, float] = {}
    for k in valid_candidates:
        model = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = model.fit_predict(scaled_features)
        scores[k] = float(silhouette_score(scaled_features, labels))
    best_k = max(scores, key=scores.get)
    return best_k, scores


def fit_kmeans_detector(
    training_data: pd.DataFrame,
    features: Iterable[str] = DEFAULT_FEATURES,
    candidates: Sequence[int] = (2, 3, 4, 5),
) -> tuple[dict, dict]:
    """Fit a K-Means detector on training records only."""
    numeric = _prepare_features(training_data, features)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(numeric)
    selected_k, silhouette_scores = choose_cluster_count(scaled, candidates)
    model = KMeans(n_clusters=selected_k, random_state=42, n_init=10)
    labels = model.fit_predict(scaled)
    counts = pd.Series(labels).value_counts().sort_index()
    normal_cluster = int(counts.idxmax())
    centroids = model.cluster_centers_
    distances = np.linalg.norm(centroids - centroids[normal_cluster], axis=1)
    anomalous_clusters = [int(cluster) for cluster, distance in enumerate(distances) if cluster != normal_cluster and distance >= 1.25]
    detector = {
        "features": list(numeric.columns),
        "scaler": scaler,
        "model": model,
        "anomalous_clusters": anomalous_clusters,
    }
    details = {
        "features": detector["features"],
        "selected_k": selected_k,
        "silhouette_scores": {str(k): round(score, 4) for k, score in silhouette_scores.items()},
        "normal_cluster": normal_cluster,
        "anomalous_clusters": anomalous_clusters,
        "cluster_sizes": {str(cluster): int(count) for cluster, count in counts.items()},
        "centroid_distances_from_normal": {str(cluster): round(float(distance), 4) for cluster, distance in enumerate(distances)},
    }
    return detector, details


def predict_kmeans_anomalies(data: pd.DataFrame, detector: dict) -> pd.Series:
    """Predict anomaly labels for data using an already fitted K-Means detector."""
    numeric = _prepare_features(data, detector["features"])
    labels = detector["model"].predict(detector["scaler"].transform(numeric))
    return pd.Series(np.isin(labels, detector["anomalous_clusters"]).astype(int), index=data.index, name="kmeans_prediction")


def detect_kmeans_anomalies(
    data: pd.DataFrame,
    features: Iterable[str] = DEFAULT_FEATURES,
    candidates: Sequence[int] = (2, 3, 4, 5),
) -> tuple[pd.Series, dict]:
    """Cluster scaled activity, then label behaviourally distant clusters anomalous.

    The largest cluster is treated as the normal baseline.  Every other cluster
    is compared with its centroid in scaled feature space.  A cluster is marked
    anomalous when its centroid is at least 1.25 units from that baseline. This
    detects groups with unusual request volume, upload volume, or access time.
    """
    detector, details = fit_kmeans_detector(data, features, candidates)
    return predict_kmeans_anomalies(data, detector), details
