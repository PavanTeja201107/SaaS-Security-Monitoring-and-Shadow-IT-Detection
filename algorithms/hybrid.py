"""Simple voting-based hybrid detector for SaaS anomaly predictions."""

from __future__ import annotations

from typing import Mapping

import pandas as pd


REQUIRED_METHODS = ("IQR", "K-Means", "Isolation Forest", "Random Forest")


def combine_predictions(predictions: Mapping[str, pd.Series], minimum_votes: int = 2) -> pd.DataFrame:
    """Combine four binary detectors using an explainable majority-style vote.

    Every method has one vote.  An event is flagged by the hybrid when at least
    two methods vote suspicious.  ``hybrid_confidence`` is not a probability;
    it is the fraction of methods that voted suspicious (0.00 to 1.00).
    """
    if minimum_votes < 1 or minimum_votes > len(REQUIRED_METHODS):
        raise ValueError(f"minimum_votes must be between 1 and {len(REQUIRED_METHODS)}.")
    missing = set(REQUIRED_METHODS) - set(predictions)
    if missing:
        raise ValueError(f"Missing predictions for: {sorted(missing)}")

    votes = pd.DataFrame({method: predictions[method] for method in REQUIRED_METHODS})
    if votes.isna().any().any():
        raise ValueError("Hybrid predictions must be aligned and cannot contain missing values.")
    if not votes.isin([0, 1]).all().all():
        raise ValueError("Each detector must supply binary predictions (0 or 1).")

    vote_count = votes.sum(axis=1).astype(int)
    result = votes.copy()
    result["suspicious_votes"] = vote_count
    result["hybrid_confidence"] = (vote_count / len(REQUIRED_METHODS)).round(2)
    result["hybrid_prediction"] = (vote_count >= minimum_votes).astype(int)
    return result
