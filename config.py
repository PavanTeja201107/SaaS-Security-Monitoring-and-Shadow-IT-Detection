"""Central, measured configuration values for behavioural detection."""

# Selected after comparing 2.5x, 3.0x, 3.5x, and 4.0x thresholds on the
# fixed holdout set. 3.5x preserves the original Hybrid F1-score.
BEHAVIORAL_MINIMUM_HISTORY = 5
BEHAVIORAL_RATIO_THRESHOLD = 3.5

# Selected after comparing +5, +10, and +15 incident contributions.
BEHAVIORAL_RISK_POINTS = 5
