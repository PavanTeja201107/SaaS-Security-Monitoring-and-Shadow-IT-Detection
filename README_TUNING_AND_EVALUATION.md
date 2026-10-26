# Behavioural Detection Tuning and Evaluation

This note records measured tuning results for the user-specific behavioural feature. It uses the existing fixed 300-record Random Forest holdout set. No values in these tables are manually entered.

## Evaluation reliability checks

- Random Forest is trained on 900 records and tested on 300 records using `random_state=42` and stratification.
- IQR, K-Means, and Isolation Forest fit on the same 900 training records before predicting the common 300-record holdout.
- A behavioural holdout baseline uses only records from the training partition whose timestamp is earlier than the holdout event. It does not use ground-truth labels, future events, or another heldout event.
- The saved Random Forest matrix and the common-holdout Random Forest row agree: TN=217, FP=8, FN=29, TP=46.
- The original and behavioural-enhanced systems use the same 300 labels and the same original Hybrid prediction series.

## Behavioural threshold comparison

The enhanced prediction is `Original Hybrid OR Behavioural Deviation`.

| System | Threshold | Behavioural holdout alerts | Precision | Recall | F1-score | FPR | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Original Hybrid | — | 0 | 0.9216 | 0.6267 | 0.7460 | 0.0178 | 221 | 4 | 28 | 47 |
| Hybrid + Behavioural | 2.5× | 30 | 0.8276 | 0.6400 | 0.7218 | 0.0444 | 215 | 10 | 27 | 48 |
| Hybrid + Behavioural | 3.0× | 27 | 0.8727 | 0.6400 | 0.7385 | 0.0311 | 218 | 7 | 27 | 48 |
| Hybrid + Behavioural | 3.5× | 23 | 0.9216 | 0.6267 | 0.7460 | 0.0178 | 221 | 4 | 28 | 47 |
| Hybrid + Behavioural | 4.0× | 21 | 0.9216 | 0.6267 | 0.7460 | 0.0178 | 221 | 4 | 28 | 47 |

### Selected threshold: 3.5×

The 2.5× and 3.0× settings found one extra anomaly but added false positives and reduced F1-score. The 3.5× setting keeps the original Hybrid's measured performance and is less likely to create unnecessary alerts. Therefore the project default is now **3.5×** for both requests and upload volume.

This does not mean the behavioural feature is useless. It still produces an explainable, user-specific signal for monitoring and incident prioritisation. It means this generated holdout dataset does not show an F1 improvement when that signal is OR-combined with Hybrid predictions.

At the selected 3.5× setting, the strict training-history evaluation finds 23 behavioural alerts among the 300 holdout records. `evaluate.py` applies the rule `improved_prediction = hybrid_prediction OR behavioral_prediction`; all 23 of those records were already Hybrid-positive, so the number of new predictions is 0. Identical metrics are therefore the correct outcome, not a missing integration.

## Behavioural risk contribution comparison

Risk points do not change Precision, Recall, or F1 because they are applied after alert detection. They change only incident priority.

| Behavioural risk points | Low incidents | Medium incidents | High incidents |
|---:|---:|---:|---:|
| +5 | 332 | 81 | 20 |
| +10 | 331 | 81 | 21 |
| +15 | 293 | 118 | 22 |

### Selected risk contribution: +5

The +5 setting is the most conservative tested option. It keeps behavioural context in an incident without promoting as many incidents to Medium or High risk as +10 or +15. Repeated behavioural alerts are still counted only once per incident by the existing risk-score de-duplication rule.

## Current algorithm comparison

| Method | Precision | Recall | F1-score | False Positive Rate |
|---|---:|---:|---:|---:|
| IQR | 0.9070 | 0.5200 | 0.6610 | 0.0178 |
| K-Means | 1.0000 | 0.3600 | 0.5294 | 0.0000 |
| Isolation Forest | 0.8519 | 0.6133 | 0.7132 | 0.0356 |
| Random Forest | 0.8519 | 0.6133 | 0.7132 | 0.0356 |
| Hybrid | 0.9216 | 0.6267 | 0.7460 | 0.0178 |

## Reproduce the comparisons

```powershell
python generate_data.py
python evaluate.py
python run_detections.py
python run_behavioral_baseline.py
python run_correlation.py
python tune_behavioral_detection.py
```

The generated comparison files are:

- `results/behavioral_threshold_comparison.csv`
- `results/behavioral_risk_weight_comparison.csv`
- `results/system_comparison.csv`
- `results/original_hybrid_confusion_matrix.csv`
- `results/improved_system_confusion_matrix.csv`
