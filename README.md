# SaaS Security Monitoring and Shadow IT Detection

B.Tech Cloud Computing course project by Member 1: **231IT030** and Member 2: **231IT074**.

## Project Objective

This project monitors SaaS activity and CloudTrail-style audit logs to identify Shadow IT, Shadow AI, unusual SaaS usage, and suspicious cloud activity. It compares detection algorithms, combines them through a simple hybrid vote, applies explainable cloud-security rules, assigns transparent risk scores, and groups related alerts into incidents for a Streamlit demonstration dashboard.

## Architecture

```text
SaaS activity CSV                 CloudTrail-style audit CSV
        |                                      |
        v                                      v
IQR | K-Means | Isolation Forest | Random Forest     Cloud security rules
        |                                      |
        +------------ Hybrid voting -----------+
                              |
                 Shadow IT / Shadow AI alerts
                              |
                  Risk scoring and correlation
                              |
                     Streamlit dashboard
```

## Dataset Description

`generate_data.py` creates reproducible datasets using fixed seed `42` and saves them under `data/`.

| File | Records | Key fields | Included behaviours |
|---|---:|---|---|
| `saas_activity.csv` | 1,200 | user, application, requests, upload volume, device, location, approval status | approved use, Shadow IT, Shadow AI, high requests/uploads, unusual time |
| `cloudtrail_logs.csv` | 1,250 | user, event, resource, source IP, region, status | normal object actions, unknown IPs, unusual login time, access-key creation, API bursts, sensitive-resource access |

Both datasets include `ground_truth` labels for evaluation. The data is generated for course-project testing and uses consistent user, device, location, and internal-IP relationships.

## Detection Algorithms

- **IQR:** Statistical baseline that flags unusual request counts, upload volume, or access hour.
- **K-Means:** Clusters scaled activity features; clusters far from the largest baseline cluster are treated as anomalous.
- **Isolation Forest:** Unsupervised anomaly detector trained without labels.
- **Random Forest:** Supervised classifier trained on a stratified training split and evaluated on an unseen test split.

## Hybrid Approach

The hybrid detector gives IQR, K-Means, Isolation Forest, and Random Forest one vote each. An event is suspicious when at least two methods flag it. Its confidence is the fraction of suspicious votes, not a probability. `results/hybrid_holdout_predictions.csv` stores every hybrid prediction and vote count.

For a fair comparison, all methods in `results/algorithm_comparison.csv` are evaluated on the same Random Forest holdout set. The unsupervised detectors fit only the corresponding training partition before predicting the holdout records.

## Cloud Security Rules

The cloud-security module generates structured alerts for:

- source IP outside configured internal prefixes;
- access outside normal working hours;
- `CreateAccessKey` events;
- repeated API activity in a five-minute window;
- configured sensitive-resource access.

## Shadow IT and Shadow AI

Shadow IT is any unauthorized non-AI SaaS application. Shadow AI is any unauthorized application in the configurable list: ChatGPT, Gemini, Claude, and DeepSeek. Their outputs are saved under `results/` as alert CSVs.

## Risk Scoring and Event Correlation

Risk scoring uses configurable design weights, such as Shadow IT/AI (+30), unknown IP (+20), unusual time (+10), and large data upload (+20). Scores are capped at 100 and classified as Low (0–30), Medium (31–60), or High (61–100).

The correlator groups events for the same user when consecutive alerts are within a 12-hour window. It includes source IP and resource context where available and saves incidents in `results/correlated_incidents.csv`.

## How to Run

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Run the full pipeline from the project root:

```powershell
python generate_data.py
python evaluate.py
python run_detections.py
python run_correlation.py
streamlit run app.py
```

## Results

Generated outputs include algorithm metrics, confusion matrices, hybrid predictions, a performance chart, security alerts, correlated incidents, and the trained Random Forest model. All values are calculated by the scripts; no metrics are manually entered.

## Limitations

- The datasets are generated and cannot represent every organization or threat pattern.
- IQR and simple rule thresholds need tuning for a real environment.
- The correlation logic is intentionally rule-based and may group unrelated events that occur close together for one user.
- The dashboard reads local CSV outputs and is not connected to a live cloud account.

## Future Work

- Validate thresholds and models with approved real enterprise logs.
- Add alert acknowledgement and analyst feedback fields.
- Support scheduled data refresh and secure configuration management.
- Add role-based access control before any operational deployment.
