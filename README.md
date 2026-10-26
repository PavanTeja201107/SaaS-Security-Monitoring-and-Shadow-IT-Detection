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
     Shadow IT / Shadow AI / Behavioural alerts
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

## User-specific Behaviour Baselines

`run_behavioral_baseline.py` calculates each user's historical median request count and upload volume using only their earlier timestamped SaaS events. A baseline needs at least five earlier records. A behavioural alert is created when requests or upload volume reaches 3.5 times that historical median.

The dashboard displays actual activity against the historical baseline, highlights threshold-exceeding points, and includes a deviation-ratio trend. Early events without sufficient history are shown as **Insufficient historical data**, not as a misleading ratio.

The behavioural signal is included in risk scoring as `Behavioral Deviation (+5)`. Existing risk-score de-duplication counts this indicator once per incident, even when several deviation events occur.

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
python run_behavioral_baseline.py
python run_correlation.py
streamlit run app.py
```

## Final Demonstration Sequence

1. Open **Overview** to show the alert totals, high-risk incident count, and Quick Demo incidents.
2. Open **Algorithm Comparison** to show the five-method chart, the Hybrid voting rows, and the Original versus Behavioural-Enhanced comparison.
3. Open **Shadow IT / Shadow AI** to show an unauthorized application alert.
4. Open **Cloud Security** and filter to `Unknown IP` or `Create Access Key`.
5. Open **Incidents** and select high-risk `INC-0139`; its reason includes `Behavioral Deviation (+5)`.
6. Open **User Behaviour**, select `user_028`, and show current requests/uploads, historical baselines, deviation ratios, explanations, and linked incident-risk impact.

## Results

Generated outputs include algorithm metrics, confusion matrices, hybrid predictions, a performance chart, security alerts, correlated incidents, and the trained Random Forest model. All values are calculated by the scripts; no metrics are manually entered.

### Detection performance on the common 300-record holdout set

| Method | Precision | Recall | F1-score | False Positive Rate |
|---|---:|---:|---:|---:|
| IQR | 0.9070 | 0.5200 | 0.6610 | 0.0178 |
| K-Means | 1.0000 | 0.3600 | 0.5294 | 0.0000 |
| Isolation Forest | 0.8519 | 0.6133 | 0.7132 | 0.0356 |
| Random Forest | 0.8519 | 0.6133 | 0.7132 | 0.0356 |
| Hybrid | 0.9216 | 0.6267 | 0.7460 | 0.0178 |

### Original versus behavioural-enhanced system

| System | Precision | Recall | F1-score | False Positive Rate |
|---|---:|---:|---:|---:|
| Original Hybrid | 0.9216 | 0.6267 | 0.7460 | 0.0178 |
| Hybrid + Behavioural Baseline | 0.9216 | 0.6267 | 0.7460 | 0.0178 |

With the tuned 3.5× threshold, the behavioural enhancement does not change the common-holdout prediction set. It preserves the original Hybrid metrics while still providing a separate explainable behavioural signal for incident prioritisation. See `README_TUNING_AND_EVALUATION.md` for the tested threshold and risk-weight comparisons.

## Run with Docker

Docker starts the complete existing pipeline inside the container, then exposes the Streamlit dashboard on port 8501.

```powershell
docker build -t saas-security-monitor .
docker run --rm -p 8501:8501 saas-security-monitor
```

Or use Docker Compose:

```powershell
docker compose up --build
```

Open `http://localhost:8501` after the pipeline completes. Docker must be running before either command.

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
