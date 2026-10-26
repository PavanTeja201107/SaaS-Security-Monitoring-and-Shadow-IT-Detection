"""Streamlit demonstration dashboard for SaaS security monitoring.

Run from the project root:
    streamlit run app.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st


ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "data"
RESULTS_DIR = ROOT_DIR / "results"


@st.cache_data
def load_csv(path: Path) -> pd.DataFrame:
    """Read a generated project artifact once per dashboard refresh."""
    return pd.read_csv(path)


def load_project_data() -> tuple[dict[str, pd.DataFrame], list[str]]:
    """Load real pipeline outputs; never substitute placeholder values."""
    paths = {
        "saas": DATA_DIR / "saas_activity.csv",
        "cloud": DATA_DIR / "cloudtrail_logs.csv",
        "shadow_it": RESULTS_DIR / "shadow_it_alerts.csv",
        "shadow_ai": RESULTS_DIR / "shadow_ai_alerts.csv",
        "cloud_alerts": RESULTS_DIR / "cloud_security_alerts.csv",
        "behavior_baselines": RESULTS_DIR / "user_behavior_baselines.csv",
        "behavior_alerts": RESULTS_DIR / "behavioral_deviation_alerts.csv",
        "incidents": RESULTS_DIR / "correlated_incidents.csv",
        "comparison": RESULTS_DIR / "algorithm_comparison.csv",
        "hybrid_votes": RESULTS_DIR / "hybrid_holdout_predictions.csv",
        "system_comparison": RESULTS_DIR / "system_comparison.csv",
    }
    data, errors = {}, []
    for name, path in paths.items():
        if not path.exists():
            errors.append(f"Missing `{path.relative_to(ROOT_DIR)}`.")
            continue
        try:
            data[name] = load_csv(path)
        except (OSError, pd.errors.ParserError, ValueError) as exc:
            errors.append(f"Could not load `{path.relative_to(ROOT_DIR)}`: {exc}")
    return data, errors


def enrich_saas_alerts(alerts: pd.DataFrame, saas: pd.DataFrame) -> pd.DataFrame:
    fields = ["event_id", "application", "application_category", "requests", "data_uploaded_mb", "approved"]
    return alerts.merge(saas[fields], on="event_id", how="left")


def enrich_cloud_alerts(alerts: pd.DataFrame, cloud: pd.DataFrame) -> pd.DataFrame:
    fields = ["event_id", "event_name", "resource", "source_ip", "region", "status"]
    return alerts.merge(cloud[fields], on="event_id", how="left")


def parse_events(value: str) -> list[dict]:
    """Decode an incident event list without failing the dashboard on bad text."""
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []


def show_overview(data: dict[str, pd.DataFrame]) -> None:
    st.header("Overview")
    st.caption("Compact view of current SaaS, cloud, behavioural, and incident risk signals.")
    incidents = data["incidents"]
    total_activities = len(data["saas"]) + len(data["cloud"])
    anomaly_alerts = len(data["shadow_it"]) + len(data["shadow_ai"]) + len(data["behavior_alerts"])
    high_risk = int(incidents["risk_level"].eq("High").sum())
    total_users = pd.concat([data["saas"]["user_id"], data["cloud"]["user_id"]]).nunique()

    metrics = st.columns(4)
    metrics[0].metric("Total activities", f"{total_activities:,}")
    metrics[1].metric("Users monitored", total_users)
    metrics[2].metric("SaaS anomaly alerts", anomaly_alerts)
    metrics[3].metric("High-risk incidents", high_risk)

    left, right = st.columns([1, 2])
    with left:
        st.subheader("Security-risk summary")
        risk_counts = incidents["risk_level"].value_counts().reindex(["Low", "Medium", "High"], fill_value=0)
        st.bar_chart(risk_counts)
    with right:
        st.subheader("Priority incidents")
        top = incidents.sort_values(["risk_score", "incident_id"], ascending=[False, True]).head(5)
        st.dataframe(top[["incident_id", "user_id", "risk_score", "risk_level", "reason"]], hide_index=True, width="stretch")


def show_detection_performance(data: dict[str, pd.DataFrame]) -> None:
    st.header("Detection Performance")
    st.caption("All five methods use the same labelled holdout set. Results are loaded from the evaluation pipeline.")
    comparison = data["comparison"]
    metric_columns = ["method", "precision", "recall", "f1_score", "false_positive_rate"]
    st.dataframe(comparison[metric_columns].round(4), hide_index=True, width="stretch")

    chart_data = comparison.set_index("method")[["precision", "recall", "f1_score"]]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    chart_data.plot(kind="bar", ax=ax, color=["#2563EB", "#F59E0B", "#16A34A"], width=0.78)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("")
    ax.set_ylabel("Score")
    ax.set_title("Precision, Recall, and F1-score")
    ax.legend(["Precision", "Recall", "F1-score"], ncol=3, loc="upper center")
    ax.tick_params(axis="x", rotation=18)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    st.pyplot(fig, width="stretch")
    plt.close(fig)

    st.subheader("Original and behavioural-enhanced comparison")
    st.caption("The enhanced system alerts when either the original Hybrid or the historical behaviour baseline alerts.")
    system_cols = ["method", "precision", "recall", "f1_score", "false_positive_rate", "true_negatives", "false_positives", "false_negatives", "true_positives", "behavioral_holdout_alerts", "new_behavioral_predictions"]
    st.dataframe(data["system_comparison"][system_cols].round(4), hide_index=True, width="stretch")

    with st.expander("Show hybrid voting examples"):
        st.caption("A Hybrid alert needs at least two suspicious votes from IQR, K-Means, Isolation Forest, and Random Forest.")
        columns = ["source_row_index", "ground_truth", "IQR", "K-Means", "Isolation Forest", "Random Forest", "suspicious_votes", "hybrid_confidence", "hybrid_prediction"]
        st.dataframe(data["hybrid_votes"][columns].head(20), hide_index=True, width="stretch")


def show_saas_security(data: dict[str, pd.DataFrame]) -> None:
    st.header("SaaS Security")
    st.caption("Shadow IT is an unauthorized non-AI app. Shadow AI is an unauthorized app in the configured AI list.")
    cards = st.columns(2)
    cards[0].metric("Shadow IT alerts", len(data["shadow_it"]))
    cards[1].metric("Shadow AI alerts", len(data["shadow_ai"]))
    tab_it, tab_ai = st.tabs(["Shadow IT", "Shadow AI"])
    with tab_it:
        st.caption("Unauthorized non-AI SaaS applications.")
        with st.expander("View Shadow IT alert records", expanded=True):
            st.dataframe(enrich_saas_alerts(data["shadow_it"], data["saas"]), hide_index=True, width="stretch")
    with tab_ai:
        st.caption("Unauthorized applications in the configured AI application list.")
        with st.expander("View Shadow AI alert records", expanded=True):
            st.dataframe(enrich_saas_alerts(data["shadow_ai"], data["saas"]), hide_index=True, width="stretch")


def show_user_behavior(data: dict[str, pd.DataFrame]) -> None:
    st.header("User Behaviour")
    st.caption("Current activity is compared with each user's earlier historical median. A behavioural alert requires five earlier records and a 3.5× request or upload deviation.")
    baselines = data["behavior_baselines"].copy()
    baselines["parsed_timestamp"] = pd.to_datetime(baselines["timestamp"], errors="coerce")
    user_id = st.selectbox("User", sorted(baselines["user_id"].unique()))
    measure = st.radio("Activity measure", ["Request count", "Upload volume (MB)"], horizontal=True)
    user_rows = baselines.loc[baselines["user_id"].eq(user_id)].sort_values("parsed_timestamp").reset_index(drop=True)

    if measure == "Request count":
        actual_col, baseline_col, ratio_col, y_label = "requests", "historical_request_baseline", "request_deviation_ratio", "Requests"
    else:
        actual_col, baseline_col, ratio_col, y_label = "data_uploaded_mb", "historical_upload_baseline_mb", "upload_deviation_ratio", "Upload volume (MB)"

    event_options = list(range(len(user_rows)))
    selected_position = st.selectbox(
        "Inspect activity", event_options, index=len(event_options) - 1,
        format_func=lambda index: f"{user_rows.iloc[index]['timestamp']} | {user_rows.iloc[index]['event_id']}",
    )
    current = user_rows.iloc[selected_position]

    fig, ax = plt.subplots(figsize=(11, 4.6))
    ax.plot(user_rows["parsed_timestamp"], user_rows[actual_col], marker="o", linewidth=1.8, markersize=4, label="Actual activity", color="#2563EB")
    ax.plot(user_rows["parsed_timestamp"], user_rows[baseline_col], linestyle="--", linewidth=2, label="Historical median baseline", color="#64748B")
    anomalous = user_rows.loc[user_rows["behavioral_alert"].fillna(False)]
    ax.scatter(anomalous["parsed_timestamp"], anomalous[actual_col], color="#DC2626", s=58, zorder=4, label="Behavioural deviation")
    ax.axvline(current["parsed_timestamp"], color="#0F172A", alpha=0.35, linewidth=1)
    ax.set_title(f"{user_id}: {y_label} versus historical baseline")
    ax.set_xlabel("Activity timestamp")
    ax.set_ylabel(y_label)
    ax.grid(alpha=0.22)
    ax.legend(loc="best")
    fig.autofmt_xdate()
    fig.tight_layout()
    st.pyplot(fig, width="stretch")
    plt.close(fig)

    has_baseline = pd.notna(current[baseline_col])
    cards = st.columns(3)
    if has_baseline:
        cards[0].metric("Historical baseline", f"{current[baseline_col]:.2f}")
        cards[1].metric("Current activity", f"{current[actual_col]:.2f}")
        cards[2].metric("Deviation ratio", f"{current[ratio_col]:.2f}×")
        if bool(current["behavioral_alert"]):
            st.warning(f"Behavioural deviation detected: {current['behavioral_explanation']}")
        else:
            st.success("Activity is within the configured behavioural deviation thresholds.")
    else:
        cards[0].metric("Current activity", f"{current[actual_col]:.2f}")
        cards[1].metric("Historical baseline", "—")
        cards[2].metric("Deviation ratio", "—")
        st.info("Insufficient historical data: this user has fewer than five earlier activity records for a valid baseline.")

def show_cloud_security(data: dict[str, pd.DataFrame]) -> None:
    st.header("Cloud Security")
    st.caption("CloudTrail-style rule alerts. The same cloud event may show more than once if it breaks more than one rule.")
    alerts = enrich_cloud_alerts(data["cloud_alerts"], data["cloud"])
    severity_counts = alerts["severity"].value_counts()
    columns = st.columns(3)
    columns[0].metric("Cloud alerts", len(alerts))
    columns[1].metric("High severity", int(severity_counts.get("High", 0)))
    columns[2].metric("Medium severity", int(severity_counts.get("Medium", 0)))
    selected_types = st.multiselect("Alert type", sorted(alerts["alert_type"].unique()), default=sorted(alerts["alert_type"].unique()))
    filtered = alerts.loc[alerts["alert_type"].isin(selected_types)]
    with st.expander("View filtered cloud alert records", expanded=True):
        st.dataframe(filtered, hide_index=True, width="stretch")


def show_incidents(data: dict[str, pd.DataFrame]) -> None:
    st.header("Incidents")
    st.caption("Related alerts are grouped by user and a 12-hour time window. Expand a selected incident to inspect all contributing alerts and risk reasons.")
    incidents = data["incidents"].copy()
    levels = st.multiselect("Risk level", ["Low", "Medium", "High"], default=["Low", "Medium", "High"])
    filtered = incidents.loc[incidents["risk_level"].isin(levels)].copy()
    filtered["event_count"] = filtered["events"].map(lambda value: len(parse_events(value)))
    filtered["first_timestamp"] = filtered["events"].map(lambda value: (parse_events(value) or [{}])[0].get("timestamp", ""))
    filtered = filtered.sort_values(["risk_score", "incident_id"], ascending=[False, True])
    summary_columns = ["incident_id", "user_id", "event_count", "first_timestamp", "risk_score", "risk_level", "reason"]
    st.dataframe(filtered[summary_columns], hide_index=True, width="stretch")

    if filtered.empty:
        st.info("No incidents match the selected risk levels.")
        return
    incident_id = st.selectbox("Inspect incident", filtered["incident_id"].tolist())
    incident = filtered.loc[filtered["incident_id"].eq(incident_id)].iloc[0]
    with st.expander(f"Incident {incident_id}: related alerts and risk explanation", expanded=True):
        cards = st.columns(3)
        cards[0].metric("Risk score", f"{incident['risk_score']}/100")
        cards[1].metric("Risk level", incident["risk_level"])
        cards[2].metric("Related alerts", incident["event_count"])
        st.write(incident["reason"])
        event_details = parse_events(incident["events"])
        if event_details:
            st.dataframe(pd.DataFrame(event_details), hide_index=True, width="stretch")
        else:
            st.code(incident["events"])


def main() -> None:
    st.set_page_config(page_title="SaaS Security Monitoring", layout="wide")
    st.title("SaaS Security Monitoring and Shadow IT Detection")
    st.caption("Cloud Computing Course Project | Member 1: 231IT030 | Member 2: 231IT074")
    data, errors = load_project_data()
    if errors:
        st.error("Required pipeline artifacts are missing.")
        for error in errors:
            st.write(f"- {error}")
        st.code("python generate_data.py\npython evaluate.py\npython run_detections.py\npython run_behavioral_baseline.py\npython run_correlation.py")
        return

    section = st.sidebar.radio("Navigation", ["Overview", "Detection Performance", "SaaS Security", "User Behaviour", "Cloud Security", "Incidents"])
    if section == "Overview":
        show_overview(data)
    elif section == "Detection Performance":
        show_detection_performance(data)
    elif section == "SaaS Security":
        show_saas_security(data)
    elif section == "User Behaviour":
        show_user_behavior(data)
    elif section == "Cloud Security":
        show_cloud_security(data)
    else:
        show_incidents(data)


if __name__ == "__main__":
    main()
