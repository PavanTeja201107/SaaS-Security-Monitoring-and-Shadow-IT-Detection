"""Generate reproducible synthetic data for the SaaS security monitoring project.

The data is intentionally synthetic, but follows simple relationships found in
real SaaS telemetry and CloudTrail-style audit logs.  Known users have typical
working hours, office locations, devices, IP ranges and normal request/data
volumes.  A smaller set of labelled anomalous records breaks one or more of
those relationships.

Run from the project root:
    python generate_data.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd


RANDOM_SEED = 42
DATA_DIR = Path("data")

AI_APPLICATIONS = ["ChatGPT", "Gemini", "Claude", "DeepSeek"]
APP_CATEGORIES = {
    "Microsoft 365": "Productivity",
    "Google Workspace": "Productivity",
    "Slack": "Collaboration",
    "Zoom": "Communication",
    "Salesforce": "CRM",
    "Jira": "Project Management",
    "GitHub": "Development",
    "OneDrive": "Storage",
}
UNAPPROVED_APPS = {
    "Notion": "Productivity",
    "Dropbox": "Storage",
    "Trello": "Project Management",
    "WeTransfer": "File Transfer",
}


def build_user_profiles() -> Dict[str, Dict[str, str]]:
    """Create stable user attributes used by both datasets."""
    offices = [
        ("Bengaluru", "10.10.1"),
        ("Hyderabad", "10.10.2"),
        ("Pune", "10.10.3"),
        ("Chennai", "10.10.4"),
    ]
    devices = ["Managed Windows Laptop", "Managed macOS Laptop"]
    profiles: Dict[str, Dict[str, str]] = {}
    for number in range(1, 51):
        location, ip_prefix = offices[(number - 1) % len(offices)]
        profiles[f"user_{number:03d}"] = {
            "location": location,
            "ip_prefix": ip_prefix,
            "device": devices[number % len(devices)],
        }
    return profiles


def timestamp_for_activity(rng: np.random.Generator, unusual_time: bool = False) -> pd.Timestamp:
    """Return a timestamp in June 2025, normally during local work hours."""
    day = int(rng.integers(1, 29))
    if unusual_time:
        hour = int(rng.choice([0, 1, 2, 3, 4, 22, 23]))
    else:
        hour = int(rng.integers(8, 19))
    return pd.Timestamp(2025, 6, day, hour, int(rng.integers(0, 60)), int(rng.integers(0, 60)))


def generate_saas_activity(rng: np.random.Generator, profiles: Dict[str, Dict[str, str]]) -> pd.DataFrame:
    """Generate normal SaaS events plus distinct labelled anomaly scenarios."""
    rows: List[dict] = []
    approved_apps = list(APP_CATEGORIES)
    users = list(profiles)
    scenarios = (
        ["normal"] * 900
        + ["shadow_it"] * 70
        + ["shadow_ai"] * 70
        + ["high_requests"] * 60
        + ["high_upload"] * 60
        + ["unusual_time"] * 40
    )
    rng.shuffle(scenarios)

    for index, scenario in enumerate(scenarios, start=1):
        user_id = str(rng.choice(users))
        profile = profiles[user_id]
        approved = True
        app = str(rng.choice(approved_apps))
        category = APP_CATEGORIES[app]
        timestamp = timestamp_for_activity(rng)
        requests = int(np.clip(rng.normal(55, 18), 8, 130))
        uploaded_mb = round(float(np.clip(rng.gamma(2.2, 4.0), 0.1, 55)), 2)
        device = profile["device"]
        location = profile["location"]
        ground_truth = 0

        if scenario == "shadow_it":
            app = str(rng.choice(list(UNAPPROVED_APPS)))
            category = UNAPPROVED_APPS[app]
            approved = False
            ground_truth = 1
        elif scenario == "shadow_ai":
            app = str(rng.choice(AI_APPLICATIONS))
            category = "AI Assistant"
            approved = False
            # Shadow AI often involves a moderately larger prompt/file upload.
            uploaded_mb = round(float(rng.uniform(5, 35)), 2)
            ground_truth = 1
        elif scenario == "high_requests":
            requests = int(rng.integers(280, 801))
            ground_truth = 1
        elif scenario == "high_upload":
            uploaded_mb = round(float(rng.uniform(180, 900)), 2)
            ground_truth = 1
        elif scenario == "unusual_time":
            timestamp = timestamp_for_activity(rng, unusual_time=True)
            ground_truth = 1

        rows.append(
            {
                "event_id": f"SAAS-{index:05d}",
                "timestamp": timestamp.isoformat(),
                "user_id": user_id,
                "application": app,
                "application_category": category,
                "requests": requests,
                "data_uploaded_mb": uploaded_mb,
                "device": device,
                "location": location,
                "approved": approved,
                "ground_truth": ground_truth,
            }
        )
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def generate_cloudtrail_logs(rng: np.random.Generator, profiles: Dict[str, Dict[str, str]]) -> pd.DataFrame:
    """Generate CloudTrail-style normal actions and explainable suspicious actions."""
    rows: List[dict] = []
    users = list(profiles)
    normal_actions = [
        ("GetObject", "s3://project-documents"),
        ("PutObject", "s3://team-uploads"),
        ("ListBucket", "s3://project-documents"),
        ("DescribeInstances", "ec2:dev-instance"),
    ]
    suspicious_resources = ["s3://finance-backups", "s3://customer-exports"]
    scenarios = (
        ["normal"] * 950
        + ["unusual_login_time"] * 45
        + ["unknown_ip"] * 50
        + ["create_access_key"] * 45
        + ["api_burst"] * 55
        + ["unusual_resource"] * 45
        + ["suspicious_data_access"] * 60
    )
    rng.shuffle(scenarios)

    for index, scenario in enumerate(scenarios, start=1):
        user_id = str(rng.choice(users))
        profile = profiles[user_id]
        event_name, resource = normal_actions[int(rng.integers(0, len(normal_actions)))]
        timestamp = timestamp_for_activity(rng)
        source_ip = f"{profile['ip_prefix']}.{int(rng.integers(10, 220))}"
        region = "ap-south-1"
        status = "Success"
        ground_truth = 0

        if scenario == "unusual_login_time":
            event_name = "ConsoleLogin"
            resource = "aws:console"
            timestamp = timestamp_for_activity(rng, unusual_time=True)
            ground_truth = 1
        elif scenario == "unknown_ip":
            event_name = "ConsoleLogin"
            resource = "aws:console"
            source_ip = f"185.220.{int(rng.integers(1, 255))}.{int(rng.integers(1, 255))}"
            ground_truth = 1
        elif scenario == "create_access_key":
            event_name = "CreateAccessKey"
            resource = "iam:access-key"
            ground_truth = 1
        elif scenario == "api_burst":
            # Repeated calls by five users in a short time window form detectable bursts.
            user_id = users[index % 5]
            profile = profiles[user_id]
            event_name = "GetObject"
            timestamp = pd.Timestamp(2025, 6, 20 + (index % 4), 14, index % 3, 0)
            resource = "s3://customer-exports"
            source_ip = f"{profile['ip_prefix']}.{int(rng.integers(10, 220))}"
            ground_truth = 1
        elif scenario == "unusual_resource":
            event_name = "GetObject"
            resource = str(rng.choice(suspicious_resources))
            ground_truth = 1
        elif scenario == "suspicious_data_access":
            event_name = "GetObject"
            resource = "s3://customer-exports"
            source_ip = f"185.220.{int(rng.integers(1, 255))}.{int(rng.integers(1, 255))}"
            timestamp = timestamp_for_activity(rng, unusual_time=True)
            ground_truth = 1

        rows.append(
            {
                "event_id": f"CLOUD-{index:05d}",
                "timestamp": timestamp.isoformat(),
                "user_id": user_id,
                "event_name": event_name,
                "resource": resource,
                "source_ip": source_ip,
                "region": region,
                "status": status,
                "ground_truth": ground_truth,
            }
        )
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def validate_dataset(df: pd.DataFrame, required_columns: List[str], dataset_name: str) -> None:
    """Fail early if generated data is not usable by later pipeline stages."""
    missing = set(required_columns) - set(df.columns)
    if missing:
        raise ValueError(f"{dataset_name}: missing columns: {sorted(missing)}")
    if df.empty:
        raise ValueError(f"{dataset_name}: dataset is empty")
    if df[required_columns].isna().any().any():
        raise ValueError(f"{dataset_name}: required fields contain missing values")
    if not df["event_id"].is_unique:
        raise ValueError(f"{dataset_name}: event_id values must be unique")
    if not set(df["ground_truth"].unique()).issubset({0, 1}):
        raise ValueError(f"{dataset_name}: ground_truth must contain only 0 or 1")
    pd.to_datetime(df["timestamp"], errors="raise")


def print_validation_report(saas_df: pd.DataFrame, cloud_df: pd.DataFrame) -> None:
    """Display the Stage 1 evidence requested for course-project validation."""
    print("\nDATASETS GENERATED AND VALIDATED")
    print(f"SaaS activity records: {len(saas_df)}")
    print(f"Cloud audit records:   {len(cloud_df)}")

    print("\nSaaS sample rows:")
    print(saas_df.head(5).to_string(index=False))
    print("\nSaaS class distribution (ground_truth):")
    print(saas_df["ground_truth"].value_counts().sort_index().rename(index={0: "normal", 1: "anomalous"}))
    print("\nSaaS numeric statistics:")
    print(saas_df[["requests", "data_uploaded_mb"]].describe().round(2).to_string())
    print("\nUnauthorized SaaS categories:")
    print(saas_df.loc[~saas_df["approved"], "application_category"].value_counts().to_string())

    print("\nCloud audit sample rows:")
    print(cloud_df.head(5).to_string(index=False))
    print("\nCloud class distribution (ground_truth):")
    print(cloud_df["ground_truth"].value_counts().sort_index().rename(index={0: "normal", 1: "suspicious"}))
    print("\nCloud event-name distribution:")
    print(cloud_df["event_name"].value_counts().to_string())
    print("\nCloud records by region/status:")
    print(cloud_df.groupby(["region", "status"]).size().rename("records").to_string())


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(RANDOM_SEED)
    profiles = build_user_profiles()

    saas_df = generate_saas_activity(rng, profiles)
    cloud_df = generate_cloudtrail_logs(rng, profiles)

    validate_dataset(
        saas_df,
        ["event_id", "timestamp", "user_id", "application", "application_category", "requests", "data_uploaded_mb", "device", "location", "approved", "ground_truth"],
        "SaaS activity",
    )
    validate_dataset(
        cloud_df,
        ["event_id", "timestamp", "user_id", "event_name", "resource", "source_ip", "region", "status", "ground_truth"],
        "Cloud audit logs",
    )

    saas_path = DATA_DIR / "saas_activity.csv"
    cloud_path = DATA_DIR / "cloudtrail_logs.csv"
    saas_df.to_csv(saas_path, index=False)
    cloud_df.to_csv(cloud_path, index=False)
    print(f"Saved: {saas_path}")
    print(f"Saved: {cloud_path}")
    print_validation_report(saas_df, cloud_df)


if __name__ == "__main__":
    main()
