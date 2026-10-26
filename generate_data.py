"""Generate reproducible SaaS and CloudTrail-style course-project datasets."""

from pathlib import Path

import numpy as np
import pandas as pd


RANDOM_SEED = 42
DATA_DIR = Path("data")
AI_APPLICATIONS = ["ChatGPT", "Gemini", "Claude", "DeepSeek"]
APP_CATEGORIES = {
    "Microsoft 365": "Productivity", "Google Workspace": "Productivity",
    "Slack": "Collaboration", "Zoom": "Communication", "Salesforce": "CRM",
    "Jira": "Project Management", "GitHub": "Development", "OneDrive": "Storage",
}
UNAPPROVED_APPS = {"Notion": "Productivity", "Dropbox": "Storage", "Trello": "Project Management", "WeTransfer": "File Transfer"}


def build_user_profiles():
    offices = [("Bengaluru", "10.10.1"), ("Hyderabad", "10.10.2"), ("Pune", "10.10.3"), ("Chennai", "10.10.4")]
    devices = ["Managed Windows Laptop", "Managed macOS Laptop"]
    return {
        f"user_{number:03d}": {
            "location": offices[(number - 1) % len(offices)][0],
            "ip_prefix": offices[(number - 1) % len(offices)][1],
            "device": devices[number % len(devices)],
        }
        for number in range(1, 51)
    }


def activity_time(rng, unusual=False):
    day = int(rng.integers(1, 29))
    hour = int(rng.choice([0, 1, 2, 3, 4, 22, 23])) if unusual else int(rng.integers(8, 19))
    return pd.Timestamp(2025, 6, day, hour, int(rng.integers(0, 60)), int(rng.integers(0, 60)))


def generate_saas(rng, profiles):
    scenarios = ["normal"] * 900 + ["shadow_it"] * 70 + ["shadow_ai"] * 70 + ["high_requests"] * 60 + ["high_upload"] * 60 + ["unusual_time"] * 40
    rng.shuffle(scenarios)
    rows = []
    for index, scenario in enumerate(scenarios, 1):
        user_id = str(rng.choice(list(profiles)))
        profile = profiles[user_id]
        application = str(rng.choice(list(APP_CATEGORIES)))
        category, approved, truth = APP_CATEGORIES[application], True, 0
        timestamp = activity_time(rng)
        requests = int(np.clip(rng.normal(55, 18), 8, 130))
        upload = round(float(np.clip(rng.gamma(2.2, 4.0), 0.1, 55)), 2)
        if scenario == "shadow_it":
            application = str(rng.choice(list(UNAPPROVED_APPS))); category = UNAPPROVED_APPS[application]; approved = False; truth = 1
        elif scenario == "shadow_ai":
            application = str(rng.choice(AI_APPLICATIONS)); category = "AI Assistant"; approved = False; upload = round(float(rng.uniform(5, 35)), 2); truth = 1
        elif scenario == "high_requests":
            requests = int(rng.integers(280, 801)); truth = 1
        elif scenario == "high_upload":
            upload = round(float(rng.uniform(180, 900)), 2); truth = 1
        elif scenario == "unusual_time":
            timestamp = activity_time(rng, True); truth = 1
        rows.append({"event_id": f"SAAS-{index:05d}", "timestamp": timestamp.isoformat(), "user_id": user_id,
                     "application": application, "application_category": category, "requests": requests,
                     "data_uploaded_mb": upload, "device": profile["device"], "location": profile["location"],
                     "approved": approved, "ground_truth": truth})
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def generate_cloud(rng, profiles):
    scenarios = ["normal"] * 950 + ["unusual_login_time"] * 45 + ["unknown_ip"] * 50 + ["create_access_key"] * 45 + ["api_burst"] * 55 + ["unusual_resource"] * 45 + ["suspicious_data_access"] * 60
    actions = [("GetObject", "s3://project-documents"), ("PutObject", "s3://team-uploads"), ("ListBucket", "s3://project-documents"), ("DescribeInstances", "ec2:dev-instance")]
    rng.shuffle(scenarios); rows = []; users = list(profiles)
    for index, scenario in enumerate(scenarios, 1):
        user_id = str(rng.choice(users)); profile = profiles[user_id]
        event_name, resource = actions[int(rng.integers(0, len(actions)))]; timestamp = activity_time(rng)
        source_ip = f"{profile['ip_prefix']}.{int(rng.integers(10, 220))}"; truth = 0
        if scenario == "unusual_login_time":
            event_name, resource, timestamp, truth = "ConsoleLogin", "aws:console", activity_time(rng, True), 1
        elif scenario == "unknown_ip":
            event_name, resource, source_ip, truth = "ConsoleLogin", "aws:console", f"185.220.{int(rng.integers(1,255))}.{int(rng.integers(1,255))}", 1
        elif scenario == "create_access_key":
            event_name, resource, truth = "CreateAccessKey", "iam:access-key", 1
        elif scenario == "api_burst":
            user_id = users[index % 5]; profile = profiles[user_id]; event_name, resource = "GetObject", "s3://customer-exports"
            timestamp = pd.Timestamp(2025, 6, 20 + (index % 4), 14, index % 3, 0); source_ip = f"{profile['ip_prefix']}.{int(rng.integers(10,220))}"; truth = 1
        elif scenario == "unusual_resource":
            event_name, resource, truth = "GetObject", str(rng.choice(["s3://finance-backups", "s3://customer-exports"])), 1
        elif scenario == "suspicious_data_access":
            event_name, resource, source_ip, timestamp, truth = "GetObject", "s3://customer-exports", f"185.220.{int(rng.integers(1,255))}.{int(rng.integers(1,255))}", activity_time(rng, True), 1
        rows.append({"event_id": f"CLOUD-{index:05d}", "timestamp": timestamp.isoformat(), "user_id": user_id,
                     "event_name": event_name, "resource": resource, "source_ip": source_ip,
                     "region": "ap-south-1", "status": "Success", "ground_truth": truth})
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def validate(data, columns, name):
    if set(columns) - set(data.columns) or data.empty or data[columns].isna().any().any():
        raise ValueError(f"{name} schema or required values are invalid.")
    if not data.event_id.is_unique or not set(data.ground_truth.unique()).issubset({0, 1}):
        raise ValueError(f"{name} IDs or labels are invalid.")
    pd.to_datetime(data.timestamp, errors="raise")


def main():
    DATA_DIR.mkdir(exist_ok=True); rng = np.random.default_rng(RANDOM_SEED); profiles = build_user_profiles()
    saas, cloud = generate_saas(rng, profiles), generate_cloud(rng, profiles)
    validate(saas, ["event_id", "timestamp", "user_id", "application", "application_category", "requests", "data_uploaded_mb", "device", "location", "approved", "ground_truth"], "SaaS")
    validate(cloud, ["event_id", "timestamp", "user_id", "event_name", "resource", "source_ip", "region", "status", "ground_truth"], "Cloud")
    saas.to_csv(DATA_DIR / "saas_activity.csv", index=False); cloud.to_csv(DATA_DIR / "cloudtrail_logs.csv", index=False)
    print(f"Generated SaaS: {len(saas)} rows ({saas.ground_truth.sum()} anomalous)")
    print(f"Generated cloud: {len(cloud)} rows ({cloud.ground_truth.sum()} suspicious)")


if __name__ == "__main__":
    main()
