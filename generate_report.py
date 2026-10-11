
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "waf_logs.csv")
REPORT_FILE = os.path.join(BASE_DIR, "incident_report.csv")

if not os.path.exists(LOG_FILE):
    print("Error: waf_logs.csv not found.")
    raise SystemExit(1)

try:
    logs = pd.read_csv(LOG_FILE)
except pd.errors.EmptyDataError:
    print("Error: The log file is empty.")
    raise SystemExit(1)

if logs.empty:
    print("No requests recorded. Nothing to report.")
    raise SystemExit(0)

incidents = logs[logs["status"] == "BLOCKED"].copy()

if incidents.empty:
    print("No blocked requests found.")
    raise SystemExit(0)

incidents.to_csv(REPORT_FILE, index=False)

print("SENTINEL WAF Incident Report Generated")
print(f"Total requests: {len(logs)}")
print(f"Blocked requests: {len(incidents)}")
print(f"Report saved to: {REPORT_FILE}")
print("\nIncident summary:")
print(incidents["attack_type"].value_counts().to_string())
