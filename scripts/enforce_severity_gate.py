import json
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("json_path")
parser.add_argument("--fail-on", choices=["low", "medium", "high"], default="high")
args = parser.parse_args()

with open(args.json_path) as f:
    data = json.load(f)

# Snyk output may be a dict (with "issues") or a list of issues
if isinstance(data, dict):
    findings = data.get("issues", [])
elif isinstance(data, list):
    findings = data
else:
    findings = []

# Count severities
counts = {"low": 0, "medium": 0, "high": 0}
for f in findings:
    sev = f.get("severity", "").lower()
    if sev in counts:
        counts[sev] += 1

# Fail if any finding meets or exceeds the severity threshold
threshold = args.fail_on
levels = ["low", "medium", "high"]
threshold_index = levels.index(threshold)

if any(counts[sev] > 0 for i, sev in enumerate(levels) if i >= threshold_index):
    print(f"Security gate failed: {counts}")
    sys.exit(1)
else:
    print(f"No findings above {threshold} severity: {counts}")

