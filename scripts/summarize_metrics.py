import json
import sys
import csv

if len(sys.argv) != 5:
    print("Usage: python summarize_metrics.py <input.json> <summary.json> <trend.csv> <.snyk>")
    sys.exit(1)

input_json = sys.argv[1]
summary_json = sys.argv[2]
trend_csv = sys.argv[3]
snyk_file = sys.argv[4]

with open(input_json) as f:
    data = json.load(f)

# Handle both dict (with "issues") and list
if isinstance(data, dict):
    issues = data.get("issues", [])
elif isinstance(data, list):
    issues = data
else:
    issues = []

counts = {"low": 0, "medium": 0, "high": 0}

for issue in issues:
    sev = issue.get("severity", "").lower()
    if sev in counts:
        counts[sev] += 1

# Save summary JSON
with open(summary_json, "w") as f:
    json.dump({
        "timestamp": "2025-09-01T12:00:00Z",
        "counts": counts,
        "false_positive_rules": 0,
        "raw_file": input_json
    }, f, indent=2)

# Save trend CSV
with open(trend_csv, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["severity", "count"])
    for k, v in counts.items():
        writer.writerow([k, v])

