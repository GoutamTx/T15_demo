#!/usr/bin/env python3
import json, sys, csv, datetime, yaml

# Usage:
#   python scripts/summarize_metrics.py INPUT_JSON SUMMARY_JSON TREND_CSV SNYK_POLICY
#
# Example:
#   python scripts/summarize_metrics.py reports/snyk-code.json reports/summary.json reports/trend.csv .snyk

inp, out_summary, out_trend, snyk_policy = sys.argv[1:5]

# Load Snyk Code JSON output
with open(inp) as fh:
    try:
        data = json.load(fh)
    except Exception:
        data = {}

issues = data.get("issues", [])

# Load false positives from .snyk
try:
    with open(snyk_policy) as fh:
        policy = yaml.safe_load(fh) or {}
        ignores = policy.get("ignore", {})
except FileNotFoundError:
    ignores = {}

# Count severities
counts = {"low": 0, "medium": 0, "high": 0}
for i in issues:
    sev = (i.get("severity") or "").lower()
    if sev in counts:
        counts[sev] += 1

fp_count = sum(len(v) for v in ignores.values())

summary = {
    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    "counts": counts,
    "false_positive_rules": fp_count,
    "raw_file": inp,
}

# Write summary JSON
with open(out_summary, "w") as fh:
    json.dump(summary, fh, indent=2)

# Append to trend CSV
header = ["timestamp", "low", "medium", "high", "false_positive_rules"]
row = [
    summary["timestamp"],
    counts["low"],
    counts["medium"],
    counts["high"],
    fp_count,
]

try:
    with open(out_trend, "x", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerow(row)
except FileExistsError:
    with open(out_trend, "a", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(row)

print("Wrote", out_summary, "and", out_trend)

