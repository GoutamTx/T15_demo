#!/usr/bin/env python3
import json, sys, argparse


SEV_ORDER = {"low": 0, "medium": 1, "high": 2}


def count_by_sev(findings):
counts = {"low":0, "medium":0, "high":0}
for f in findings:
sev = (f.get("severity") or "").lower()
if sev in counts: counts[sev]+=1
return counts


if __name__ == "__main__":
ap = argparse.ArgumentParser()
ap.add_argument("json_path")
ap.add_argument("--fail-on", default="high", choices=["low","medium","high"])
args = ap.parse_args()


with open(args.json_path) as fh:
data = json.load(fh)


findings = data.get("issues", []) or data.get("runs", []) or []
# Snyk Code JSON uses `issues`; tolerate other shapes defensively


counts = count_by_sev(findings)
print("Findings:", counts)


# Fail if any findings at threshold or higher
threshold = args.fail_on.lower()
should_fail = any(counts[sev] > 0 for sev in counts if SEV_ORDER[sev] >= SEV_ORDER[threshold])


if should_fail:
print(f"Severity gate failed: >= {threshold} issues present.")
sys.exit(1)
else:
print("Severity gate passed.")
