#!/usr/bin/env python3
import sys, re, yaml, datetime
from pathlib import Path


# Usage: parse a PR body or comment text for lines like:
# /snyk-fp code-security/SNYK-CODE-1234 "Reason here" 30


COMMAND_RE = re.compile(r"/snyk-fp\s+(\S+)\s+\"([^\"]+)\"\s+(\d+)")


comment_text = None
for i, a in enumerate(sys.argv):
if a == "--comment" and i+1 < len(sys.argv):
comment_text = sys.argv[i+1]


if not comment_text:
print("No comment text supplied; skipping.")
sys.exit(0)


m = COMMAND_RE.search(comment_text)
if not m:
print("No /snyk-fp command found; skipping.")
sys.exit(0)


issue_id, reason, days = m.group(1), m.group(2), int(m.group(3))


snyk_path = Path('.snyk')
if snyk_path.exists():
data = yaml.safe_load(snyk_path.read_text()) or {}
else:
data = {"version":"v1.27.0"}


data.setdefault("ignore", {})
entry = {
"*": {
"reason": reason,
"created": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
"expires": (datetime.datetime.utcnow() + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
}
}


existing
