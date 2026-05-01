#!/usr/bin/env python3
import json
from pathlib import Path

MAN_DIR = Path("/opt/capstone/04-evaluation/manual_results")
CLOUD_DIR = Path("/opt/capstone/05-triage-assistant/outputs/cloud")
OUT = Path("/opt/capstone/04-evaluation/manual_vs_cloud.csv")

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

rows = []
for man_file in sorted(MAN_DIR.glob("*.manual.json")):
    man = load_json(man_file)
    case_id = man["case_id"]

    cloud_file = CLOUD_DIR / f"{case_id}.cloud.json"
    meta_file = CLOUD_DIR / f"{case_id}.cloud.meta.json"

    if not cloud_file.exists() or not meta_file.exists():
        continue

    cloud = load_json(cloud_file)
    meta = load_json(meta_file)

    rows.append({
        "case_id": case_id,
        "rule_id": man.get("rule_id",""),
        "manual_classification": man.get("analyst_classification",""),
        "manual_priority": man.get("priority",""),
        "manual_mttt_seconds": man.get("mttt_seconds",""),
        "cloud_classification": cloud.get("classification",""),
        "cloud_priority": cloud.get("priority",""),
        "cloud_confidence": cloud.get("confidence",""),
        "cloud_elapsed_seconds": meta.get("elapsed_seconds",""),
        "cloud_model": meta.get("model","")
    })

# write csv
cols = [
    "case_id","rule_id",
    "manual_classification","manual_priority","manual_mttt_seconds",
    "cloud_classification","cloud_priority","cloud_confidence","cloud_elapsed_seconds","cloud_model"
]
lines = [",".join(cols)]
for r in rows:
    lines.append(",".join([str(r.get(c,"")) for c in cols]))

OUT.write_text("\n".join(lines), encoding="utf-8")
print(f"Wrote {OUT} ({len(rows)} rows)")
