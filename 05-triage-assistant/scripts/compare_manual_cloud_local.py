#!/usr/bin/env python3
import json
from pathlib import Path

MAN_DIR = Path("/opt/capstone/04-evaluation/manual_results")
CLOUD_DIR = Path("/opt/capstone/05-triage-assistant/outputs/cloud")
LOCAL_DIR = Path("/opt/capstone/05-triage-assistant/outputs/local")
OUT = Path("/opt/capstone/04-evaluation/manual_vs_cloud_vs_local.csv")

def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

def get_cloud(case_id: str):
    cj = CLOUD_DIR / f"{case_id}.cloud.json"
    cm = CLOUD_DIR / f"{case_id}.cloud.meta.json"
    if not (cj.exists() and cm.exists()):
        return None, None
    return load_json(cj), load_json(cm)

def get_local(case_id: str):
    lj = LOCAL_DIR / f"{case_id}.local.json"
    lm = LOCAL_DIR / f"{case_id}.local.meta.json"
    if not (lj.exists() and lm.exists()):
        return None, None
    return load_json(lj), load_json(lm)

rows = []
for man_file in sorted(MAN_DIR.glob("*.manual.json")):
    man = load_json(man_file)
    case_id = man["case_id"]

    cloud, cloud_meta = get_cloud(case_id)
    local, local_meta = get_local(case_id)

    rows.append({
        "case_id": case_id,
        "rule_id": man.get("rule_id",""),
        "truth_label": man.get("truth_classification",""),  # if you stored it there; ok if blank
        "manual_classification": man.get("analyst_classification",""),
        "manual_priority": man.get("priority",""),
        "manual_mttt_seconds": man.get("mttt_seconds",""),

        "cloud_classification": (cloud or {}).get("classification",""),
        "cloud_priority": (cloud or {}).get("priority",""),
        "cloud_confidence": (cloud or {}).get("confidence",""),
        "cloud_elapsed_seconds": (cloud_meta or {}).get("elapsed_seconds",""),
        "cloud_model": (cloud_meta or {}).get("model",""),

        "local_classification": (local or {}).get("classification",""),
        "local_priority": (local or {}).get("priority",""),
        "local_confidence": (local or {}).get("confidence",""),
        "local_elapsed_seconds": (local_meta or {}).get("elapsed_seconds",""),
        "local_model": (local_meta or {}).get("model","")
    })

cols = [
    "case_id","rule_id","truth_label",
    "manual_classification","manual_priority","manual_mttt_seconds",
    "cloud_classification","cloud_priority","cloud_confidence","cloud_elapsed_seconds","cloud_model",
    "local_classification","local_priority","local_confidence","local_elapsed_seconds","local_model"
]

lines = [",".join(cols)]
for r in rows:
    # quote commas safely by replacing commas (simple approach)
    def safe(v):
        s = str(v)
        return '"' + s.replace('"','""') + '"'
    lines.append(",".join([safe(r.get(c,"")) for c in cols]))

OUT.write_text("\n".join(lines), encoding="utf-8")
print(f"Wrote {OUT} ({len(rows)} rows)")
